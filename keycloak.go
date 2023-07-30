package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	resty "github.com/go-resty/resty/v2"
	"github.com/nmcclain/ldap"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var logger = zerolog.New(os.Stderr).With().Logger()

type keycloakHandler struct {
	config          *keycloakHandlerConfig
	baseDNUsers     string
	baseDNGroups    string
	baseDNBindUsers string
	restClient      *resty.Client
	session         *session
}

type keycloakHandlerConfig struct {
	keycloakHostname string
	keycloakPort     int
	keycloakRealm    string
	vsphereDomain    string
}

type session struct {
	clientID     string
	clientSecret string
	boundDN      *string
	token        *oauth2.Token
}

type Group struct {
	Name string `json:"name"`
}

type User struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	Id        string `json:"id"`
	LastName  string `json:"lastName"`
	Username  string `json:"username"`
}

// Handler (Binder)

func (h keycloakHandler) Bind(
	bindDN string,
	bindSimplePw string,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	logger.Debug().
		Str("bindDN", bindDN).
		Msg("Bind request")
	if h.config == nil {
		return ldap.LDAPResultOperationsError,
			errors.New("misconfiguration")
	}

	pre := "cn="
	suf := "," + h.baseDNBindUsers
	if !strings.HasPrefix(bindDN, pre) || !strings.HasSuffix(bindDN, suf) {
		logger.Error().
			Str("base", h.baseDNBindUsers).
			Msg("invalid bindDN")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	clientID := strings.TrimPrefix(strings.TrimSuffix(bindDN, suf), pre)
	clientSecret := bindSimplePw
	if err := h.session.open(h.config.tokenEndpoint(), clientID,
		clientSecret, bindDN); err != nil {
		logger.Error().Err(err).Msg("Bind response")
		return ldap.LDAPResultInvalidCredentials, nil
	} else {
		logger.Debug().
			Time("expiry", h.session.token.Expiry).
			Msg("Bind response")
		return ldap.LDAPResultSuccess, nil
	}
}

var rootDSEAttributes = []string{
	"configurationNamingContext",
	"currentTime",
	"defaultNamingContext",
	"dnsHostName",
	"domainControllerFunctionality",
	"domainFunctionality",
	"dsServiceName",
	"forestFunctionality",
	"highestCommittedUSN",
	"isGlobalCatalogReady",
	"isSynchronized",
	"ldapServiceName",
	"namingContexts",
	"rootDomainNamingContext",
	"schemaNamingContext",
	"serverName",
	"subschemaSubentry",
	"supportedCapabilities",
	"supportedControl",
	"supportedLDAPPolicies",
	"supportedLDAPVersion",
	"supportedSASLMechanisms"}

var filterGroupsWithPrefix = regexp.MustCompile("^\\(&\\(objectClass=group\\)" +
	"\\(\\|\\(sAMAccountName=(.+)\\*\\)" +
	"\\(cn=(.+)\\*\\)\\)\\)$")
var filterRootDSE = regexp.MustCompile("^\\(objectclass=\\*\\)$")
var filterUsers = regexp.MustCompile("^\\(objectClass=user\\)$")
var filterUsersWithPrefix = regexp.MustCompile("^\\(&\\(objectClass=user\\)" +
	"\\(\\|\\(sAMAccountName=(.+)\\*\\)" +
	"\\(sn=(.+)\\*\\)" +
	"\\(givenName=(.+)\\*\\)" +
	"\\(cn=(.+)\\*\\)" +
	"\\(displayname=(.+)\\*\\)" +
	"\\(userPrincipalName=(.+)\\*\\)\\)\\)$")

var attributes0 = []string{}
var attributes3 = []string{
	"sAMAccountName",
	"description",
	"objectSid"}
var attributes9 = []string{
	"sAMAccountName",
	"userPrincipalName",
	"description",
	"givenName",
	"sn",
	"mail",
	"userAccountControl",
	"lockoutTime",
	"objectSid"}

var controls0 = []string{}
var controls1 = []string{ldap.ControlTypePaging}

// Handler (Searcher)

func (h keycloakHandler) Search(
	boundDN string,
	req ldap.SearchRequest,
	conn net.Conn,
) (ldap.ServerSearchResult, error) {
	scope := ldap.ScopeMap[req.Scope]
	deferAliases := ldap.DerefMap[req.DerefAliases]
	c := make([]string, len(req.Controls))
	for i, cc := range req.Controls {
		if s, ok := ldap.ControlTypeMap[cc.GetControlType()]; ok {
			c[i] = s
		} else {
			c[i] = cc.GetControlType()
		}
	}
	controls := strings.Join(c, " ")
	attributes := strings.Join(req.Attributes, " ")
	logger.Debug().
		Str("boundDN", boundDN).
		Str("baseDN", req.BaseDN).
		Str("scope", scope).
		Str("derefAliases", deferAliases).
		Int("sizeLimit", req.SizeLimit).
		Int("timeLimit", req.TimeLimit).
		Bool("typesOnly", req.TypesOnly).
		Str("filter", req.Filter).
		Str("attributes", attributes).
		Str("controls", controls).
		Msg("Search request")

	if err := h.checkSession(boundDN, true); err != nil {
		logger.Error().Err(err).Msg("Search response")
		return errorSearchResult(), err
	} else if req.DerefAliases != ldap.NeverDerefAliases ||
		req.SizeLimit != 0 ||
		req.TimeLimit != 0 ||
		req.TypesOnly {

		err := unexpected(fmt.Sprintf("DeferAliases: \"%s\", "+
			"SizeLimit: %d, "+
			"TimeLimit: %d, "+
			"TypesOnly: %t",
			deferAliases,
			req.SizeLimit,
			req.TimeLimit,
			req.TypesOnly))
		logger.Error().Err(err).Msg("Search response")
		return errorSearchResult(), err
	} else if _, ok := checkSearchRequest(
		req,
		"",
		ldap.ScopeBaseObject,
		filterRootDSE,
		attributes0,
		controls0); ok {

		res := h.rootDSESearchResult()
		logger.Debug().
			Str("BaseDN", req.BaseDN).
			Int("entries", len(res.Entries)).
			Msg("Search response")
		return res, nil
	} else if _, ok := checkSearchRequest(
		req,
		h.baseDNUsers,
		ldap.ScopeWholeSubtree,
		filterUsers,
		attributes9,
		controls1); ok {

		if res, err := h.usersSearchResult(""); err != nil {
			logger.Error().Err(err).Msg("Search response")
			return errorSearchResult(), err
		} else {
			logger.Debug().
				Str("BaseDN", req.BaseDN).
				Int("entries", len(res.Entries)).
				Msg("Search response")
			return res, nil
		}
	} else if prefix, ok := checkSearchRequest(
		req,
		h.baseDNUsers,
		ldap.ScopeWholeSubtree,
		filterUsersWithPrefix,
		attributes9,
		controls1); ok {

		if res, err := h.usersSearchResult(prefix); err != nil {
			logger.Error().Err(err).Msg("Search response")
			return errorSearchResult(), err
		} else {
			logger.Debug().
				Str("BaseDN", req.BaseDN).
				Str("prefix", prefix).
				Int("entries", len(res.Entries)).
				Msg("Search response")
			return res, nil
		}
	} else if prefix, ok := checkSearchRequest(req,
		h.baseDNUsers,
		ldap.ScopeWholeSubtree,
		filterGroupsWithPrefix,
		attributes3,
		controls1); ok {

		if res, err := h.groupsSearchResult(prefix); err != nil {
			return errorSearchResult(), err
		} else {
			logger.Debug().
				Str("BaseDN", req.BaseDN).
				Str("prefix", prefix).
				Int("entries", len(res.Entries)).
				Msg("Search response")
			return res, nil
		}
	} else {
		err := unexpected(fmt.Sprintf("BaseDN: \"%s\", "+
			"Scope: \"%s\", "+
			"Filter: \"%s\", "+
			"Attributes: \"%s\", "+
			"Controls: \"%s\"",
			req.BaseDN,
			scope,
			req.Filter,
			attributes,
			controls))
		logger.Error().Err(err).Msg("Search response")
		return errorSearchResult(), err
	}
}

// Handler (Closer)

func (h keycloakHandler) Close(
	boundDN string,
	conn net.Conn,
) error {
	logger.Debug().
		Str("boundDN", boundDN).
		Msg("Close request")
	if err := h.checkSession(boundDN, false); err != nil {
		logger.Error().Err(err).Msg("Close response")
		return err
	} else {
		h.session.token = nil
		h.session.boundDN = nil
		logger.Debug().Msg("Close response")
		return nil
	}
}

// Handler (Adder)

func (h keycloakHandler) Add(
	boundDN string,
	req ldap.AddRequest,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	logger.Debug().
		Str("boundDN", boundDN).
		Msg("Add")
	return ldap.LDAPResultOperationsError, unexpected("Add")
}

// Handler (Modifier)

func (h keycloakHandler) Modify(
	boundDN string,
	req ldap.ModifyRequest,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	logger.Debug().
		Str("boundDN", boundDN).
		Msg("Modify")
	return ldap.LDAPResultOperationsError, unexpected("Modify")
}

// Handler (Deleter)

func (h keycloakHandler) Delete(
	boundDN string,
	deleteDN string,
	conn net.Conn,
) (ldap.LDAPResultCode, error) {
	logger.Debug().
		Str("boundDN", boundDN).
		Str("deleteDN", deleteDN).
		Msg("Delete")
	return ldap.LDAPResultOperationsError, unexpected("Delete")
}

// Handler (HelperMaker)

func (h keycloakHandler) FindUser(
	userName string,
	searchByUPN bool,
) (bool, config.User, error) {
	logger.Debug().
		Str("userName", userName).
		Bool("searchByUPN", searchByUPN).
		Msg("FindUser")
	user := config.User{}
	return false, user, unexpected("FindUser")
}

func (h keycloakHandler) FindGroup(
	groupName string,
) (bool, config.Group, error) {
	logger.Debug().
		Str("groupName", groupName).
		Msg("FindGroup")
	group := config.Group{}
	return false, group, unexpected("FindGroup")
}

func (h *keycloakHandler) checkSession(boundDN string, refresh bool) error {
	if h.session == nil {
		return errors.New("no session")
	} else if *h.session.boundDN != boundDN {
		return errors.New(fmt.Sprintf("unexpected boundDN: %s",
			boundDN))
	} else if !refresh {
		return nil
	} else if err := h.session.refresh(
		h.config.tokenEndpoint()); err != nil {
		return err
	} else {
		return nil
	}
}

func (h *keycloakHandler) groupsSearchResult(
	prefix string,
) (ldap.ServerSearchResult, error) {
	groups := &[]Group{}
	err := h.keycloakGet("groups", groups)
	if err != nil {
		return errorSearchResult(), err
	}

	e := make([]*ldap.Entry, 0, len(*groups))
	for _, group := range *groups {
		if !strings.HasPrefix(group.Name, prefix) {
			continue
		}

		a := make([]*ldap.EntryAttribute, 2)
		a[0] = newAttribute("objectClass", "group")
		a[1] = newAttribute("cn", group.Name)

		logger.Debug().
			Str("name", group.Name).
			Msg("group")

		dn := fmt.Sprintf("cn=%s,%s", group.Name, h.baseDNGroups)
		e = append(e, &ldap.Entry{DN: dn, Attributes: a})
	}

	return ldap.ServerSearchResult{
		Entries:    e,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess}, nil
}

func (h *keycloakHandler) keycloakGet(
	path string,
	result interface{},
) error {
	u := h.config.restAPIEndpoint(path)
	logger.Debug().
		Str("method", "GET").
		Str("url", u).
		Msg("Keycloak REST API request")

	res, err := h.restClient.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(h.session.token.AccessToken).
		SetResult(result).
		Get(u)
	if err == nil && res.StatusCode() != http.StatusOK {
		err = errors.New(res.Status())
	}
	if err != nil {
		logger.Error().Err(err).Msg("Keycloak REST API response")
		return err
	}
	logger.Debug().Msg("Keycloak REST API response")
	return nil
}

func (h *keycloakHandler) rootDSESearchResult() ldap.ServerSearchResult {
	a := make([]*ldap.EntryAttribute, len(rootDSEAttributes))
	for i, name := range rootDSEAttributes {
		a[i] = &ldap.EntryAttribute{
			Name:   name,
			Values: []string{""}}
	}
	e := &ldap.Entry{DN: "", Attributes: a}

	return ldap.ServerSearchResult{
		Entries:    []*ldap.Entry{e},
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess,
	}
}

func (h *keycloakHandler) usersSearchResult(
	prefix string,
) (ldap.ServerSearchResult, error) {
	users := &[]User{}
	err := h.keycloakGet("users", users)
	if err != nil {
		return errorSearchResult(), err
	}

	e := make([]*ldap.Entry, 0, len(*users))
	for _, user := range *users {
		if !strings.HasPrefix(user.Username, prefix) &&
			!strings.HasPrefix(user.LastName, prefix) {
			continue
		}

		a := make([]*ldap.EntryAttribute, 7)
		a[0] = newAttribute("objectClass", "user")
		a[1] = newAttribute("sAMAccountName", user.Username)
		a[2] = newAttribute("cn", user.Username)
		a[3] = newAttribute("givenName", user.FirstName)
		a[4] = newAttribute("sn", user.LastName)
		a[5] = newAttribute("mail", user.Email)
		a[6] = newAttribute("description", "")

		logger.Debug().
			Str("username", user.Username).
			Msg("user")

		dn := fmt.Sprintf("cn=%s,%s", user.Username, h.baseDNUsers)
		e = append(e, &ldap.Entry{DN: dn, Attributes: a})
	}

	return ldap.ServerSearchResult{
		Entries:    e,
		Referrals:  nil,
		Controls:   nil,
		ResultCode: ldap.LDAPResultSuccess}, nil
}

func (c *keycloakHandlerConfig) restAPIEndpoint(path string) string {
	return fmt.Sprintf("https://%s:%d/admin/realms/%s/%s",
		c.keycloakHostname,
		c.keycloakPort,
		c.keycloakRealm,
		path)
}

func (c *keycloakHandlerConfig) tokenEndpoint() string {
	f := "https://%s:%d/realms/%s/protocol/openid-connect/token"
	return fmt.Sprintf(f,
		c.keycloakHostname,
		c.keycloakPort,
		c.keycloakRealm)
}

func (s *session) open(
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	bindDN string,
) error {
	if token, err := clientCredentialsGrant(tokenEndpoint,
		clientID, clientSecret); err != nil {
		return err
	} else {
		s.clientID = clientID
		s.clientSecret = clientSecret
		s.boundDN = &bindDN
		s.token = token
		return nil
	}
}

func (s *session) refresh(tokenEndpoint string) error {
	if s.token.Valid() {
		return nil
	} else if token, err := clientCredentialsGrant(tokenEndpoint,
		s.clientID, s.clientSecret); err != nil {
		return err
	} else {
		s.token = token
		return nil
	}
}

func NewKeycloakHandler(opts ...handler.Option) handler.Handler {
	if c, err := newKeycloakHandlerConfig(); err != nil {
		logger.Error().Err(err).Send()
		return keycloakHandler{}
	} else {
		b := "dc=" + strings.Replace(c.vsphereDomain, ".", ",dc=", -1)
		return keycloakHandler{
			config:          c,
			baseDNUsers:     "cn=users," + b,
			baseDNGroups:    "cn=groups," + b,
			baseDNBindUsers: "cn=bind," + b,
			restClient:      resty.New(),
			session:         &session{}}
	}
}

func checkSearchRequest(
	req ldap.SearchRequest,
	baseDN string,
	scope int,
	filterRegexp *regexp.Regexp,
	attributes []string,
	controls []string,
) (string, bool) {
	if req.BaseDN != baseDN ||
		req.Scope != scope ||
		len(req.Attributes) != len(attributes) ||
		len(req.Controls) != len(controls) {
		return "", false
	}
	for i, a := range attributes {
		if req.Attributes[i] != a {
			return "", false
		}
	}
	for i, c := range controls {
		if req.Controls[i].GetControlType() != c {
			return "", false
		}
	}

	if g := filterRegexp.FindStringSubmatch(req.Filter); g == nil {
		return "", false
	} else if len(g) == 1 {
		return "", true // no prefix
	} else {
		prefix := g[1]
		for _, gg := range g[2:] {
			if gg != prefix {
				return "", false
			}
		}
		return prefix, true
	}
}

func clientCredentialsGrant(
	tokenEndpoint string,
	clientID string,
	clientSecret string,
) (*oauth2.Token, error) {
	oauth2Config := &clientcredentials.Config{
		TokenURL:       tokenEndpoint,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		Scopes:         nil,
		EndpointParams: url.Values{}}

	ctx := context.Background()
	logger.Debug().
		Str("endpoint", tokenEndpoint).
		Str("grant_type", "client_credentials").
		Str("client_id", clientID).
		Msg("OAuth 2.0 authorization request")

	if token, err := oauth2Config.TokenSource(ctx).Token(); err != nil {
		logger.Error().Err(err).Msg("OAuth 2.0 error response")
		return nil, err
	} else if !token.Valid() {
		err := errors.New("invalid token")
		logger.Error().Err(err).Msg("OAuth 2.0 error response")
		return nil, err
	} else {
		logger.Debug().Msg("OAuth 2.0 access token response")
		return token, nil
	}
}

func envNotSet(key string) error {
	return errors.New(fmt.Sprintf("environment variable not set: %s", key))
}

func errorSearchResult() ldap.ServerSearchResult {
	return ldap.ServerSearchResult{
		make([]*ldap.Entry, 0),
		[]string{},
		[]ldap.Control{},
		ldap.LDAPResultOperationsError}
}

func getenv(key string) string {
	s := os.Getenv(key)
	logger.Debug().Str("env", key).Str("value", s).Send()
	return s
}

func hide(s string) string {
	return strings.Repeat("*", utf8.RuneCountInString(s))
}

func newAttribute(name, value string) *ldap.EntryAttribute {
	return &ldap.EntryAttribute{Name: name, Values: []string{value}}
}

func newKeycloakHandlerConfig() (*keycloakHandlerConfig, error) {
	c := &keycloakHandlerConfig{}

	if s := getenv("KEYCLOAK_HOSTNAME"); s == "" {
		return nil, envNotSet("KEYCLOAK_HOSTNAME")
	} else {
		c.keycloakHostname = s
	}

	if s := getenv("KEYCLOAK_PORT"); s == "" {
		c.keycloakPort = 8444
	} else if p, err := strconv.Atoi(s); err != nil {
		return nil, errors.New(fmt.Sprintf(
			"invalid port number: %s", s))
	} else {
		c.keycloakPort = p
	}

	if s := getenv("KEYCLOAK_REALM"); s == "" {
		return nil, envNotSet("KEYCLOAK_REALM")
	} else {
		c.keycloakRealm = s
	}

	if s := getenv("VSPHERE_DOMAIN"); s == "" {
		return nil, envNotSet("VSPHERE_DOMAIN")
	} else {
		c.vsphereDomain = strings.TrimSuffix(s, ".")
	}

	return c, nil
}

func unexpected(msg string) error {
	return errors.New(fmt.Sprintf("unexpected call: %s", msg))
}
