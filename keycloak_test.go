package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterGroupsWithPrefix(t *testing.T) {
	s := "(&(objectClass=group)(|(sAMAccountName=pre*)(cn=pre*)))"
	g := filterGroupsWithPrefix.FindStringSubmatch(s)
	assert.NotNil(t, g)
	assert.Equal(t, 3, len(g))
	assert.Equal(t, s, g[0])
	for _, gg := range g[1:] {
		assert.Equal(t, "pre", gg)
	}
}

func TestFilterRootDSE(t *testing.T) {
	s := "(objectclass=*)"
	g := filterRootDSE.FindStringSubmatch(s)
	assert.NotNil(t, g)
	assert.Equal(t, 1, len(g))
	assert.Equal(t, s, g[0])
}

func TestFilterUsers(t *testing.T) {
	s := "(objectClass=user)"
	g := filterUsers.FindStringSubmatch(s)
	assert.NotNil(t, g)
	assert.Equal(t, 1, len(g))
	assert.Equal(t, s, g[0])
}

func TestFilterUsersWithPrefix(t *testing.T) {
	s := "(&(objectClass=user)(|(sAMAccountName=pre*)" +
		"(sn=pre*)" +
		"(givenName=pre*)" +
		"(cn=pre*)" +
		"(displayname=pre*)" +
		"(userPrincipalName=pre*)))"
	g := filterUsersWithPrefix.FindStringSubmatch(s)
	assert.NotNil(t, g)
	assert.Equal(t, 7, len(g))
	assert.Equal(t, s, g[0])
	for _, gg := range g[1:] {
		assert.Equal(t, "pre", gg)
	}
}

func TestHide(t *testing.T) {
	assert.Equal(t, "********", hide("password"))
}

func TestRestAPIEndpoint(t *testing.T) {
	c := keycloakHandlerConfig{
		keycloakHostname: "localhost",
		keycloakPort:     8443,
		keycloakRealm:    "test-realm"}
	assert.Equal(t, "https://localhost:8443/admin/realms/test-realm/users",
		c.restAPIEndpoint("users"))
}

func TestSid(t *testing.T) {
	assert.Equal(t,
		"S-1-5-21-1634561892-1663987305-970616175-959604020",
		sidToString(sid("4e292dae-35db-4f1a-b40b-17e8e0a3a6b7",
			"domain.com")))
}

func TestTokenEndpoint(t *testing.T) {
	c := keycloakHandlerConfig{
		keycloakHostname: "localhost",
		keycloakPort:     8443,
		keycloakRealm:    "test-realm"}
	assert.Equal(t, "https://localhost:8443/realms/test-realm/protocol/"+
		"openid-connect/token", c.tokenEndpoint())
}
