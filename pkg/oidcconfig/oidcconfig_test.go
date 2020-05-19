package oidcconfig

import (
	"testing"
)

func TestNewOIDCConfigSuccess(t *testing.T) {

	config := NewOIDCConfig(
		Issuer("https://op.example.com"),
		AuthorizationEndpoint("https://op.example.com/authorization"),
		TokenEndpoint("https://op.example.com/token"),
		UserInfoEndpoint("https://op.example.com/userinfo"),
		JWKsURI("https://op.example.com/jwks"),
		TokenEndpointAuthMethodsSupported([]string{"client_secret_basic", "client_secret_post"}),
	)
	response := config.Response()

	if response.Issuer != "https://op.example.com" {
		t.Errorf("invalid issuer. expected: https://op.example.com, actual: %#v", response.Issuer)
	}

	if response.AuthorizationEndpoint != "https://op.example.com/authorization" {
		t.Errorf("invalid authorization_endpoint. expected: https://op.example.com/authorization, actual: %#v", response.AuthorizationEndpoint)
	}

	if response.TokenEndpoint != "https://op.example.com/token" {
		t.Errorf("invalid token_endpoint. expected: https://op.example.com/token, actual: %#v", response.TokenEndpoint)
	}

	if response.UserInfoEndpoint != "https://op.example.com/userinfo" {
		t.Errorf("invalid userinfo_endpoint. expected: https://op.example.com/userinfo, actual: %#v", response.UserInfoEndpoint)
	}

	if response.JWKsURI != "https://op.example.com/jwks" {
		t.Errorf("invalid jwks_uri. expected: https://op.example.com/jwks, actual: %#v", response.JWKsURI)
	}

	for key, value := range []string{"client_secret_basic", "client_secret_post"} {
		if response.TokenEndpointAuthMethodsSupported[key] != value {
			t.Errorf("invalid token_endpoint_auth_methods_supported. expected: %v: %#v", value, response.TokenEndpointAuthMethodsSupported[key])
		}
	}
}
