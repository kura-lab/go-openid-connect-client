package oidcconfig

import (
	"log"
	"net/http"
	"testing"

	"gopkg.in/h2non/gock.v1"
)

func TestNewSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		Get("/.well-known/openid-configuration").
		Reply(200).
		JSON(map[string]interface{}{
			"issuer":                 "https://op.example.com",
			"authorization_endpoint": "https://op.example.com/authorization",
			"token_endpoint":         "https://op.example.com/token",
			"userinfo_endpoint":      "https://op.example.com/userinfo",
			"jwks_uri":               "https://op.example.com/jwks",
			"token_endpoint_auth_methods_supported": []string{
				"client_secret_basic",
				"client_secret_post",
			},
			"response_types_supported": []string{
				"code",
				"code token id_token",
			},
			"scopes_supported": []string{
				"openid",
				"email",
				"profile",
				"address",
			},
			"id_token_signing_alg_values_supported": []string{
				"RS256",
				"ES256",
			},
		})

	oIDCConfigPointer := New(
		"https://op.example.com/.well-known/openid-configuration",
	)
	if err := oIDCConfigPointer.Request(); err != nil {
		log.Println("failed to request openid configuration")
	}

	response := oIDCConfigPointer.Response()

	if response.StatusCode != http.StatusOK {
		t.Errorf("invalid http state code. expected: %v, actual: %v", http.StatusOK, response.StatusCode)
	}

	if response.Status != "200 OK" {
		t.Errorf("invalid http state. expected: 200 OK, actual: %v", response.Status)
	}

	if response.Issuer != "https://op.example.com" {
		t.Errorf("invalid issuer. expected: https://op.example.com, actual: %v", response.Issuer)
	}

	if response.AuthorizationEndpoint != "https://op.example.com/authorization" {
		t.Errorf("invalid authorization_endpoint. expected: https://op.example.com/authorization, actual: %v", response.AuthorizationEndpoint)
	}

	if response.TokenEndpoint != "https://op.example.com/token" {
		t.Errorf("invalid token_endpoint. expected: https://op.example.com/token, actual: %v", response.TokenEndpoint)
	}

	if response.UserInfoEndpoint != "https://op.example.com/userinfo" {
		t.Errorf("invalid userinfo. expected: https://op.example.com/userinfo, actual: %v", response.UserInfoEndpoint)
	}

	if response.JWKsURI != "https://op.example.com/jwks" {
		t.Errorf("invalid jwks_uri. expected: https://op.example.com/jwks, actual: %v", response.JWKsURI)
	}

	for key, value := range []string{"client_secret_basic", "client_secret_post"} {
		if response.TokenEndpointAuthMethodsSupported[key] != value {
			t.Errorf("invalid token_endpoint_auth_methods_supported. expected: %v: %#v", value, response.TokenEndpointAuthMethodsSupported[key])
		}
	}

	for key, value := range []string{"code", "code token id_token"} {
		if response.ResponseTypesSupported[key] != value {
			t.Errorf("invalid response_types_supported. expected: %v: %#v", value, response.ResponseTypesSupported[key])
		}
	}

	for key, value := range []string{"openid", "email", "profile", "address"} {
		if response.ScopesSupported[key] != value {
			t.Errorf("invalid scopes_supported. expected: %v: %#v", value, response.ScopesSupported[key])
		}
	}

	for key, value := range []string{"RS256", "ES256"} {
		if response.IDTokenSigningAlgValuesSupported[key] != value {
			t.Errorf("invalid id_token_signing_alg_values_supported. expected: %v: %#v", value, response.IDTokenSigningAlgValuesSupported[key])
		}
	}
}

func TestNewOIDCConfigSuccess(t *testing.T) {

	config := NewOIDCConfig(
		Issuer("https://op.example.com"),
		AuthorizationEndpoint("https://op.example.com/authorization"),
		TokenEndpoint("https://op.example.com/token"),
		UserInfoEndpoint("https://op.example.com/userinfo"),
		JWKsURI("https://op.example.com/jwks"),
		TokenEndpointAuthMethodsSupported([]string{"client_secret_basic", "client_secret_post"}),
		IDTokenSigningAlgValuesSupported([]string{"RS256", "RS512"}),
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

	for key, value := range []string{"RS256", "RS512"} {
		if response.IDTokenSigningAlgValuesSupported[key] != value {
			t.Errorf("invalid id_token_signing_alg_values_supported. expected: %v: %#v", value, response.IDTokenSigningAlgValuesSupported[key])
		}
	}
}
