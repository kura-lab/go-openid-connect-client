package client

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"gopkg.in/h2non/gock.v1"
)

func TestNewConfigurationSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Authorization", "^Bearer REGISTRATION_ACCESS_TOKEN$").
		Get("/registration").
		MatchParam("client_id", "CLIENT_ID").
		Reply(201).
		JSON(map[string]interface{}{
			"client_id":                  "CLIENT_ID",
			"client_secret":              "CLIENT_SECRET",
			"client_secret_expires_at":   0,
			"token_endpoint_auth_method": "client_secret_basic",
			"application_type":           "web",
			"redirect_uris": []string{
				"https://rp.example.com/callback",
				"https://rp.example.com/callback2",
			},
			"client_name":  "My Example",
			"logo_uri":     "https://rp.example.com/logo.png",
			"subject_type": "pairwise",
			"jwks_uri":     "https://rp.example.com/my_public_keys.jwks",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.RegistrationEndpoint("https://op.example.com/registration"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	configurationPointer := NewConfiguration(
		oIDCConfigResponse,
		"CLIENT_ID",
		RegistrationAccessToken("REGISTRATION_ACCESS_TOKEN"),
	)

	err := configurationPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := configurationPointer.Response()

	if response.Status != "201 Created" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 201 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.ClientID != "CLIENT_ID" {
		t.Errorf("invalid client_id. expected: CLIENT_ID, actual: %v", response.ClientID)
	}

	if response.ClientSecret != "CLIENT_SECRET" {
		t.Errorf("invalid client_secret. expected: CLIENT_SECRET, actual: %v", response.ClientSecret)
	}

	if response.ClientSecretExpiresAt != 0 {
		t.Errorf("invalid client_secret_expires_at. expected: 0, actual: %v", response.ClientSecretExpiresAt)
	}

	if response.ClientIDIssuedAt != 0 {
		t.Errorf("invalid client_id_issued_at. expected: 0, actual: %v", response.ClientIDIssuedAt)
	}

	if response.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("invalid token_endpoint_auth_method. expected: client_secret_basic, actual: %v", response.TokenEndpointAuthMethod)
	}

	if response.ApplicationType != "web" {
		t.Errorf("invalid application_type. expected: web, actual: %v", response.ApplicationType)
	}

	for key, expected := range []string{
		"https://rp.example.com/callback",
		"https://rp.example.com/callback2",
	} {
		if response.RedirectURIs[key] != expected {
			t.Errorf("invalid redirect_uris. expected: %v, actual: %v", expected, response.RedirectURIs[key])
		}
	}

	if response.ClientName != "My Example" {
		t.Errorf("invalid client_name. expected: My Exampl, actual: %v", response.ClientName)
	}

	if response.LogoURI != "https://rp.example.com/logo.png" {
		t.Errorf("invalid logo_uri. expected: https://rp.example.com/logo.png, actual: %v", response.LogoURI)
	}

	if response.SubjectType != "pairwise" {
		t.Errorf("invalid subject_type. expected: pairwise, actual: %v", response.SubjectType)
	}

	if response.JWKsURI != "https://rp.example.com/my_public_keys.jwks" {
		t.Errorf("invalid jwks_uri. expected: , actual: %v", response.JWKsURI)
	}

	if response.Error != "" {
		t.Errorf("invalid error. expected: (empty), actual: %v", response.Error)
	}

	if response.ErrorDescription != "" {
		t.Errorf("invalid error_description. expected: (empty), actual: %v", response.ErrorDescription)
	}
}

func TestNewConfigurationFailure(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Authorization", "^Bearer INVALID_REGISTRATION_ACCESS_TOKEN$").
		Get("/registration").
		MatchParam("client_id", "CLIENT_ID").
		Reply(401).
		SetHeader("WWW-Authenticate",
			"Bearer realm=\"example\",\r\n"+
				"scope=\"openid profile email\",\r\n"+
				"error=\"invalid_token\",\r\n"+
				"error_description=\"The access token expired\"",
		).
		JSON(map[string]interface{}{})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.RegistrationEndpoint("https://op.example.com/registration"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	configurationPointer := NewConfiguration(
		oIDCConfigResponse,
		"CLIENT_ID",
		RegistrationAccessToken("INVALID_REGISTRATION_ACCESS_TOKEN"),
	)

	err := configurationPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := configurationPointer.Response()

	if response.Status != "401 Unauthorized" {
		t.Errorf("invalid http status. expected: 401 Unauthorized, actual: %v", response.Status)
	}

	if response.StatusCode != 401 {
		t.Errorf("invalid http status code. expected: 401, actual: %v", response.StatusCode)
	}

	if response.WWWAuthenticate.Realm != "example" {
		t.Errorf("invalid realm. expected: example, actual: %v", response.WWWAuthenticate.Realm)
	}

	if response.WWWAuthenticate.Scope != "openid profile email" {
		t.Errorf("invalid scope. expected: openid profile email, actual: %v", response.WWWAuthenticate.Scope)
	}

	if response.WWWAuthenticate.Error != "invalid_token" {
		t.Errorf("invalid error. expected: invalid_token, actual: %v", response.WWWAuthenticate.Error)
	}

	if response.WWWAuthenticate.ErrorDescription != "The access token expired" {
		t.Errorf("invalid error description. expected: The access token expired, actual: %v", response.WWWAuthenticate.ErrorDescription)
	}
}

func TestNewConfigurationDecodingFailure(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Authorization", "^Bearer REGISTRATION_ACCESS_TOKEN$").
		Get("/registration").
		MatchParam("client_id", "CLIENT_ID").
		Reply(201).
		BodyString("INVALID_BODY")

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.RegistrationEndpoint("https://op.example.com/registration"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	configurationPointer := NewConfiguration(
		oIDCConfigResponse,
		"CLIENT_ID",
		RegistrationAccessToken("REGISTRATION_ACCESS_TOKEN"),
	)

	err := configurationPointer.Request()

	if err == nil {
		t.Fatalf("expect json decoding error.")
	}
}
