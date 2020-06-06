package client

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"gopkg.in/h2non/gock.v1"
)

func TestNewRegistrationSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/json$").
		Post("/registration").
		MatchType("json").
		JSON(map[string]interface{}{
			"redirect_uris": []string{
				"https://rp.example.com/callback",
				"https://rp.example.com/callback2",
			},
			"application_type": "web",
			"response_types": []string{
				"code",
			},
			"grant_types": []string{
				"authorization_code",
				"refresh_token",
			},
			"client_name":                "My Example",
			"logo_uri":                   "https://rp.example.com/logo.png",
			"subject_type":               "pairwise",
			"token_endpoint_auth_method": "client_secret_basic",
			"jwks_uri":                   "https://rp.example.com/jwks",
			"initiate_login_uri":         "https://rp.example.com/login",
		}).
		Reply(201).
		JSON(map[string]interface{}{
			"client_id":                 "CLIENT_ID",
			"client_secret":             "CLIENT_SECRET",
			"client_secret_expires_at":  0,
			"registration_access_token": "REGISTRATION_ACCESS_TOKEN",
			"registration_client_uri":   "https://op.example.com/registration?client_id=CLINET_ID",
			"token_endpoint_auth_method": []string{
				"client_secret_basic",
			},
			"application_type": "web",
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

	registrationPointer := NewRegistration(
		oIDCConfigResponse,
		[]string{
			"https://rp.example.com/callback",
			"https://rp.example.com/callback2",
		},
		ApplicationType("web"),
		ResponseTypes([]string{
			"code",
		}),
		GrantTypes([]string{
			"authorization_code",
			"refresh_token",
		}),
		ClientName("My Example"),
		LogoURI("https://rp.example.com/logo.png"),
		SubjectType("pairwise"),
		TokenEndpointAuthMethod("client_secret_basic"),
		JWKsURI("https://rp.example.com/jwks"),
		InitiateLoginURI("https://rp.example.com/login"),
	)

	err := registrationPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := registrationPointer.Response()

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

	if response.RegistrationAccessToken != "REGISTRATION_ACCESS_TOKEN" {
		t.Errorf("invalid registration_access_token. expected: REGISTRATION_ACCESS_TOKEN, actual: %v", response.RegistrationAccessToken)
	}

	if response.RegistrationClientURI != "https://op.example.com/registration?client_id=CLINET_ID" {
		t.Errorf("invalid registration_client_uri. expected: https://op.example.com/registration?client_id=CLINET_ID, actual: %v", response.RegistrationClientURI)
	}

	if response.ClientIDIssuedAt != 0 {
		t.Errorf("invalid client_id_issued_at. expected: 0, actual: %v", response.ClientIDIssuedAt)
	}

	for key, expected := range []string{"client_secret_basic"} {
		if response.TokenEndpointAuthMethod[key] != expected {
			t.Errorf("invalid token_endpoint_auth_method. expected: %v, actual: %v", expected, response.TokenEndpointAuthMethod[key])
		}
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

func TestNewRegistrationFailure(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/json$").
		Post("/registration").
		MatchType("json").
		JSON(map[string]interface{}{
			"redirect_uris": []string{
				"INVALID_REDIRECT_URIS",
			},
		}).
		Reply(400).
		JSON(map[string]interface{}{
			"error":             "invalid_redirect_uri",
			"error_description": "One or more redirect_uri values are invalid",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.RegistrationEndpoint("https://op.example.com/registration"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	registrationPointer := NewRegistration(
		oIDCConfigResponse,
		[]string{
			"INVALID_REDIRECT_URIS",
		},
	)

	err := registrationPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := registrationPointer.Response()

	if response.Status != "400 Bad Request" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 400 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.Error != "invalid_redirect_uri" {
		t.Errorf("invalid error. expected: invalid_redirect_uri, actual: %v", response.Error)
	}

	if response.ErrorDescription != "One or more redirect_uri values are invalid" {
		t.Errorf("invalid error_description. expected: One or more redirect_uri values are invalid, actual: %v", response.ErrorDescription)
	}
}

func TestNewRegistrationDecodingFailure(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/json$").
		Post("/registration").
		MatchType("json").
		JSON(map[string]interface{}{
			"redirect_uris": []string{
				"https://rp.example.com/callback",
			},
		}).
		Reply(200).
		BodyString("INVALID_BODY")

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.RegistrationEndpoint("https://op.example.com/registration"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	registrationPointer := NewRegistration(
		oIDCConfigResponse,
		[]string{
			"https://rp.example.com/callback",
		},
	)

	err := registrationPointer.Request()

	if err == nil {
		t.Fatalf("expect json decoding error.")
	}
}
