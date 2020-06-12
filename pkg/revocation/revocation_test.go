package revocation

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"github.com/kura-lab/go-openid-connect-client/pkg/revocation/tokentypehint"
	"gopkg.in/h2non/gock.v1"
)

func TestNewRevocationSuccesses(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/revocation").
		Reply(200).
		JSON(map[string]interface{}{})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.RevocationEndpoint("https://op.example.com/revocation"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	revocationPointer := NewRevocation(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		"TOKEN",
	)

	err := revocationPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := revocationPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.Error != "" {
		t.Errorf("invalid error. expected: (empty), actual: %v", response.Error)
	}

	if response.ErrorDescription != "" {
		t.Errorf("invalid error_description. expected: (empty), actual: %v", response.ErrorDescription)
	}

	if response.ErrorURI != "" {
		t.Errorf("invalid error_uri. expected: (empty), actual: %v", response.ErrorURI)
	}

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/revocation").
		Reply(200).
		JSON(map[string]interface{}{})

	oIDCConfigPointer = oidcconfig.NewOIDCConfig(
		oidcconfig.RevocationEndpoint("https://op.example.com/revocation"),
	)

	oIDCConfigResponse = oIDCConfigPointer.Response()

	revocationPointer = NewRevocation(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		"TOKEN",
		TokenTypeHint(tokentypehint.AccessToken),
	)

	err = revocationPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response = revocationPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.Error != "" {
		t.Errorf("invalid error. expected: (empty), actual: %v", response.Error)
	}

	if response.ErrorDescription != "" {
		t.Errorf("invalid error_description. expected: (empty), actual: %v", response.ErrorDescription)
	}

	if response.ErrorURI != "" {
		t.Errorf("invalid error_uri. expected: (empty), actual: %v", response.ErrorURI)
	}
}

func TestNewRevocationFailures(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/revocation").
		Reply(400).
		JSON(map[string]interface{}{
			"error":             "unsupported_token_type",
			"error_description": "authorization server does not support the revocation of the presented token type",
			"error_uri":         "https://op.example.com/error",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.RevocationEndpoint("https://op.example.com/revocation"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	revocationPointer := NewRevocation(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		"TOKEN",
		TokenTypeHint(tokentypehint.RefreshToken),
	)

	err := revocationPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := revocationPointer.Response()

	if response.Status != "400 Bad Request" {
		t.Errorf("invalid http status. expected: 400 Bad Request, actual: %v", response.Status)
	}

	if response.StatusCode != 400 {
		t.Errorf("invalid http status code. expected: 400, actual: %v", response.StatusCode)
	}

	if response.Error != "unsupported_token_type" {
		t.Errorf("invalid error. expected: unsupported_token_type, actual: %v", response.Error)
	}

	if response.ErrorDescription != "authorization server does not support the revocation of the presented token type" {
		t.Errorf("invalid error_description. expected: authorization server does not support the revocation of the presented token type, actual: %v", response.ErrorDescription)
	}

	if response.ErrorURI != "https://op.example.com/error" {
		t.Errorf("invalid error_uri. expected: https://op.example.com/error, actual: %v", response.ErrorURI)
	}

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/revocation").
		Reply(200).
		BodyString("INVALID_BODY")

	oIDCConfigPointer = oidcconfig.NewOIDCConfig(
		oidcconfig.RevocationEndpoint("https://op.example.com/revocation"),
	)

	oIDCConfigResponse = oIDCConfigPointer.Response()

	revocationPointer = NewRevocation(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		"TOKEN",
	)

	err = revocationPointer.Request()

	if err == nil {
		t.Fatalf("expect json body parsing error.")
	}
}
