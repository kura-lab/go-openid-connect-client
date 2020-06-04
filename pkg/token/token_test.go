package token

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"github.com/kura-lab/go-openid-connect-client/pkg/state"
	"github.com/kura-lab/go-openid-connect-client/pkg/token/granttype"
	"gopkg.in/h2non/gock.v1"
)

func TestNewTokenAuthorizationCodeSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/token").
		Reply(200).
		JSON(map[string]interface{}{
			"access_token":  "ACCESS_TOKEN",
			"token_type":    "Bearer",
			"refresh_token": "REFRESH_TOKEN",
			"expires_in":    1577804400,
			"id_token":      "ID_TOKEN",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.TokenEndpoint("https://op.example.com/token"),
		oidcconfig.TokenEndpointAuthMethodsSupported([]string{"client_secret_basic"}),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	statePass := state.Pass{VerificationResult: true}

	tokenPointer := NewToken(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		StatePass(statePass),
		GrantType(granttype.AuthorizationCode),
		AuthorizationCode("AUTHORIZATION_CODE"),
		RedirectURI("REDIRECT_URI"),
		CodeVerifier("CODE_VERIFIER"),
	)

	err := tokenPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := tokenPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.AccessToken != "ACCESS_TOKEN" {
		t.Errorf("invalid access token. expected: ACCESS_TOKEN, actual: %v", response.AccessToken)
	}

	if response.TokenType != "Bearer" {
		t.Errorf("invalid token type. expected: bearer, actual: %v", response.TokenType)
	}

	if response.RefreshToken != "REFRESH_TOKEN" {
		t.Errorf("invalid refres token. expected: REFRESH_TOKEN, actual: %v", response.RefreshToken)
	}

	if response.ExpiresIn != 1577804400 {
		t.Errorf("invalid expires in. expected: 1577804400, actual: %v", response.ExpiresIn)
	}

	if response.IDToken != "ID_TOKEN" {
		t.Errorf("invalid id token. expected: ID_TOKEN, actual: %v", response.IDToken)
	}
}

func TestNewTokenAuthorizationCodeClientSecretPostSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		Post("/token").
		Reply(200).
		JSON(map[string]interface{}{
			"access_token":  "ACCESS_TOKEN",
			"token_type":    "Bearer",
			"refresh_token": "REFRESH_TOKEN",
			"expires_in":    1577804400,
			"id_token":      "ID_TOKEN",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.TokenEndpoint("https://op.example.com/token"),
		oidcconfig.TokenEndpointAuthMethodsSupported([]string{"client_secret_post"}),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	statePass := state.Pass{VerificationResult: true}

	tokenPointer := NewToken(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		StatePass(statePass),
		GrantType(granttype.AuthorizationCode),
		AuthorizationCode("AUTHORIZATION_CODE"),
		RedirectURI("REDIRECT_URI"),
		CodeVerifier("CODE_VERIFIER"),
	)

	err := tokenPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := tokenPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}
}

func TestNewTokenIgnoreStateVerificationSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/token").
		Reply(200).
		JSON(map[string]interface{}{
			"access_token":  "ACCESS_TOKEN",
			"token_type":    "Bearer",
			"refresh_token": "REFRESH_TOKEN",
			"expires_in":    1577804400,
			"id_token":      "ID_TOKEN",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.TokenEndpoint("https://op.example.com/token"),
		oidcconfig.TokenEndpointAuthMethodsSupported([]string{"client_secret_basic"}),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	tokenPointer := NewToken(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		IgnoreStateVerification(),
		GrantType(granttype.AuthorizationCode),
		AuthorizationCode("AUTHORIZATION_CODE"),
		RedirectURI("REDIRECT_URI"),
		CodeVerifier("CODE_VERIFIER"),
	)

	err := tokenPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := tokenPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}
}

func TestNewTokenRefreshTokenSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/token").
		Reply(200).
		JSON(map[string]interface{}{
			"access_token": "ACCESS_TOKEN",
			"token_type":   "Bearer",
			"expires_in":   1577804400,
			"id_token":     "ID_TOKEN",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.TokenEndpoint("https://op.example.com/token"),
		oidcconfig.TokenEndpointAuthMethodsSupported([]string{"client_secret_basic"}),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	tokenPointer := NewToken(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		GrantType(granttype.RefreshToken),
		RefreshToken("REFRESH_TOKEN"),
	)

	err := tokenPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := tokenPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.AccessToken != "ACCESS_TOKEN" {
		t.Errorf("invalid access token. expected: ACCESS_TOKEN, actual: %v", response.AccessToken)
	}

	if response.TokenType != "Bearer" {
		t.Errorf("invalid token type. expected: bearer, actual: %v", response.TokenType)
	}

	if response.RefreshToken != "" {
		t.Errorf("exists refres token. expected: (empty), actual: %v", response.RefreshToken)
	}

	if response.ExpiresIn != 1577804400 {
		t.Errorf("invalid expires in. expected: 1577804400, actual: %v", response.ExpiresIn)
	}

	if response.IDToken != "ID_TOKEN" {
		t.Errorf("invalid id token. expected: ID_TOKEN, actual: %v", response.IDToken)
	}
}

func TestNewTokenFailures(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		BasicAuth("CLIENT_ID", "CLIENT_SECRET").
		Post("/token").
		Reply(200).
		BodyString("INVALID_BODY")

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.TokenEndpoint("https://op.example.com/token"),
		oidcconfig.TokenEndpointAuthMethodsSupported([]string{"client_secret_basic"}),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	statePass := state.Pass{VerificationResult: true}

	tokenPointer := NewToken(
		oIDCConfigResponse,
		"CLIENT_ID",
		"CLIENT_SECRET",
		StatePass(statePass),
		GrantType(granttype.AuthorizationCode),
		AuthorizationCode("AUTHORIZATION_CODE"),
		RedirectURI("REDIRECT_URI"),
		CodeVerifier("CODE_VERIFIER"),
	)

	err := tokenPointer.Request()

	if err == nil {
		t.Fatalf("expect json parsing error.")
	}
}
