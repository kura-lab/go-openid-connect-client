package introspection

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/introspection/tokentypehint"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"gopkg.in/h2non/gock.v1"
)

func TestNewIntrospectionSuccesses(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		Post("/introspection").
		Reply(200).
		JSON(map[string]interface{}{
			"active":     true,
			"scope":      "openid email profile",
			"client_id":  "CLIENT_ID",
			"username":   "USERNAME",
			"token_type": "bearer",
			"exp":        1592146800,
			"iat":        1592143200,
			"nbf":        1592143200,
			"sub":        "123456789",
			"aud":        []string{"CLIENT_ID", "CLIENT_ID2"},
			"iss":        "https://op.example.com",
			"jti":        "qwerty",
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.IntrospectionEndpoint("https://op.example.com/introspection"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	introspectionPointer := NewIntrospection(
		oIDCConfigResponse,
		"TOKEN",
	)

	err := introspectionPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := introspectionPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.Active != true {
		t.Errorf("invalid active. expected: true, actual: %v", response.Active)
	}

	if response.Scope != "openid email profile" {
		t.Errorf("invalid scope. expected: openid email profile, actual: %v", response.Scope)
	}

	if response.ClientID != "CLIENT_ID" {
		t.Errorf("invalid client_id. expected: CLIENT_ID, actual: %v", response.ClientID)
	}

	if response.UserName != "USERNAME" {
		t.Errorf("invalid username. expected: USERNAME, actual: %v", response.UserName)
	}

	if response.TokenType != "bearer" {
		t.Errorf("invalid token_type. expected: bearer, actual: %v", response.TokenType)
	}

	if response.Expire != 1592146800 {
		t.Errorf("invalid exp. expected: 1592146800, actual: %v", response.Expire)
	}

	if response.IssuedAt != 1592143200 {
		t.Errorf("invalid iat. expected: 1592143200, actual: %v", response.IssuedAt)
	}

	if response.NotBefore != 1592143200 {
		t.Errorf("invalid nbf. expected: 1592143200, actual: %v", response.NotBefore)
	}

	if response.Subject != "123456789" {
		t.Errorf("invalid sub. expected: 123456789, actual: %v", response.Subject)
	}

	for key, value := range []string{"CLIENT_ID", "CLIENT_ID2"} {
		if response.Audience[key] != value {
			t.Errorf("invalid aud. expected: %v, actual: %v", value, response.Audience[key])
		}
	}

	if response.Issuer != "https://op.example.com" {
		t.Errorf("invalid iss. expected: https://op.example.com, actual: %v", response.Issuer)
	}

	if response.JWTID != "qwerty" {
		t.Errorf("invalid jti. expected: qwerty, actual: %v", response.JWTID)
	}

	if response.WWWAuthenticate.Realm != "" {
		t.Errorf("invalid realm. expected: (empty), actual: %v", response.WWWAuthenticate.Realm)
	}

	if response.WWWAuthenticate.Scope != "" {
		t.Errorf("invalid scope. expected: (empty), actual: %v", response.WWWAuthenticate.Scope)
	}

	if response.WWWAuthenticate.Error != "" {
		t.Errorf("invalid error. expected: (empty), actual: %v", response.WWWAuthenticate.Error)
	}

	if response.WWWAuthenticate.ErrorDescription != "" {
		t.Errorf("invalid error description. expected: (empty), actual: %v", response.WWWAuthenticate.ErrorDescription)
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
		Post("/introspection").
		Reply(200).
		JSON(map[string]interface{}{
			"active": true,
			"aud":    "CLIENT_ID",
		})

	introspectionPointer = NewIntrospection(
		oIDCConfigResponse,
		"TOKEN",
		TokenTypeHint(tokentypehint.AccessToken),
		ClientAuthentication("CLIENT_ID", "CLIENT_SECRET"),
	)

	err = introspectionPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response = introspectionPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.Active != true {
		t.Errorf("invalid active. expected: true, actual: %v", response.Active)
	}

	for key, value := range []string{"CLIENT_ID"} {
		if response.Audience[key] != value {
			t.Errorf("invalid aud. expected: %v, actual: %v", value, response.Audience[key])
		}
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
		MatchHeader("Authorization", "^Bearer ACCESS_TOKEN$").
		Post("/introspection").
		Reply(200).
		JSON(map[string]interface{}{
			"active": true,
		})

	introspectionPointer = NewIntrospection(
		oIDCConfigResponse,
		"TOKEN",
		TokenTypeHint(tokentypehint.RefreshToken),
		AccessToken("ACCESS_TOKEN"),
	)

	err = introspectionPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response = introspectionPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.Active != true {
		t.Errorf("invalid active. expected: true, actual: %v", response.Active)
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

func TestNewIntrospectionFailures(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		MatchHeader("Authorization", "^Bearer ACCESS_TOKEN$").
		Post("/introspection").
		Reply(401).
		SetHeader("WWW-Authenticate",
			"Bearer realm=\"example\",\r\n"+
				"scope=\"openid profile email\",\r\n"+
				"error=\"invalid_token\",\r\n"+
				"error_description=\"The access token expired\"",
		).
		JSON(map[string]interface{}{})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.IntrospectionEndpoint("https://op.example.com/introspection"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	introspectionPointer := NewIntrospection(
		oIDCConfigResponse,
		"TOKEN",
		TokenTypeHint(tokentypehint.RefreshToken),
		AccessToken("ACCESS_TOKEN"),
	)

	err := introspectionPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := introspectionPointer.Response()

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
		MatchHeader("Authorization", "^Bearer ACCESS_TOKEN$").
		Post("/introspection").
		Reply(400).
		JSON(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "unsupported parameter",
			"error_uri":         "https://op.example.com/error",
		})

	introspectionPointer = NewIntrospection(
		oIDCConfigResponse,
		"TOKEN",
		TokenTypeHint("INVALID_TOKEN_TYPE_HINT"),
		AccessToken("ACCESS_TOKEN"),
	)

	err = introspectionPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response = introspectionPointer.Response()

	if response.Status != "400 Bad Request" {
		t.Errorf("invalid http status. expected: 400 Bad Request, actual: %v", response.Status)
	}

	if response.StatusCode != 400 {
		t.Errorf("invalid http status code. expected: 400, actual: %v", response.StatusCode)
	}

	if response.WWWAuthenticate.Realm != "" {
		t.Errorf("invalid realm. expected: (empty), actual: %v", response.WWWAuthenticate.Realm)
	}

	if response.WWWAuthenticate.Scope != "" {
		t.Errorf("invalid scope. expected: (empty), actual: %v", response.WWWAuthenticate.Scope)
	}

	if response.WWWAuthenticate.Error != "" {
		t.Errorf("invalid error. expected: (empty), actual: %v", response.WWWAuthenticate.Error)
	}

	if response.WWWAuthenticate.ErrorDescription != "" {
		t.Errorf("invalid error description. expected: (empty), actual: %v", response.WWWAuthenticate.ErrorDescription)
	}

	if response.Error != "invalid_request" {
		t.Errorf("invalid error. expected: invalid_request, actual: %v", response.Error)
	}

	if response.ErrorDescription != "unsupported parameter" {
		t.Errorf("invalid error_description. expected: unsupported parameter, actual: %v", response.ErrorDescription)
	}

	if response.ErrorURI != "https://op.example.com/error" {
		t.Errorf("invalid error_uri. expected: https://op.example.com/error, actual: %v", response.ErrorURI)
	}

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		Post("/introspection").
		Reply(200).
		BodyString("INVALID_BODY")

	introspectionPointer = NewIntrospection(
		oIDCConfigResponse,
		"TOKEN",
	)

	err = introspectionPointer.Request()

	if err == nil {
		t.Fatalf("expect json body parsing error.")
	}

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		Post("/introspection").
		Reply(200).
		JSON(map[string]interface{}{
			"active": true,
			"aud":    12345,
		})

	introspectionPointer = NewIntrospection(
		oIDCConfigResponse,
		"TOKEN",
	)

	err = introspectionPointer.Request()

	if err == nil {
		t.Fatalf("expect aud parsing error.")
	}
}
