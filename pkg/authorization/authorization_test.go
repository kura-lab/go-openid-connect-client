package authorization

import (
	"net/url"
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/codechallengemethod"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/display"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/prompt"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/responsemode"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/responsetype"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/scope"
	"github.com/kura-lab/go-openid-connect-client/pkg/hash"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

func TestNewAuthorizationSuccess(t *testing.T) {

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.AuthorizationEndpoint("https://op.example.com/authorization"),
	)
	oIDCConfigResponse := config.Response()

	authorizationPotinter := NewAuthorization(
		oIDCConfigResponse,
		"CLIENT_ID",
		"https://rp.example.com/callback",
		ResponseType(responsetype.Code, responsetype.IDToken),
		ResponseMode(responsemode.FormPost),
		Scope(scope.OpenID, scope.Email, scope.Profile),
		State("abc"),
		Nonce("xyz"),
		Prompt(prompt.Login, prompt.Consent),
		Display(display.Touch),
		CodeChallenge(hash.GenerateSHA256("12345")),
		CodeChallengeMethod(codechallengemethod.S256),
		AuthenticationContextReferenceValues("urn:mace:incommon:iap:silver"),
	)

	authorizationURL, err := authorizationPotinter.GenerateURL()
	if err != nil {
		t.Fatalf("failed to generate authorization url. err: %#v", err)
	}

	u, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("invalid generated authorization url. err: %#v", err)
	}

	if u.Scheme != "https" {
		t.Errorf("invalid scheme. expected: https, actual: %v", u.Scheme)
	}

	if u.Hostname() != "op.example.com" {
		t.Errorf("invalid host name. expected: op.example.com, actual: %v", u.Scheme)
	}

	if u.Path != "/authorization" {
		t.Errorf("invalid path. expected: /authorization. actual: %v", u.Scheme)
	}

	query := u.Query()

	if query.Get("client_id") != "CLIENT_ID" {
		t.Errorf("invalid client id. expected: CLIENT_ID, actual: %v", query.Get("client_id"))
	}

	if query.Get("redirect_uri") != "https://rp.example.com/callback" {
		t.Errorf("invalid redirect uri. expected: https://rp.example.com/callback, actual: %v", query.Get("redirect_uri"))
	}

	if query.Get("response_type") != "code id_token" {
		t.Errorf("invalid response type. expected: code id_token, actual: %v", query.Get("response_type"))
	}

	if query.Get("response_mode") != "form_post" {
		t.Errorf("invalid response mode. expected: form_post, actual: %v", query.Get("response_mode"))
	}

	if query.Get("scope") != "openid email profile" {
		t.Errorf("invalid scope. expected: openid email profile, actual: %v", query.Get("scope"))
	}

	if query.Get("state") != "abc" {
		t.Errorf("invalid state. expected: abc, actual: %v", query.Get("state"))
	}

	if query.Get("nonce") != "xyz" {
		t.Errorf("invalid nonce. expected: xyz, actual: %v", query.Get("nonce"))
	}

	if query.Get("prompt") != "login consent" {
		t.Errorf("invalid prompt. expected: login consent, actual: %v", query.Get("prompt"))
	}

	if query.Get("display") != "touch" {
		t.Errorf("invalid display. expected: touch, actual: %v", query.Get("display"))
	}

	if query.Get("code_challenge") != hash.GenerateSHA256("12345") {
		t.Errorf("invalid code challenge. expected: %v, actual: %v", hash.GenerateSHA256("12345"), query.Get("code_challenge"))
	}

	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("invalid code challenge method. expected: S256, actual: %v", query.Get("code_challenge_method"))
	}

	if query.Get("acr_values") != "urn:mace:incommon:iap:silver" {
		t.Errorf("invalid acr values. expected: urn:mace:incommon:iap:silver, actual: %v", query.Get("acr_values"))
	}
}

func TestNewAuthorizationFailures(t *testing.T) {

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.AuthorizationEndpoint("INVALID_URL%"),
	)
	oIDCConfigResponse := config.Response()

	authorizationPotinter := NewAuthorization(
		oIDCConfigResponse,
		"CLIENT_ID",
		"https://rp.example.com/callback",
		ResponseType(responsetype.Code, responsetype.IDToken),
		Scope(scope.OpenID, scope.Email, scope.Profile),
		State("abc"),
		Nonce("xyz"),
	)

	authorizationURL, err := authorizationPotinter.GenerateURL()
	if err == nil {
		t.Fatalf("expect authorization url parse error.")
	}
	if authorizationURL != "" {
		t.Fatalf("expect empty string.")
	}

	config = oidcconfig.NewOIDCConfig(
		oidcconfig.AuthorizationEndpoint("https://op.example.com/authorization"),
		oidcconfig.ResponseTypesSupported([]string{"code", "code token"}),
		oidcconfig.ResponseModesSupported([]string{"query", "fragment"}),
		oidcconfig.ScopesSupported([]string{"openid", "email", "profile"}),
	)
	oIDCConfigResponse = config.Response()

	authorizationPotinter = NewAuthorization(
		oIDCConfigResponse,
		"CLIENT_ID",
		"https://rp.example.com/callback",
		ResponseType(responsetype.IDToken),
		Scope(scope.OpenID, scope.Email, scope.Profile),
		State("abc"),
		Nonce("xyz"),
	)

	authorizationURL, err = authorizationPotinter.GenerateURL()
	if err == nil {
		t.Fatalf("expect response type error.")
	}
	if authorizationURL != "" {
		t.Fatalf("expect empty string.")
	}

	authorizationPotinter = NewAuthorization(
		oIDCConfigResponse,
		"CLIENT_ID",
		"https://rp.example.com/callback",
		ResponseType(responsetype.IDToken),
		ResponseMode(responsemode.FormPost),
		Scope(scope.OpenID, scope.Email, scope.Profile),
		State("abc"),
		Nonce("xyz"),
	)

	authorizationURL, err = authorizationPotinter.GenerateURL()
	if err == nil {
		t.Fatalf("expect response mode error.")
	}
	if authorizationURL != "" {
		t.Fatalf("expect empty string.")
	}

	authorizationPotinter = NewAuthorization(
		oIDCConfigResponse,
		"CLIENT_ID",
		"https://rp.example.com/callback",
		ResponseType(responsetype.Code),
		Scope(scope.OpenID, scope.Email, scope.Profile, scope.Address),
		State("abc"),
	)

	authorizationURL, err = authorizationPotinter.GenerateURL()
	if err == nil {
		t.Fatalf("expect scope error.")
	}
	if authorizationURL != "" {
		t.Fatalf("expect empty string.")
	}
}

func TestValidateResponseTypeSucceeds(t *testing.T) {

	data := [][][]string{
		{[]string{"code"}, []string{"code"}},
		{[]string{"token"}, []string{"code", "token"}},
		{[]string{"code", "token"}, []string{"code", "code token"}},
		{[]string{"code", "id_token", "token"}, []string{"code", "code token", "code token id_token"}},
	}

	for _, value := range data {
		if !validateResponseType(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t", true, false)
		}
	}
}

func TestValidateResponseTypeFailds(t *testing.T) {

	data := [][][]string{
		{[]string{"token"}, []string{"code"}},
		{[]string{"token"}, []string{"code", "code token"}},
		{[]string{"code id_token"}, []string{"code", "code token", "token id_token"}},
	}

	for _, value := range data {
		if validateResponseType(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t", false, true)
		}
	}
}

func TestValidateScopeSucceeds(t *testing.T) {

	data := [][][]string{
		{[]string{"openid"}, []string{"openid"}},
		{[]string{"openid"}, []string{"email", "openid"}},
		{[]string{"openid", "email"}, []string{"email", "openid"}},
		{[]string{"openid", "email"}, []string{"openid", "email", "profile"}},
	}

	for _, value := range data {
		if !validateScope(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t, input:%v", true, false, value[0])
		}
	}
}

func TestValidateScopeFailds(t *testing.T) {

	data := [][][]string{
		{[]string{"email"}, []string{"openid"}},
		{[]string{"email"}, []string{"openid", "profile", "address", "phone"}},
	}

	for _, value := range data {
		if validateScope(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t", false, true)
		}
	}
}
