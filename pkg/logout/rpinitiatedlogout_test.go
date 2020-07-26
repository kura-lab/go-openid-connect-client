package logout

import (
	"net/url"
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

func TestNewLogoutSuccess(t *testing.T) {

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.EndSessionEndpoint("https://op.example.com/logout"),
	)
	oIDCConfigResponse := config.Response()

	logoutPotinter := NewLogout(
		oIDCConfigResponse,
		IDTokenHint("ID_TOKEN_HINT"),
		PostLogoutRedirectURI("https://rp.example.com/logout"),
		State("abc"),
	)

	logoutURL, err := logoutPotinter.GenerateURL()
	if err != nil {
		t.Fatalf("failed to generate logout url. err: %#v", err)
	}

	u, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("invalid generated logout url. err: %#v", err)
	}

	if u.Scheme != "https" {
		t.Errorf("invalid scheme. expected: https, actual: %v", u.Scheme)
	}

	if u.Hostname() != "op.example.com" {
		t.Errorf("invalid host name. expected: op.example.com, actual: %v", u.Scheme)
	}

	if u.Path != "/logout" {
		t.Errorf("invalid path. expected: /authorization. actual: %v", u.Scheme)
	}

	query := u.Query()

	if query.Get("id_token_hint") != "ID_TOKEN_HINT" {
		t.Errorf("invalid id_token_hint. expected: ID_TOKEN_HINT, actual: %v", query.Get("id_token_hint"))
	}

	if query.Get("post_logout_redirect_uri") != "https://rp.example.com/logout" {
		t.Errorf("invalid post_logout_redirect_uri. expected: https://rp.example.com/logout, actual: %v", query.Get("post_logout_redirect_uri"))
	}

	if query.Get("state") != "abc" {
		t.Errorf("invalid state. expected: abc, actual: %v", query.Get("state"))
	}
}

func TestNewLogoutFailure(t *testing.T) {

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.EndSessionEndpoint("INVALID_URL%"),
	)
	oIDCConfigResponse := config.Response()

	logoutPotinter := NewLogout(
		oIDCConfigResponse,
		IDTokenHint("ID_TOKEN_HINT"),
		PostLogoutRedirectURI("https://rp.example.com/logout"),
		State("abc"),
	)

	logoutURL, err := logoutPotinter.GenerateURL()
	if err == nil {
		t.Fatalf("expect logout url parse error.")
	}
	if logoutURL != "" {
		t.Fatalf("expect empty string.")
	}
}
