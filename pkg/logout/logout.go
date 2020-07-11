package logout

import (
	"net/url"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Logout is struct to generate RP-Initiated Logout URL.
type Logout struct {
	oIDCConfig oidcconfig.Response
	// recommended
	iDTokenHint string
	// optional
	postLogoutRedirectURI string
	state                 string
}

// NewLogout is Logout constructor function.
func NewLogout(oIDCConfig oidcconfig.Response, options ...Option) *Logout {
	logout := new(Logout)
	logout.oIDCConfig = oIDCConfig

	for _, option := range options {
		option(logout)
	}
	return logout
}

// Option is functional option for Logout struct initialization.
type Option func(*Logout) error

// IDTokenHint is functional option to add "id_token_hint" parameter.
func IDTokenHint(iDTokenHint string) Option {
	return func(logout *Logout) error {
		logout.iDTokenHint = iDTokenHint
		return nil
	}
}

// PostLogoutRedirectURI is functional option to add "post_logout_redirect_uri" parameter.
func PostLogoutRedirectURI(postLogoutRedirectURI string) Option {
	return func(logout *Logout) error {
		logout.postLogoutRedirectURI = postLogoutRedirectURI
		return nil
	}
}

// State is functional option to add "state" parameter.
func State(state string) Option {
	return func(logout *Logout) error {
		logout.state = state
		return nil
	}
}

// GenerateURL is method to generate Logout Endpoint URL
func (logout *Logout) GenerateURL() (string, error) {

	u, err := url.Parse(logout.oIDCConfig.EndSessionEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()

	if logout.iDTokenHint != "" {
		q.Set("id_token_hint", logout.iDTokenHint)
	}

	if logout.postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", logout.postLogoutRedirectURI)
	}

	if logout.state != "" {
		q.Set("state", logout.state)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
