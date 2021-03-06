package authorization

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/responsetype"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/scope"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	mystrings "github.com/kura-lab/go-openid-connect-client/pkg/strings"
)

// Authorization is struct to generate Authorization Endpoint URL.
type Authorization struct {
	oIDCConfig oidcconfig.Response
	// required
	clientID     string
	redirectURI  string
	responseType []string
	responseMode string
	scope        []string
	// recommended
	state string
	nonce string
	// optional
	prompt                               []string
	display                              string
	codeChallenge                        string
	codeChallengeMethod                  string
	authenticationContextReferenceValues string
}

// NewAuthorization is Authorization constructor function.
func NewAuthorization(oIDCConfig oidcconfig.Response, clientID string, redirectURI string, options ...Option) *Authorization {
	authorization := new(Authorization)
	authorization.oIDCConfig = oIDCConfig
	authorization.clientID = clientID
	authorization.redirectURI = redirectURI
	authorization.responseType = []string{responsetype.Code}
	authorization.scope = []string{scope.OpenID}

	for _, option := range options {
		option(authorization)
	}
	return authorization
}

// Option is functional option for Authorization struct initialization.
type Option func(*Authorization) error

// ResponseType is functional option to add "response_type" parameter.
func ResponseType(responseType ...string) Option {
	return func(authorization *Authorization) error {
		authorization.responseType = responseType
		return nil
	}
}

// ResponseMode is functional option to add "response_mode" parameter.
func ResponseMode(responseMode string) Option {
	return func(authorization *Authorization) error {
		authorization.responseMode = responseMode
		return nil
	}
}

// Scope is functional option to add "scope" parameter.
func Scope(scope ...string) Option {
	return func(authorization *Authorization) error {
		authorization.scope = scope
		return nil
	}
}

// State is functional option to add "state" parameter.
func State(state string) Option {
	return func(authorization *Authorization) error {
		authorization.state = state
		return nil
	}
}

// Nonce is functional option to add "nonce" parameter.
func Nonce(nonce string) Option {
	return func(authorization *Authorization) error {
		authorization.nonce = nonce
		return nil
	}
}

// Prompt is functional option to add "prompt" parameter.
func Prompt(prompt ...string) Option {
	return func(authorization *Authorization) error {
		authorization.prompt = prompt
		return nil
	}
}

// Display is functional option to add "display" parameter.
func Display(display string) Option {
	return func(authorization *Authorization) error {
		authorization.display = display
		return nil
	}
}

// CodeChallenge is functional option to add "code_challenge" parameter.
func CodeChallenge(codeChallenge string) Option {
	return func(authorization *Authorization) error {
		authorization.codeChallenge = codeChallenge
		return nil
	}
}

// CodeChallengeMethod is functional option to add "code_challenge_method" parameter.
func CodeChallengeMethod(codeChallengeMethod string) Option {
	return func(authorization *Authorization) error {
		authorization.codeChallengeMethod = codeChallengeMethod
		return nil
	}
}

// AuthenticationContextReferenceValues is functional option to add "acr_values" parameter.
func AuthenticationContextReferenceValues(authenticationContextReferenceValues string) Option {
	return func(authorization *Authorization) error {
		authorization.authenticationContextReferenceValues = authenticationContextReferenceValues
		return nil
	}
}

// GenerateURL is method to generate Authorization Endpoint URL
func (authorization *Authorization) GenerateURL() (string, error) {

	u, err := url.Parse(authorization.oIDCConfig.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", authorization.clientID)
	q.Set("redirect_uri", authorization.redirectURI)

	if len(authorization.oIDCConfig.ResponseTypesSupported) > 0 && !validateResponseType(
		authorization.responseType,
		authorization.oIDCConfig.ResponseTypesSupported,
	) {
		return "", errors.New("unsupported response type. added response type is " + fmt.Sprintf("%v", authorization.responseType) +
			". supported response type is " + fmt.Sprintf("%v", authorization.oIDCConfig.ResponseTypesSupported))
	}
	q.Set("response_type", strings.Join(authorization.responseType, " "))

	if len(authorization.oIDCConfig.ResponseModesSupported) > 0 && authorization.responseMode != "" &&
		!mystrings.Contains(
			authorization.responseMode,
			authorization.oIDCConfig.ResponseModesSupported,
		) {
		return "", errors.New("unsupported response mode. added response mode is " + authorization.responseMode +
			". supported response modes are " + fmt.Sprintf("%v", authorization.oIDCConfig.ResponseModesSupported))
	}
	q.Set("response_mode", authorization.responseMode)

	if len(authorization.oIDCConfig.ScopesSupported) > 0 && !validateScope(
		authorization.scope,
		authorization.oIDCConfig.ScopesSupported,
	) {
		return "", errors.New("unsupported scope. added scope is " + fmt.Sprintf("%v", authorization.scope) +
			". expected scope is " + fmt.Sprintf("%v", authorization.oIDCConfig.ScopesSupported))
	}
	q.Set("scope", strings.Join(authorization.scope, " "))

	if authorization.state != "" {
		q.Set("state", authorization.state)
	}
	if authorization.nonce != "" {
		q.Set("nonce", authorization.nonce)
	}
	if len(authorization.prompt) > 0 {
		q.Set("prompt", strings.Join(authorization.prompt, " "))
	}
	if authorization.display != "" {
		q.Set("display", authorization.display)
	}
	if authorization.codeChallenge != "" {
		q.Set("code_challenge", authorization.codeChallenge)
	}
	if authorization.codeChallengeMethod != "" {
		q.Set("code_challenge_method", authorization.codeChallengeMethod)
	}
	if authorization.authenticationContextReferenceValues != "" {
		q.Set("acr_values", authorization.authenticationContextReferenceValues)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
