package authorization

import (
	"errors"
	"net/url"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/responsetype"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/scope"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Authorization is struct to generate Authorization Endpoint URL.
type Authorization struct {
	oidcconfig *oidcconfig.OIDCConfig
	// required
	clientID     string
	redirectURI  string
	responseType []string
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
func NewAuthorization(oidcconfig *oidcconfig.OIDCConfig, clientID string, redirectURI string, options ...Option) *Authorization {
	authorization := new(Authorization)
	authorization.oidcconfig = oidcconfig
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

	u, err := url.Parse(authorization.oidcconfig.AuthorizationEndpoint())
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", authorization.clientID)
	q.Set("redirect_uri", authorization.redirectURI)

	if len(authorization.oidcconfig.ResponseTypesSupported()) > 0 && !validateResponseType(
		authorization.responseType,
		authorization.oidcconfig.ResponseTypesSupported(),
	) {
		return "", errors.New("unsupported response_type")
	}
	q.Set("response_type", strings.Join(authorization.responseType, " "))

	if len(authorization.oidcconfig.ScopesSupported()) > 0 && !validateScope(
		authorization.scope,
		authorization.oidcconfig.ScopesSupported(),
	) {
		return "", errors.New("unsupported scope")
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

func contains(src string, arr []string) bool {
	for _, value := range arr {
		if src == value {
			return true
		}
	}
	return false
}

func validateResponseType(responseTypes []string, responseTypesSupported []string) bool {
	exacted := false
	for _, supportedTypesString := range responseTypesSupported {
		supportedResponseTypes := strings.Split(supportedTypesString, " ")

		if len(responseTypes) != len(supportedResponseTypes) {
			continue
		}

		contain := false
		for _, responseType := range responseTypes {
			if contains(responseType, supportedResponseTypes) {
				contain = true
				continue
			} else {
				contain = false
				break
			}
		}
		if contain {
			exacted = true
			break
		}
	}

	return exacted
}

func validateScope(scopes []string, scopesSupported []string) bool {
	for _, scope := range scopes {
		if contains(scope, scopesSupported) {
			continue
		} else {
			return false
		}
	}

	return true
}
