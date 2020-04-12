package authorization

import (
	"net/url"

	"../oidcconfig"
)

type Authorization struct {
	oidcconfig *oidcconfig.OIDCConfig
	// required
	clientID     string
	redirectURI  string
	responseType string
	scope        string
	// recommended
	state string
	nonce string
	// optional
	prompt                               string
	display                              string
	codeChallenge                        string
	codeChallengeMethod                  string
	authenticationContextReferenceValues string
}

func NewAuthorization(oidcconfig *oidcconfig.OIDCConfig, clientID string, redirectURI string, options ...Option) *Authorization {
	authorization := new(Authorization)
	authorization.oidcconfig = oidcconfig
	authorization.clientID = clientID
	authorization.redirectURI = redirectURI
	authorization.responseType = "code"
	authorization.scope = "openid"

	for _, option := range options {
		option(authorization)
	}
	return authorization
}

type Option func(*Authorization) error

func ResponseType(responseType string) Option {
	return func(authorization *Authorization) error {
		authorization.responseType = responseType
		return nil
	}
}

func Scope(scope string) Option {
	return func(authorization *Authorization) error {
		authorization.scope = scope
		return nil
	}
}

func State(state string) Option {
	return func(authorization *Authorization) error {
		authorization.state = state
		return nil
	}
}

func Nonce(nonce string) Option {
	return func(authorization *Authorization) error {
		authorization.nonce = nonce
		return nil
	}
}

func Prompt(prompt string) Option {
	return func(authorization *Authorization) error {
		authorization.prompt = prompt
		return nil
	}
}

func Display(display string) Option {
	return func(authorization *Authorization) error {
		authorization.display = display
		return nil
	}
}

func CodeChallenge(codeChallenge string) Option {
	return func(authorization *Authorization) error {
		authorization.codeChallenge = codeChallenge
		return nil
	}
}

func CodeChallengeMethod(codeChallengeMethod string) Option {
	return func(authorization *Authorization) error {
		authorization.codeChallengeMethod = codeChallengeMethod
		return nil
	}
}

func AuthenticationContextReferenceValues(authenticationContextReferenceValues string) Option {
	return func(authorization *Authorization) error {
		authorization.authenticationContextReferenceValues = authenticationContextReferenceValues
		return nil
	}
}

func (authorization *Authorization) GenerateURL() (string, error) {

	u, err := url.Parse(authorization.oidcconfig.AuthorizationEndpoint())
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", authorization.clientID)
	q.Set("redirect_uri", authorization.redirectURI)
	q.Set("response_type", authorization.responseType)
	q.Set("scope", authorization.scope)

	if authorization.state != "" {
		q.Set("state", authorization.state)
	}
	if authorization.nonce != "" {
		q.Set("nonce", authorization.nonce)
	}
	if authorization.prompt != "" {
		q.Set("prompt", authorization.prompt)
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
