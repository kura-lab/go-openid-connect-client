package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"github.com/kura-lab/go-openid-connect-client/pkg/state"
	mystrings "github.com/kura-lab/go-openid-connect-client/pkg/strings"
	"github.com/kura-lab/go-openid-connect-client/pkg/token/granttype"
)

// Response is struct for Token Response.
type Response struct {
	Status           string
	StatusCode       int
	Body             string
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// Token is struct to request Token Endpoint.
type Token struct {
	oIDCConfig oidcconfig.Response
	statePass  state.Pass
	response   Response
	// required
	clientID     string
	clientSecret string
	grantType    string
	// optional
	codeVerifier string
	// case by case
	authorizationCode string
	redirectURI       string
	refreshToken      string

	tokenEndpointAuthMethod string
}

// NewToken is Token constructor function.
func NewToken(oIDCConfig oidcconfig.Response, clientID string, clientSecret string, options ...Option) *Token {
	token := new(Token)
	token.oIDCConfig = oIDCConfig
	token.clientID = clientID
	token.clientSecret = clientSecret
	token.grantType = "authorization_code"

	token.tokenEndpointAuthMethod = "client_secret_basic"

	for _, option := range options {
		option(token)
	}
	return token
}

// Option is functional option for Token struct initialization.
type Option func(*Token) error

// IgnoreStateVerification is functional option to ignore state verification
// Notice: using this function is not recommended. you should verify state to prevent Cross-Site Request Forgery(CSRF, XSRF).
func IgnoreStateVerification() Option {
	return func(token *Token) error {
		token.statePass = state.Pass{VerificationResult: true}
		return nil
	}
}

// StatePass is functional option to add state.pass included state verification result.
func StatePass(pass state.Pass) Option {
	return func(token *Token) error {
		token.statePass = pass
		return nil
	}
}

// GrantType is functional option to add "grant_type" parameter.
func GrantType(grantType string) Option {
	return func(token *Token) error {
		token.grantType = grantType
		return nil
	}
}

// CodeVerifier is functional option to add "code_verifier" parameter.
func CodeVerifier(codeVerifier string) Option {
	return func(token *Token) error {
		token.codeVerifier = codeVerifier
		return nil
	}
}

// AuthorizationCode is functional option to add "authorization_code" parameter.
func AuthorizationCode(authorizationCode string) Option {
	return func(token *Token) error {
		token.authorizationCode = authorizationCode
		return nil
	}
}

// RedirectURI is functional option to add "redirect_uri" parameter.
func RedirectURI(redirectURI string) Option {
	return func(token *Token) error {
		token.redirectURI = redirectURI
		return nil
	}
}

// RefreshToken is functional option to add "refresh_token" parameter.
func RefreshToken(refreshToken string) Option {
	return func(token *Token) error {
		token.refreshToken = refreshToken
		return nil
	}
}

// ClientSecretPost is functional option to specify client_id and client_secret with post body. token_endpoint_auth_method is "client_secret_post".
// default method is "client_secret_basic"(Basic Authentication) if not specify this option.
func ClientSecretPost() Option {
	return func(token *Token) error {
		token.tokenEndpointAuthMethod = "client_secret_post"
		return nil
	}
}

// Request is method to request Token Endpoint.
func (token *Token) Request() (nerr error) {

	if token.grantType == granttype.AuthorizationCode {
		if !token.statePass.VerificationResult {
			nerr = errors.New("state parameter has not been verified or the verification result was false")
			return
		}
	}

	values := url.Values{}
	values.Set("grant_type", token.grantType)

	if token.codeVerifier != "" {
		values.Add("code_verifier", token.codeVerifier)
	}
	if token.authorizationCode != "" {
		values.Add("code", token.authorizationCode)
	}
	if token.redirectURI != "" {
		values.Add("redirect_uri", token.redirectURI)
	}
	if token.refreshToken != "" {
		values.Add("refresh_token", token.refreshToken)
	}

	if len(token.oIDCConfig.TokenEndpointAuthMethodsSupported) > 0 {
		if !mystrings.Contains(token.tokenEndpointAuthMethod, token.oIDCConfig.TokenEndpointAuthMethodsSupported) {
			nerr = errors.New("unsupported token_endpoint_auth_method. actual is " + token.tokenEndpointAuthMethod +
				". support method are " + fmt.Sprintf("%#v", token.oIDCConfig.TokenEndpointAuthMethodsSupported))
			return
		}
	}

	if token.tokenEndpointAuthMethod == "client_secret_post" {
		values.Add("client_id", token.clientID)
		values.Add("client_secret", token.clientSecret)
	}

	tokenRequest, err := http.NewRequest(
		"POST",
		token.oIDCConfig.TokenEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		nerr = err
		return
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if token.tokenEndpointAuthMethod == "client_secret_basic" {
		tokenRequest.SetBasicAuth(token.clientID, token.clientSecret)
	}

	response, err := http.DefaultClient.Do(tokenRequest)
	defer func() {
		if _, err := io.Copy(ioutil.Discard, response.Body); err != nil {
			nerr = err
			return
		}
		if err := response.Body.Close(); err != nil {
			nerr = err
			return
		}
	}()

	if err != nil {
		nerr = err
		return
	}

	buf := bytes.NewBuffer(nil)
	body := bytes.NewBuffer(nil)

	w := io.MultiWriter(buf, body)
	io.Copy(w, response.Body)

	var tokenResponse Response
	token.response = tokenResponse
	token.response.Status = response.Status
	token.response.StatusCode = response.StatusCode

	rawBody, err := ioutil.ReadAll(buf)
	if err != nil {
		nerr = err
		return
	}
	token.response.Body = string(rawBody)

	err = json.NewDecoder(body).Decode(&token.response)
	if err != nil {
		nerr = err
		return
	}

	return
}

// Response is getter method of Response struct.
func (token *Token) Response() Response {
	return token.response
}
