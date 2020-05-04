package token

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for Token Response.
type Response struct {
	Status           string
	StatusCode       int
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
}

// NewToken is Token constructor function.
func NewToken(oIDCConfig oidcconfig.Response, clientID string, clientSecret string, options ...Option) *Token {
	token := new(Token)
	token.oIDCConfig = oIDCConfig
	token.clientID = clientID
	token.clientSecret = clientSecret
	token.grantType = "authorization_code"

	for _, option := range options {
		option(token)
	}
	return token
}

// Option is functional option for Token struct initialization.
type Option func(*Token) error

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

// Request is method to request Token Endpoint.
func (token *Token) Request() error {
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

	tokenEndpointAuthMethod := "client_secret_basic"
	for _, method := range token.oIDCConfig.TokenEndpointAuthMethodsSupported {
		if method == "client_secret_basic" {
			tokenEndpointAuthMethod = "client_secret_basic"
			break
		} else if method == "client_secret_post" {
			tokenEndpointAuthMethod = "client_secret_post"
			values.Add("client_id", token.clientID)
			values.Add("refresh_secret", token.clientSecret)
			break
		}
	}

	tokenRequest, err := http.NewRequest(
		"POST",
		token.oIDCConfig.TokenEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return err
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if tokenEndpointAuthMethod == "client_secret_basic" {
		tokenRequest.SetBasicAuth(token.clientID, token.clientSecret)
	}

	response, err := http.DefaultClient.Do(tokenRequest)
	defer func() {
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
	}()

	if err != nil {
		return err
	}

	var tokenResponse Response
	err = json.NewDecoder(response.Body).Decode(&tokenResponse)
	if err != nil {
		return err
	}
	tokenResponse.Status = response.Status
	tokenResponse.StatusCode = response.StatusCode
	token.response = tokenResponse

	return nil
}

// Response is getter method of Response struct.
func (token *Token) Response() Response {
	return token.response
}
