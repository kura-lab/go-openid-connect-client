package token

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for Token Response.
type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

// Token is struct to request Token Endpoint.
type Token struct {
	oidcconfig *oidcconfig.OIDCConfig
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
func NewToken(oidcconfig *oidcconfig.OIDCConfig, clientID string, clientSecret string, options ...Option) *Token {
	token := new(Token)
	token.oidcconfig = oidcconfig
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
func (token *Token) Request() (Response, error) {
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

	tokenRequest, err := http.NewRequest(
		"POST",
		token.oidcconfig.TokenEndpoint(),
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return Response{}, err
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.SetBasicAuth(token.clientID, token.clientSecret)
	response, err := http.DefaultClient.Do(tokenRequest)
	defer func() {
		_, err = io.Copy(ioutil.Discard, response.Body)
		if err != nil {
			log.Panic(err)
		}
		err = response.Body.Close()
		if err != nil {
			log.Panic(err)
		}
	}()

	if err != nil {
		return Response{}, err
	}

	var tokenResponse Response
	err = json.NewDecoder(response.Body).Decode(&tokenResponse)
	if err != nil {
		return Response{}, err
	}

	return tokenResponse, nil
}
