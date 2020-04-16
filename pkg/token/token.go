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

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

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

type Option func(*Token) error

func GrantType(grantType string) Option {
	return func(token *Token) error {
		token.grantType = grantType
		return nil
	}
}

func CodeVerifier(codeVerifier string) Option {
	return func(token *Token) error {
		token.codeVerifier = codeVerifier
		return nil
	}
}

func AuthorizationCode(authorizationCode string) Option {
	return func(token *Token) error {
		token.authorizationCode = authorizationCode
		return nil
	}
}

func RedirectURI(redirectURI string) Option {
	return func(token *Token) error {
		token.redirectURI = redirectURI
		return nil
	}
}

func RefreshToken(refreshToken string) Option {
	return func(token *Token) error {
		token.refreshToken = refreshToken
		return nil
	}
}

func (token *Token) Request() (TokenResponse, error) {
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
		return TokenResponse{}, err
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
		return TokenResponse{}, err
	}

	var tokenResponse TokenResponse
	err = json.NewDecoder(response.Body).Decode(&tokenResponse)
	if err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}
