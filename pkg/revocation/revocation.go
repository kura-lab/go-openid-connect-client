package revocation

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for OAuth 2.0 Token Revocation Response.
type Response struct {
	Status           string
	StatusCode       int
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// Revocation is struct to request OAuth 2.0 Token Revocation Endpoint.
type Revocation struct {
	oIDCConfig oidcconfig.Response
	response   Response
	// required. Access Token or Refresh Token.
	token string
	// optional
	tokenTypeHint string
}

// NewRevocation is Revocation constructor function.
func NewRevocation(oIDCConfig oidcconfig.Response, token string, options ...Option) *Revocation {
	revocation := new(Revocation)
	revocation.oIDCConfig = oIDCConfig
	revocation.token = token

	for _, option := range options {
		option(revocation)
	}
	return revocation
}

// Option is functional option for Revocation struct initialization.
type Option func(*Revocation) error

// TokenTypeHint is functional option to add token_type_hint parameter.
func TokenTypeHint(tokenTypeHint string) Option {
	return func(revocation *Revocation) error {
		revocation.tokenTypeHint = tokenTypeHint
		return nil
	}
}

// Request is method to request OAuth 2.0 Token Revocation Endpoint.
func (revocation *Revocation) Request() (nerr error) {

	revocationRequest, err := http.NewRequest(
		"POST",
		revocation.oIDCConfig.RevocationEndpoint,
		nil,
	)
	if err != nil {
		nerr = err
		return
	}

	revocationRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revocationRequest.Header.Set("Authorization", "Bearer "+revocation.token)
	response, err := http.DefaultClient.Do(revocationRequest)
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

	var revocationResponse Response
	err = json.NewDecoder(response.Body).Decode(&revocationResponse)
	if err != nil {
		nerr = err
		return
	}
	revocationResponse.Status = response.Status
	revocationResponse.StatusCode = response.StatusCode
	revocation.response = revocationResponse

	return
}

// Response is getter method of Response struct
func (revocation *Revocation) Response() Response {
	return revocation.response
}
