package revocation

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for OAuth 2.0 Token Revocation Response.
type Response struct {
	Status           string
	StatusCode       int
	Body             string
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// Revocation is struct to request OAuth 2.0 Token Revocation Endpoint.
type Revocation struct {
	oIDCConfig oidcconfig.Response
	response   Response
	// required. Access Token or Refresh Token.
	clientID     string
	clientSecret string
	token        string
	// optional
	tokenTypeHint string
}

// NewRevocation is Revocation constructor function.
func NewRevocation(oIDCConfig oidcconfig.Response, clientID string, clientSecret string, token string, options ...Option) *Revocation {
	revocation := new(Revocation)
	revocation.oIDCConfig = oIDCConfig
	revocation.clientID = clientID
	revocation.clientSecret = clientSecret
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

	values := url.Values{}
	values.Set("token", revocation.token)

	if revocation.tokenTypeHint != "" {
		values.Add("token_type_hint", revocation.tokenTypeHint)
	}

	revocationRequest, err := http.NewRequest(
		http.MethodPost,
		revocation.oIDCConfig.RevocationEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		nerr = err
		return
	}

	revocationRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revocationRequest.SetBasicAuth(revocation.clientID, revocation.clientSecret)

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

	buf := bytes.NewBuffer(nil)
	body := bytes.NewBuffer(nil)

	w := io.MultiWriter(buf, body)
	io.Copy(w, response.Body)

	var revocationResponse Response
	revocation.response = revocationResponse
	revocation.response.Status = response.Status
	revocation.response.StatusCode = response.StatusCode

	rawBody, err := ioutil.ReadAll(buf)
	if err != nil {
		nerr = err
		return
	}
	revocation.response.Body = string(rawBody)

	err = json.NewDecoder(body).Decode(&revocation.response)
	if err != nil {
		nerr = err
		return
	}

	return
}

// Response is getter method of Response struct
func (revocation *Revocation) Response() Response {
	return revocation.response
}
