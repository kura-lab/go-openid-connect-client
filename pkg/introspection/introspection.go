package introspection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/header"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for OAuth 2.0 Token Introspection Response.
type Response struct {
	Status     string
	StatusCode int
	Body       string
	// requierd
	Active bool `json:"active"`
	// optional
	Scope       string `json:"scope"`
	ClientID    string `json:"client_id"`
	UserName    string `json:"username"`
	TokenType   string `json:"token_type"`
	Expire      int    `json:"exp"`
	IssuedAt    int    `json:"iat"`
	NotBefore   int    `json:"nbf"`
	Subject     string `json:"sub"`
	Audience    []string
	RawAudience json.RawMessage `json:"aud"`
	Issuer      string          `json:"iss"`
	JWTID       string          `json:"jti"`

	WWWAuthenticate  header.WWWAuthenticate
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// Introspection is struct to request OAuth 2.0 Token Introspection Endpoint.
type Introspection struct {
	oIDCConfig oidcconfig.Response
	response   Response
	// required. Access Token or Refresh Token.
	token string
	// optional
	tokenTypeHint string
	accessToken   string
	clientID      string
	clientSecret  string
}

// NewIntrospection is Introspection constructor function.
func NewIntrospection(oIDCConfig oidcconfig.Response, token string, options ...Option) *Introspection {
	introspection := new(Introspection)
	introspection.oIDCConfig = oIDCConfig
	introspection.token = token

	for _, option := range options {
		option(introspection)
	}
	return introspection
}

// Option is functional option for Introspection struct initialization.
type Option func(*Introspection) error

// TokenTypeHint is functional option to add token_type_hint parameter.
func TokenTypeHint(tokenTypeHint string) Option {
	return func(introspection *Introspection) error {
		introspection.tokenTypeHint = tokenTypeHint
		return nil
	}
}

// AccessToken is functional option to add Access Token in Authorization Bearer Header.
func AccessToken(accessToken string) Option {
	return func(introspection *Introspection) error {
		introspection.accessToken = accessToken
		return nil
	}
}

// ClientAuthentication is functional option to add Client(Basic) Authentication.
func ClientAuthentication(clientID string, clientSecret string) Option {
	return func(introspection *Introspection) error {
		introspection.clientID = clientID
		introspection.clientSecret = clientSecret
		return nil
	}
}

// Request is method to request OAuth 2.0 Token Introspection Endpoint.
func (introspection *Introspection) Request() (nerr error) {

	values := url.Values{}
	values.Set("token", introspection.token)

	if introspection.tokenTypeHint != "" {
		values.Add("token_type_hint", introspection.tokenTypeHint)
	}

	introspectionRequest, err := http.NewRequest(
		http.MethodPost,
		introspection.oIDCConfig.IntrospectionEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		nerr = err
		return
	}

	introspectionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if introspection.accessToken != "" {
		introspectionRequest.Header.Set("Authorization", "Bearer "+introspection.accessToken)
	} else if introspection.clientID != "" && introspection.clientSecret != "" {
		introspectionRequest.SetBasicAuth(introspection.clientID, introspection.clientSecret)
	}

	response, err := http.DefaultClient.Do(introspectionRequest)
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

	var introspectionResponse Response
	introspection.response = introspectionResponse
	introspection.response.Status = response.Status
	introspection.response.StatusCode = response.StatusCode

	rawBody, err := ioutil.ReadAll(buf)
	if err != nil {
		nerr = err
		return
	}
	introspection.response.Body = string(rawBody)

	err = json.NewDecoder(body).Decode(&introspection.response)
	if err != nil {
		nerr = err
		return
	}

	if introspection.response.RawAudience != nil {
		if err := json.Unmarshal(introspection.response.RawAudience, &introspection.response.Audience); err != nil {
			var audString string
			if err := json.Unmarshal(introspection.response.RawAudience, &audString); err != nil {
				nerr = errors.New("unexpected type of aud claim. it assumes array type of string or string type")
				return
			}
			introspection.response.Audience = append(introspection.response.Audience, audString)
		}
	}

	if response.Header.Get("WWW-Authenticate") != "" {
		parsed := header.ParseWWWAuthenticateHeader(response.Header.Get("WWW-Authenticate"))
		if parsed["realm"] != "" {
			introspection.response.WWWAuthenticate.Realm = parsed["realm"]
		}
		if parsed["scope"] != "" {
			introspection.response.WWWAuthenticate.Scope = parsed["scope"]
		}
		if parsed["error"] != "" {
			introspection.response.WWWAuthenticate.Error = parsed["error"]
		}
		if parsed["error_description"] != "" {
			introspection.response.WWWAuthenticate.ErrorDescription = parsed["error_description"]
		}
	}

	return
}

// Response is getter method of Response struct
func (introspection *Introspection) Response() Response {
	return introspection.response
}
