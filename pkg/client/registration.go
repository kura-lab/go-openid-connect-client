package client

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/header"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for Client Registration Response.
type Response struct {
	Status                  string
	StatusCode              int
	Body                    string
	WWWAuthenticate         header.WWWAuthenticate
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientSecretExpiresAt   int      `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientIDIssuedAt        int      `json:"client_id_issued_at"`
	TokenEndpointAuthMethod []string `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	LogoURI                 string   `json:"logo_uri"`
	SubjectType             string   `json:"subject_type"`
	JWKsURI                 string   `json:"jwks_uri"`
	Error                   string   `json:"error"`
	ErrorDescription        string   `json:"error_description"`
}

// Registration is struct to request Client Registration Endpoint.
type Registration struct {
	oIDCConfig oidcconfig.Response
	request    map[string]interface{}
	response   Response
}

// NewRegistration is Registration constructor function.
func NewRegistration(oIDCConfig oidcconfig.Response, redirectURIs []string, options ...Option) *Registration {
	registration := new(Registration)
	registration.oIDCConfig = oIDCConfig

	registration.request = map[string]interface{}{}
	registration.request["redirect_uris"] = redirectURIs

	for _, option := range options {
		option(registration)
	}
	return registration
}

// Option is functional option for Registration struct initialization.
type Option func(*Registration) error

// ApplicationType is functional option to add "application_type" parameter.
func ApplicationType(applicationType string) Option {
	return func(registration *Registration) error {
		registration.request["application_type"] = applicationType
		return nil
	}
}

// ResponseTypes is functional option to add "response_types" parameter.
func ResponseTypes(responseTypes []string) Option {
	return func(registration *Registration) error {
		registration.request["response_types"] = responseTypes
		return nil
	}
}

// GrantTypes is functional option to add "grant_types" parameter.
func GrantTypes(grantTypes []string) Option {
	return func(registration *Registration) error {
		registration.request["grant_types"] = grantTypes
		return nil
	}
}

// Name is functional option to add "client_name" parameter.
func Name(clientName string) Option {
	return func(registration *Registration) error {
		registration.request["client_name"] = clientName
		return nil
	}
}

// LogoURI is functional option to add "logo_uri" parameter.
func LogoURI(logoURI string) Option {
	return func(registration *Registration) error {
		registration.request["logo_uri"] = logoURI
		return nil
	}
}

// SubjectType is functional option to add "subject_type" parameter.
func SubjectType(subjectType string) Option {
	return func(registration *Registration) error {
		registration.request["subject_type"] = subjectType
		return nil
	}
}

// TokenEndpointAuthMethod is functional option to add "token_endpoint_auth_method" parameter.
func TokenEndpointAuthMethod(tokenEndpointAuthMethod string) Option {
	return func(registration *Registration) error {
		registration.request["token_endpoint_auth_method"] = tokenEndpointAuthMethod
		return nil
	}
}

// JWKsURI is functional option to add "jwks_uri" parameter.
func JWKsURI(jWKsURI string) Option {
	return func(registration *Registration) error {
		registration.request["jwks_uri"] = jWKsURI
		return nil
	}
}

// InitiateLoginURI is functional option to add "initiate_login_uri" parameter.
func InitiateLoginURI(initiateLoginURI string) Option {
	return func(registration *Registration) error {
		registration.request["initiate_login_uri"] = initiateLoginURI
		return nil
	}
}

// Request is method to request Registration Endpoint.
func (registration *Registration) Request() (nerr error) {

	requestBody, err := json.Marshal(registration.request)
	if err != nil {
		nerr = err
		return
	}

	registrationRequest, err := http.NewRequest(
		"POST",
		registration.oIDCConfig.RegistrationEndpoint,
		strings.NewReader(string(requestBody)),
	)
	if err != nil {
		nerr = err
		return
	}
	registrationRequest.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(registrationRequest)
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
	responseBody := bytes.NewBuffer(nil)

	w := io.MultiWriter(buf, responseBody)
	io.Copy(w, response.Body)

	var registrationResponse Response
	registration.response = registrationResponse
	registration.response.Status = response.Status
	registration.response.StatusCode = response.StatusCode

	rawBody, err := ioutil.ReadAll(buf)
	if err != nil {
		nerr = err
		return
	}
	registration.response.Body = string(rawBody)

	err = json.NewDecoder(responseBody).Decode(&registration.response)
	if err != nil {
		nerr = err
		return
	}

	return
}

// Response is getter method of Response struct.
func (registration *Registration) Response() Response {
	return registration.response
}
