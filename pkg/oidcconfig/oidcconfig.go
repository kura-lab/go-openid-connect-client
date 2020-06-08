package oidcconfig

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
)

// Response is struct for OpenID Configuration Response.
type Response struct {
	Status                            string
	StatusCode                        int
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKsURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
}

// OIDCConfig is struct to request OpenID Configuration Endpoint.
type OIDCConfig struct {
	response                          Response
	uRL                               string
	issuer                            string
	authorizationEndpoint             string
	tokenEndpoint                     string
	userInfoEndpoint                  string
	jWKsURI                           string
	registrationEndpoint              string
	tokenEndpointAuthMethodsSupported []string
	responseTypesSupported            []string
	scopesSupported                   []string
	iDTokenSigningAlgValuesSupported  []string
}

// New is OIDCConfig constructor function.
func New(uRL string) *OIDCConfig {
	config := new(OIDCConfig)
	config.uRL = uRL
	return config
}

// NewOIDCConfig is OIDCConfig constructor function.
func NewOIDCConfig(options ...Option) *OIDCConfig {
	config := new(OIDCConfig)
	for _, option := range options {
		option(config)
	}
	return config
}

// Option is functional option for OIDCConfig struct initialization.
type Option func(*OIDCConfig) error

// Issuer is functional option to add Issuer.
func Issuer(issuer string) Option {
	return func(config *OIDCConfig) error {
		config.issuer = issuer
		return nil
	}
}

// RegistrationEndpoint is functional option to add Client Registration Endpoint.
func RegistrationEndpoint(registrationEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.registrationEndpoint = registrationEndpoint
		return nil
	}
}

// AuthorizationEndpoint is functional option to add Authorization Endpoint.
func AuthorizationEndpoint(authorizationEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.authorizationEndpoint = authorizationEndpoint
		return nil
	}
}

// TokenEndpoint is functional option to add Token Endpoint.
func TokenEndpoint(tokenEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.tokenEndpoint = tokenEndpoint
		return nil
	}
}

// UserInfoEndpoint is functional option to add UserInfo Endpoint.
func UserInfoEndpoint(userInfoEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.userInfoEndpoint = userInfoEndpoint
		return nil
	}
}

// JWKsURI is functional option to add JWKs URI.
func JWKsURI(jWKsURI string) Option {
	return func(config *OIDCConfig) error {
		config.jWKsURI = jWKsURI
		return nil
	}
}

// TokenEndpointAuthMethodsSupported is functional option to add Token Endpoint Authentication Methods Supported.
func TokenEndpointAuthMethodsSupported(tokenEndpointAuthMethodsSupported []string) Option {
	return func(config *OIDCConfig) error {
		config.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
		return nil
	}
}

// ResponseTypesSupported is functional option to add Response Types Supported.
func ResponseTypesSupported(responseTypesSupported []string) Option {
	return func(config *OIDCConfig) error {
		config.responseTypesSupported = responseTypesSupported
		return nil
	}
}

// ScopesSupported is functional option to add Scopes Supported.
func ScopesSupported(scopesSupported []string) Option {
	return func(config *OIDCConfig) error {
		config.scopesSupported = scopesSupported
		return nil
	}
}

// IDTokenSigningAlgValuesSupported is functional option to add ID Token Signing Algorithm Values Supported.
func IDTokenSigningAlgValuesSupported(iDTokenSigningAlgValuesSupported []string) Option {
	return func(config *OIDCConfig) error {
		config.iDTokenSigningAlgValuesSupported = iDTokenSigningAlgValuesSupported
		return nil
	}
}

// Request is method to request OpenID Configuration Endpoint.
func (config *OIDCConfig) Request() (nerr error) {
	configRequest, err := http.NewRequest(
		"GET",
		config.uRL,
		nil,
	)
	if err != nil {
		nerr = err
		return
	}
	response, err := http.DefaultClient.Do(configRequest)
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

	var configResponse Response
	err = json.NewDecoder(response.Body).Decode(&configResponse)
	if err != nil {
		nerr = err
		return
	}
	configResponse.Status = response.Status
	configResponse.StatusCode = response.StatusCode
	config.response = configResponse

	return
}

// Response is getter method of Response struct.
// if specify parameters with NewOIDCConfig, these parameter will be set.
func (config *OIDCConfig) Response() Response {

	if config.issuer != "" {
		config.response.Issuer = config.issuer
	}
	if config.authorizationEndpoint != "" {
		config.response.AuthorizationEndpoint = config.authorizationEndpoint
	}
	if config.tokenEndpoint != "" {
		config.response.TokenEndpoint = config.tokenEndpoint
	}
	if config.userInfoEndpoint != "" {
		config.response.UserInfoEndpoint = config.userInfoEndpoint
	}
	if config.jWKsURI != "" {
		config.response.JWKsURI = config.jWKsURI
	}
	if config.registrationEndpoint != "" {
		config.response.RegistrationEndpoint = config.registrationEndpoint
	}
	if len(config.tokenEndpointAuthMethodsSupported) > 0 {
		config.response.TokenEndpointAuthMethodsSupported = config.tokenEndpointAuthMethodsSupported
	}
	if len(config.responseTypesSupported) > 0 {
		config.response.ResponseTypesSupported = config.responseTypesSupported
	}
	if len(config.scopesSupported) > 0 {
		config.response.ScopesSupported = config.scopesSupported
	}
	if len(config.iDTokenSigningAlgValuesSupported) > 0 {
		config.response.IDTokenSigningAlgValuesSupported = config.iDTokenSigningAlgValuesSupported
	}

	return config.response
}
