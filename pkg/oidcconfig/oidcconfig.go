package oidcconfig

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

// Response is struct for OpenID Configuration Response.
type Response struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKsURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
}

// OIDCConfig is struct to request OpenID Configuration Endpoint.
type OIDCConfig struct {
	uRL                               string
	issuer                            string
	authorizationEndpoint             string
	tokenEndpoint                     string
	userInfoEndpoint                  string
	jWKsURI                           string
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

// Issuer is getter of issuer.
func (config *OIDCConfig) Issuer() string {
	return config.issuer
}

// AuthorizationEndpoint is getter of Authorization Endpoint.
func (config *OIDCConfig) AuthorizationEndpoint() string {
	return config.authorizationEndpoint
}

// TokenEndpoint is getter of Token Endpoint.
func (config *OIDCConfig) TokenEndpoint() string {
	return config.tokenEndpoint
}

// UserInfoEndpoint is getter of UserInfo Endpoint.
func (config *OIDCConfig) UserInfoEndpoint() string {
	return config.userInfoEndpoint
}

// JWKsURI is getter of JWKs URI.
func (config *OIDCConfig) JWKsURI() string {
	return config.jWKsURI
}

// TokenEndpointAuthMethodsSupported is getter of Token Endpoint Authentication Methods Supported.
func (config *OIDCConfig) TokenEndpointAuthMethodsSupported() []string {
	return config.tokenEndpointAuthMethodsSupported
}

// ResponseTypesSupported is getter of response types supported.
func (config *OIDCConfig) ResponseTypesSupported() []string {
	return config.responseTypesSupported
}

// ScopesSupported is getter of scopes supported.
func (config *OIDCConfig) ScopesSupported() []string {
	return config.scopesSupported
}

// IDTokenSigningAlgValuesSupported is getter of id token signing alg values supporte.
func (config *OIDCConfig) IDTokenSigningAlgValuesSupported() []string {
	return config.iDTokenSigningAlgValuesSupported
}

// Request is method to request OpenID Configuration Endpoint.
func (config *OIDCConfig) Request() error {
	configRequest, err := http.NewRequest(
		"GET",
		config.uRL,
		nil,
	)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(configRequest)
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
		return err
	}

	var configResponse Response
	err = json.NewDecoder(response.Body).Decode(&configResponse)
	if err != nil {
		return err
	}

	if configResponse.Issuer != "" {
		config.issuer = configResponse.Issuer
	}
	if configResponse.AuthorizationEndpoint != "" {
		config.authorizationEndpoint = configResponse.AuthorizationEndpoint
	}
	if configResponse.TokenEndpoint != "" {
		config.tokenEndpoint = configResponse.TokenEndpoint
	}
	if configResponse.UserInfoEndpoint != "" {
		config.userInfoEndpoint = configResponse.UserInfoEndpoint
	}
	if configResponse.JWKsURI != "" {
		config.jWKsURI = configResponse.JWKsURI
	}
	if len(configResponse.TokenEndpointAuthMethodsSupported) > 0 {
		config.tokenEndpointAuthMethodsSupported = configResponse.TokenEndpointAuthMethodsSupported
	}
	if len(configResponse.ResponseTypesSupported) > 0 {
		config.responseTypesSupported = configResponse.ResponseTypesSupported
	}
	if len(configResponse.ScopesSupported) > 0 {
		config.scopesSupported = configResponse.ScopesSupported
	}
	if len(configResponse.IDTokenSigningAlgValuesSupported) > 0 {
		config.iDTokenSigningAlgValuesSupported = configResponse.IDTokenSigningAlgValuesSupported
	}

	return nil
}
