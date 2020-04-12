package oidcconfig

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type OIDCConfigResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKsURI               string `json:"jwks_uri"`
}

type OIDCConfig struct {
	uRL                   string
	issuer                string
	authorizationEndpoint string
	tokenEndpoint         string
	userInfoEndpoint      string
	jWKsURI               string
}

func New(uRL string) *OIDCConfig {
	config := new(OIDCConfig)
	config.uRL = uRL
	return config
}

func NewOIDCConfig(options ...Option) *OIDCConfig {
	config := new(OIDCConfig)
	for _, option := range options {
		option(config)
	}
	return config
}

type Option func(*OIDCConfig) error

func Issuer(issuer string) Option {
	return func(config *OIDCConfig) error {
		config.issuer = issuer
		return nil
	}
}

func AuthorizationEndpoint(authorizationEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.authorizationEndpoint = authorizationEndpoint
		return nil
	}
}

func TokenEndpoint(tokenEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.tokenEndpoint = tokenEndpoint
		return nil
	}
}

func UserInfoEndpoint(userInfoEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.userInfoEndpoint = userInfoEndpoint
		return nil
	}
}

func JWKsURI(jWKsURI string) Option {
	return func(config *OIDCConfig) error {
		config.jWKsURI = jWKsURI
		return nil
	}
}

func (config *OIDCConfig) Issuer() string {
	return config.issuer
}

func (config *OIDCConfig) AuthorizationEndpoint() string {
	return config.authorizationEndpoint
}

func (config *OIDCConfig) TokenEndpoint() string {
	return config.tokenEndpoint
}

func (config *OIDCConfig) UserInfoEndpoint() string {
	return config.userInfoEndpoint
}

func (config *OIDCConfig) JWKsURI() string {
	return config.jWKsURI
}

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

	var configResponse OIDCConfigResponse
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

	return nil
}
