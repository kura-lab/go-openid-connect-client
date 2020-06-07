package client

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/header"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Configuration is struct to request Client Configuration Endpoint.
type Configuration struct {
	oIDCConfig              oidcconfig.Response
	clientID                string
	registrationAccessToken string
	response                Response
}

// NewConfiguration is Configuration constructor function.
func NewConfiguration(oIDCConfig oidcconfig.Response, clientID string, options ...ConfigurationOption) *Configuration {
	configuration := new(Configuration)
	configuration.oIDCConfig = oIDCConfig

	configuration.clientID = clientID

	for _, option := range options {
		option(configuration)
	}
	return configuration
}

// ConfigurationOption is functional option for Registration struct initialization.
type ConfigurationOption func(*Configuration) error

// RegistrationAccessToken is functional option to add Registration Access Token in Authorization Bearer Header.
func RegistrationAccessToken(registrationAccessToken string) ConfigurationOption {
	return func(configuration *Configuration) error {
		configuration.registrationAccessToken = registrationAccessToken
		return nil
	}
}

// Request is method to request Configuration Endpoint.
func (configuration *Configuration) Request() (nerr error) {

	configurationRequest, err := http.NewRequest(
		"GET",
		configuration.oIDCConfig.RegistrationEndpoint,
		nil,
	)
	if err != nil {
		nerr = err
		return
	}

	if configuration.registrationAccessToken != "" {
		configurationRequest.Header.Set("Authorization", "Bearer "+configuration.registrationAccessToken)
	}

	params := configurationRequest.URL.Query()
	params.Add("client_id", configuration.clientID)
	configurationRequest.URL.RawQuery = params.Encode()

	response, err := http.DefaultClient.Do(configurationRequest)
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

	var configurationResponse Response
	err = json.NewDecoder(response.Body).Decode(&configurationResponse)
	if err != nil {
		nerr = err
		return
	}
	configurationResponse.Status = response.Status
	configurationResponse.StatusCode = response.StatusCode
	configuration.response = configurationResponse

	if response.Header.Get("WWW-Authenticate") != "" {
		parsed := header.ParseWWWAuthenticateHeader(response.Header.Get("WWW-Authenticate"))
		if parsed["realm"] != "" {
			configuration.response.WWWAuthenticate.Realm = parsed["realm"]
		}
		if parsed["scope"] != "" {
			configuration.response.WWWAuthenticate.Scope = parsed["scope"]
		}
		if parsed["error"] != "" {
			configuration.response.WWWAuthenticate.Error = parsed["error"]
		}
		if parsed["error_description"] != "" {
			configuration.response.WWWAuthenticate.ErrorDescription = parsed["error_description"]
		}
	}

	return
}

// Response is getter method of Response struct.
func (configuration *Configuration) Response() Response {
	return configuration.response
}
