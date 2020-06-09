package callback

import (
	"errors"
	"net/url"

	"github.com/kura-lab/go-openid-connect-client/pkg/state"
)

// Response is structi to get error parameters.
type Response struct {
	State             string
	AuthorizationCode string
	AccessToken       string
	IDToken           string
	Error             string
	ErrorDescription  string
	ErrorURI          string
}

// Callback is struct to parse callback query and verify state parameter.
type Callback struct {
	queryString string
	uRI         *url.URL
	form        url.Values
	response    Response
}

// NewCallback is Callback constructor function.
func NewCallback(options ...Option) *Callback {
	callback := new(Callback)

	for _, option := range options {
		option(callback)
	}
	return callback
}

// Option is functional option for Callback struct initialization.
type Option func(*Callback) error

// QueryString is functional option to add callback Query String.
func QueryString(queryString string) Option {
	return func(callback *Callback) error {
		callback.queryString = queryString
		return nil
	}
}

// URI is functional option to add callback url.URL.
func URI(uRI *url.URL) Option {
	return func(callback *Callback) error {
		callback.uRI = uRI
		return nil
	}
}

// Form is functional option to add callback post form.
func Form(form url.Values) Option {
	return func(callback *Callback) error {
		callback.form = form
		return nil
	}
}

// Parse is method to parse callback query or body parameters.
func (callback *Callback) Parse() error {

	var values url.Values
	if callback.queryString != "" {
		q, err := url.ParseQuery(callback.queryString)
		if err != nil {
			return errors.New("failed to parse callback uri")
		}
		values = q
	} else if callback.uRI != nil {
		values = callback.uRI.Query()
	} else if callback.form != nil {
		values = callback.form
	} else {
		return errors.New("insufficient parameters. set callback query string or callback uri with functional option")
	}

	if state, ok := values["state"]; ok {
		callback.response.State = state[0]
	}

	if authorizationCode, ok := values["code"]; ok {
		callback.response.AuthorizationCode = authorizationCode[0]
	}

	if accessToken, ok := values["access_token"]; ok {
		callback.response.AccessToken = accessToken[0]
	}

	if iDToken, ok := values["id_token"]; ok {
		callback.response.IDToken = iDToken[0]
	}

	if callbackError, ok := values["error"]; ok {
		callback.response.Error = callbackError[0]
	}

	if errorDescription, ok := values["error_description"]; ok {
		callback.response.ErrorDescription = errorDescription[0]
	}

	if errorURI, ok := values["error_uri"]; ok {
		callback.response.ErrorURI = errorURI[0]
	}

	return nil
}

// VerifyState is method to verify whether requested state is equal to state in callback URI.
func (callback *Callback) VerifyState(requestedState string) (state.Pass, error) {

	statePointer := state.NewState(
		requestedState,
		state.CallbackState(callback.response.State),
	)
	return statePointer.Verify()
}

// Response is method to get Response struct.
func (callback *Callback) Response() Response {
	return callback.response
}
