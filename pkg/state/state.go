package state

import (
	"errors"
	"net/url"
)

// State is struct to verify state parameters.
type State struct {
	requested           string
	callback            string
	callbackQueryString string
	callbackURI         *url.URL
}

// Pass is struct of state verification result.
type Pass struct {
	VerificationResult bool
}

// NewState is State constructor function.
func NewState(requested string, options ...Option) *State {
	state := new(State)
	state.requested = requested

	for _, option := range options {
		option(state)
	}
	return state
}

// Option is functional option for State struct initialization.
type Option func(*State) error

// CallbackState is functional option to add callback "state" parameter.
func CallbackState(callback string) Option {
	return func(state *State) error {
		state.callback = callback
		return nil
	}
}

// CallbackQueryString is functional option to add callback Query String included "state" parameter.
func CallbackQueryString(callbackQueryString string) Option {
	return func(state *State) error {
		state.callbackQueryString = callbackQueryString
		return nil
	}
}

// CallbackURI is functional option to add callback url.URL included "state" parameter.
func CallbackURI(callbackURI *url.URL) Option {
	return func(state *State) error {
		state.callbackURI = callbackURI
		return nil
	}
}

// Verify is method to verify that whether or not requested state is equal to state in callback URI.
func (state *State) Verify() (Pass, error) {

	if state.callback != "" {
		if state.requested == state.callback {
			return Pass{VerificationResult: true}, nil
		}
		return Pass{}, errors.New("callback state is not equal to value of requested state")
	}

	if state.callbackQueryString != "" || state.callbackURI != nil {
		var query url.Values
		if state.callbackQueryString != "" {
			q, err := url.ParseQuery(state.callbackQueryString)
			if err != nil {
				return Pass{}, errors.New("failed to parse callback uri")
			}
			query = q
		} else {
			query = state.callbackURI.Query()
		}
		callback, ok := query["state"]
		if ok {
			if state.requested == callback[0] {
				return Pass{VerificationResult: true}, nil
			}
			return Pass{}, errors.New("state in callback uri is not equal to value of requested state")
		}
		return Pass{}, errors.New("not include state in query of callback uri")
	}

	return Pass{}, errors.New("insufficient state. set callack state or callback uri with functional option")
}
