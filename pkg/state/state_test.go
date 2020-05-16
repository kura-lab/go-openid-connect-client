package state

import (
	"net/url"
	"testing"
)

func TestStateVerifySuccesses(t *testing.T) {

	state := NewState("xyz", CallbackState("xyz"))
	if pass, err := state.Verify(); err != nil {
		t.Errorf("state error. expected: true, error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}

	state = NewState("xyz", CallbackQueryString("code=abc&state=xyz"))
	if pass, err := state.Verify(); err != nil {
		t.Errorf("state error. expected: true, error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}

	u, _ := url.Parse("http://rp.example.com/callback?code=abc&state=xyz")
	state = NewState("xyz", CallbackURI(u))
	if pass, err := state.Verify(); err != nil {
		t.Errorf("state error. expected: true, error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}
}

func TestStateVerifyFailure(t *testing.T) {

	state := NewState("xyz", CallbackState("abc"))
	pass, err := state.Verify()
	if err == nil {
		t.Errorf("state error. expected: false, error: %#v", err)
	}
	if pass.VerificationResult {
		t.Errorf("state pass error. expected: false, pass: %#v", pass)
	}

	state = NewState("xyz", CallbackQueryString("code=abc&state=abc"))
	pass, err = state.Verify()
	if err == nil {
		t.Errorf("state error. expected: false, error: %#v", err)
	}
	if pass.VerificationResult {
		t.Errorf("state pass error. expected: false, pass: %#v", pass)
	}

	u, _ := url.Parse("http://rp.example.com/callback?code=abc&state=abc")
	state = NewState("xyz", CallbackURI(u))
	pass, err = state.Verify()
	if err == nil {
		t.Errorf("state error. expected: false, error: %#v", err)
	}
	if pass.VerificationResult {
		t.Errorf("state pass error. expected: false, pass: %#v", pass)
	}
}
