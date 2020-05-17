package callback

import (
	"net/url"
	"testing"
)

func TestCallbackByQueryStringSuccesses(t *testing.T) {

	callbackPointer := NewCallback(
		QueryString("code=abc&state=xyz"),
	)
	if err := callbackPointer.Parse(); err != nil {
		t.Errorf("parse error. error: %#v", err)
	}
	if pass, err := callbackPointer.VerifyState("xyz"); err != nil {
		t.Errorf("verify state error. error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}
	response := callbackPointer.Response()
	if response.State != "xyz" {
		t.Errorf("state error. expected: xyz, actual: %v", response.State)
	}
	if response.AuthorizationCode != "abc" {
		t.Errorf("authorization code error. expected: xyz, actual: %v", response.AuthorizationCode)
	}

	callbackPointer = NewCallback(
		QueryString("state=xyz&error=login_required"),
	)
	if err := callbackPointer.Parse(); err != nil {
		t.Errorf("parse error. error: %#v", err)
	}
	if pass, err := callbackPointer.VerifyState("xyz"); err != nil {
		t.Errorf("verify state error. error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}
	response = callbackPointer.Response()
	if response.State != "xyz" {
		t.Errorf("state error. expected: xyz, actual: %v", response.State)
	}
	if response.Error != "login_required" {
		t.Errorf("callback error. expected: login_required, actual: %v", response.Error)
	}

	callbackPointer = NewCallback(
		QueryString("state=xyz&error=login_required&error_description=display%20a%20user%20interface&error_uri=https%3A%2F%2Fop.example.com%2Ferror"),
	)
	if err := callbackPointer.Parse(); err != nil {
		t.Errorf("parse error. error: %#v", err)
	}
	if pass, err := callbackPointer.VerifyState("xyz"); err != nil {
		t.Errorf("verify state error. error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}
	response = callbackPointer.Response()
	if response.State != "xyz" {
		t.Errorf("state error. expected: xyz, actual: %v", response.State)
	}
	if response.Error != "login_required" {
		t.Errorf("callback error. expected: login_required, actual: %v", response.Error)
	}
	if response.ErrorDescription != "display a user interface" {
		t.Errorf("callback error description. expected: display a user interface, actual: %v", response.ErrorDescription)
	}
	if response.ErrorURI != "https://op.example.com/error" {
		t.Errorf("callback error uri. expected: https://op.example.com/error, actual: %v", response.ErrorURI)
	}

}

func TestCallbackByURISuccesses(t *testing.T) {

	u, _ := url.Parse("http://rp.example.com/callback?code=abc&state=xyz")
	callbackPointer := NewCallback(
		URI(u),
	)
	if err := callbackPointer.Parse(); err != nil {
		t.Errorf("parse error. error: %#v", err)
	}
	if pass, err := callbackPointer.VerifyState("xyz"); err != nil {
		t.Errorf("verify state error. error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}
	response := callbackPointer.Response()
	if response.State != "xyz" {
		t.Errorf("state error. expected: xyz, actual: %v", response.State)
	}
	if response.AuthorizationCode != "abc" {
		t.Errorf("authorization code error. expected: abc, actual: %v", response.AuthorizationCode)
	}

	u, _ = url.Parse("http://rp.example.com/callback?state=xyz&error=login_required&error_description=display%20a%20user%20interface&error_uri=https%3A%2F%2Fop.example.com%2Ferror")
	callbackPointer = NewCallback(URI(u))
	if err := callbackPointer.Parse(); err != nil {
		t.Errorf("parse error. error: %#v", err)
	}
	if pass, err := callbackPointer.VerifyState("xyz"); err != nil {
		t.Errorf("verify state error. error: %#v", err)
		if !pass.VerificationResult {
			t.Errorf("state pass error. expected: true, pass: %#v", pass)
		}
	}
	response = callbackPointer.Response()
	if response.State != "xyz" {
		t.Errorf("state error. expected: xyz, actual: %v", response.State)
	}
	if response.Error != "login_required" {
		t.Errorf("callback error. expected: login_required, actual: %v", response.Error)
	}
	if response.ErrorDescription != "display a user interface" {
		t.Errorf("callback error description. expected: display a user interface, actual: %v", response.ErrorDescription)
	}
	if response.ErrorURI != "https://op.example.com/error" {
		t.Errorf("callback error uri. expected: https://op.example.com/error, actual: %v", response.ErrorURI)
	}
}
