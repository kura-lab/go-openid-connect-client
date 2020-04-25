package authorization

import (
	"testing"
)

func TestValidateResponseTypeSucceeds(t *testing.T) {

	data := [][][]string{
		{[]string{"code"}, []string{"code"}},
		{[]string{"token"}, []string{"code", "token"}},
		{[]string{"code", "token"}, []string{"code", "code token"}},
		{[]string{"code", "id_token", "token"}, []string{"code", "code token", "code token id_token"}},
	}

	for _, value := range data {
		if !validateResponseType(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t", true, false)
		}
	}
}

func TestValidateResponseTypeFailds(t *testing.T) {

	data := [][][]string{
		{[]string{"token"}, []string{"code"}},
		{[]string{"token"}, []string{"code", "code token"}},
		{[]string{"code id_token"}, []string{"code", "code token", "token id_token"}},
	}

	for _, value := range data {
		if validateResponseType(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t", false, true)
		}
	}
}

func TestValidateScopeSucceeds(t *testing.T) {

	data := [][][]string{
		{[]string{"openid"}, []string{"openid"}},
		{[]string{"openid"}, []string{"email", "openid"}},
		{[]string{"openid", "email"}, []string{"email", "openid"}},
		{[]string{"openid", "email"}, []string{"openid", "email", "profile"}},
	}

	for _, value := range data {
		if !validateScope(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t, input:%v", true, false, value[0])
		}
	}
}

func TestValidateScopeFailds(t *testing.T) {

	data := [][][]string{
		{[]string{"email"}, []string{"openid"}},
		{[]string{"email"}, []string{"openid", "profile", "address", "phone"}},
	}

	for _, value := range data {
		if validateScope(value[0], value[1]) {
			t.Errorf("error. expected:%t, actual:%t", false, true)
		}
	}
}
