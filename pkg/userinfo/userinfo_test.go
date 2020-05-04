package userinfo

import (
	"testing"
)

func TestParseWWWAuthenticateHeader(t *testing.T) {

	data := [][]interface{}{
		{
			"Bearer realm=example",
			map[string]string{"realm": "example"},
		},
		{
			"Bearer realm=\"example\",\r\nerror=\"invalid_token\"",
			map[string]string{"realm": "example", "error": "invalid_token"},
		},
		{
			"Bearer realm=\"example\",\r\nscope=\"openid profile email\",\r\nerror=\"invalid_token\",\r\nerror_description=\"The access token expired\"",
			map[string]string{"realm": "example", "scope": "openid profile email", "error": "invalid_token", "error_description": "The access token expired"},
		},
		{
			"Bearer realm=\"example\",\r\nerror=\"invalid_token\",\r\nerror_description=\"The access token expired\"",
			map[string]string{"realm": "example", "error": "invalid_token", "error_description": "The access token expired"},
		},
		{
			"Bearer realm=\"example\",\rerror=\"invalid_token\",\rerror_description=\"The access token expired\"",
			map[string]string{"realm": "example", "error": "invalid_token", "error_description": "The access token expired"},
		},
		{
			"Bearer realm=\"example\",\nerror=\"invalid_token\",\nerror_description=\"The access token expired\"",
			map[string]string{"realm": "example", "error": "invalid_token", "error_description": "The access token expired"},
		},
	}

	for _, value := range data {
		parsed := parseWWWAuthenticateHeader(string(value[0].(string)))

		if len(value[1].(map[string]string)) != len(parsed) {
			t.Errorf("not match length of parsed value. expected:%v, actual:%v", value[1], parsed)
		}

		for k, v := range value[1].(map[string]string) {
			if v != parsed[k] {
				t.Errorf("error. key:%s, expected:%s, actual:%s", k, v, parsed[k])
			}
		}
	}
}
