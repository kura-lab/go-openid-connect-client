package userinfo

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"gopkg.in/h2non/gock.v1"
)

func TestNewUserInfoSuccesses(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		MatchHeader("Authorization", "^Bearer ACCESS_TOKEN$").
		Post("/userinfo").
		Reply(200).
		JSON(map[string]interface{}{
			"sub":                   "0123456789",
			"name":                  "Jane Doe",
			"given_name":            "Jane",
			"family_name":           "Doe",
			"middle_name":           "Grace",
			"nick_name":             "J.D.",
			"preferred_username":    "j.doe",
			"profile":               "https://example.com/janedoe",
			"picture":               "https://example.com/janedoe/me.jpg",
			"website":               "https://blog.example.com/janedoe",
			"email":                 "janedoe@example.com",
			"email_verified":        true,
			"gender":                "female",
			"birthdate":             "1986-01-01",
			"zoneinfo":              "Asia/Tokyo",
			"locale":                "ja-JP",
			"phone_number":          "+81 (09) 1234-5678",
			"phone_number_verified": true,
			"address": map[string]string{
				"formatted":      "Kandamyoujin-street,\r\nChiyoda-ku,\r\nTokyo, Japan,\r\n1010021",
				"street_address": "Kandamyoujin-street",
				"locality":       "Chiyoda-ku",
				"region":         "Tokyo",
				"postal_code":    "1010021",
				"county":         "JP",
			},
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.UserInfoEndpoint("https://op.example.com/userinfo"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	userInfoPointer := NewUserInfo(
		oIDCConfigResponse,
		"ACCESS_TOKEN",
	)

	err := userInfoPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := userInfoPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	if response.Subject != "0123456789" {
		t.Errorf("invalid sub. expected: 0123456789, actual: %v", response.Subject)
	}

	if response.Name != "Jane Doe" {
		t.Errorf("invalid name. expected: Jane Doe, actual: %v", response.Name)
	}

	if response.GivenName != "Jane" {
		t.Errorf("invalid give name. expected: Jane, actual: %v", response.GivenName)
	}

	if response.FamilyName != "Doe" {
		t.Errorf("invalid family name. expected: Doe, actual: %v", response.FamilyName)
	}

	if response.MiddleName != "Grace" {
		t.Errorf("invalid middle name. expected: Grace, actual: %v", response.MiddleName)
	}

	if response.NickName != "J.D." {
		t.Errorf("invalid nick name. expected: J.D., actual: %v", response.NickName)
	}

	if response.PreferredUsername != "j.doe" {
		t.Errorf("invalid preferred username. expected: j.doe, actual: %v", response.PreferredUsername)
	}

	if response.Profile != "https://example.com/janedoe" {
		t.Errorf("invalid profile. expected: https://example.com/janedoe, actual: %v", response.Profile)
	}

	if response.Picture != "https://example.com/janedoe/me.jpg" {
		t.Errorf("invalid picture. expected: https://example.com/janedoe/me.jpg, actual: %v", response.Picture)
	}

	if response.Website != "https://blog.example.com/janedoe" {
		t.Errorf("invalid website. expected: https://blog.example.com/janedoe, actual: %v", response.Website)
	}

	if response.Email != "janedoe@example.com" {
		t.Errorf("invalid email. expected: janedoe@example.com, actual: %v", response.Email)
	}

	if response.EmailVerified != true {
		t.Errorf("invalid email verified. expected: true, actual: %v", response.EmailVerified)
	}

	if response.Gender != "female" {
		t.Errorf("invalid gender. expected: female, actual: %v", response.Gender)
	}

	if response.Birthdate != "1986-01-01" {
		t.Errorf("invalid birthdate. expected: 1986-01-01, actual: %v", response.Birthdate)
	}

	if response.Zoneinfo != "Asia/Tokyo" {
		t.Errorf("invalid zoneinfo. expected: Asia/Tokyo, actual: %v", response.Zoneinfo)
	}

	if response.Locale != "ja-JP" {
		t.Errorf("invalid locale. expected: ja-JP, actual: %v", response.Locale)
	}

	if response.PhoneNumber != "+81 (09) 1234-5678" {
		t.Errorf("invalid phone number. expected: +81 (09) 1234-5678, actual: %v", response.PhoneNumber)
	}

	if response.PhoneNumberVerified != true {
		t.Errorf("invalid phone number verified. expected: true, actual: %v", response.PhoneNumberVerified)
	}

	if response.Address.Formatted != "Kandamyoujin-street,\r\nChiyoda-ku,\r\nTokyo, Japan,\r\n1010021" {
		t.Errorf("invalid address/formatted. expected: Kandamyoujin-street, Chiyoda-ku, Tokyo Japan, 1010021, actual: %v", response.Address.Formatted)
	}

	if response.Address.StreetAddress != "Kandamyoujin-street" {
		t.Errorf("invalid address/street address. expected: Kandamyoujin-street, actual: %v", response.Address.StreetAddress)
	}

	if response.Address.Locality != "Chiyoda-ku" {
		t.Errorf("invalid address/locality. expected: Chiyoda-ku, actual: %v", response.Address.Locality)
	}

	if response.Address.Region != "Tokyo" {
		t.Errorf("invalid address/region. expected: Tokyo, actual: %v", response.Address.Locality)
	}

	if response.Address.PostalCode != "1010021" {
		t.Errorf("invalid address/postal code. expected: 1010021, actual: %v", response.Address.PostalCode)
	}

	if response.Address.Country != "JP" {
		t.Errorf("invalid address/county. expected: JP, actual: %v", response.Address.Country)
	}

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		MatchHeader("Authorization", "^Bearer ACCESS_TOKEN$").
		Post("/userinfo").
		Reply(401).
		SetHeader("WWW-Authenticate",
			"realm=\"example\"",
		).
		JSON(map[string]interface{}{})

	oIDCConfigPointer = oidcconfig.NewOIDCConfig(
		oidcconfig.UserInfoEndpoint("https://op.example.com/userinfo"),
	)

	oIDCConfigResponse = oIDCConfigPointer.Response()

	userInfoPointer = NewUserInfo(
		oIDCConfigResponse,
		"ACCESS_TOKEN",
	)

	err = userInfoPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response = userInfoPointer.Response()

	if response.Status != "401 Unauthorized" {
		t.Errorf("invalid http status. expected: 401 Unauthorized, actual: %v", response.Status)
	}

	if response.StatusCode != 401 {
		t.Errorf("invalid http status code. expected: 401 Unauthorized, actual: %v", response.StatusCode)
	}

	if response.WWWAuthenticate.Realm != "" {
		t.Errorf("invalid realm. expected: (empty), actual: %v", response.WWWAuthenticate.Realm)
	}

	if response.WWWAuthenticate.Scope != "" {
		t.Errorf("invalid scope. expected: (empty), actual: %v", response.WWWAuthenticate.Scope)
	}

	if response.WWWAuthenticate.Error != "" {
		t.Errorf("invalid error. expected: (empty), actual: %v", response.WWWAuthenticate.Error)
	}

	if response.WWWAuthenticate.ErrorDescription != "" {
		t.Errorf("invalid error description. expected: (empty), actual: %v", response.WWWAuthenticate.ErrorDescription)
	}
}

func TestNewUserInfoFailures(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		MatchHeader("Authorization", "^Bearer ACCESS_TOKEN$").
		Post("/userinfo").
		Reply(401).
		SetHeader("WWW-Authenticate",
			"Bearer realm=\"example\",\r\n"+
				"scope=\"openid profile email\",\r\n"+
				"error=\"invalid_token\",\r\n"+
				"error_description=\"The access token expired\"",
		).
		JSON(map[string]interface{}{})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.UserInfoEndpoint("https://op.example.com/userinfo"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	userInfoPointer := NewUserInfo(
		oIDCConfigResponse,
		"ACCESS_TOKEN",
	)

	err := userInfoPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := userInfoPointer.Response()

	if response.Status != "401 Unauthorized" {
		t.Errorf("invalid http status. expected: 401 Unauthorized, actual: %v", response.Status)
	}

	if response.StatusCode != 401 {
		t.Errorf("invalid http status code. expected: 401 Unauthorized, actual: %v", response.StatusCode)
	}

	if response.WWWAuthenticate.Realm != "example" {
		t.Errorf("invalid realm. expected: example, actual: %v", response.WWWAuthenticate.Realm)
	}

	if response.WWWAuthenticate.Scope != "openid profile email" {
		t.Errorf("invalid scope. expected: openid profile email, actual: %v", response.WWWAuthenticate.Scope)
	}

	if response.WWWAuthenticate.Error != "invalid_token" {
		t.Errorf("invalid error. expected: invalid_token, actual: %v", response.WWWAuthenticate.Error)
	}

	if response.WWWAuthenticate.ErrorDescription != "The access token expired" {
		t.Errorf("invalid error description. expected: The access token expired, actual: %v", response.WWWAuthenticate.ErrorDescription)
	}

	gock.New("https://op.example.com").
		MatchHeader("Content-Type", "^application/x-www-form-urlencoded$").
		MatchHeader("Authorization", "^Bearer ACCESS_TOKEN$").
		Post("/userinfo").
		Reply(200).
		BodyString("INVALID_BODY")

	oIDCConfigPointer = oidcconfig.NewOIDCConfig(
		oidcconfig.UserInfoEndpoint("https://op.example.com/userinfo"),
	)

	oIDCConfigResponse = oIDCConfigPointer.Response()

	userInfoPointer = NewUserInfo(
		oIDCConfigResponse,
		"ACCESS_TOKEN",
	)

	err = userInfoPointer.Request()

	if err == nil {
		t.Fatalf("expect budy parsing error.")
	}
}

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
