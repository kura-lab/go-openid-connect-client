package userinfo

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/header"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for UserInfo Response.
type Response struct {
	Status              string
	StatusCode          int
	Body                string
	WWWAuthenticate     header.WWWAuthenticate
	Subject             string `json:"sub"`
	Name                string `json:"name"`
	GivenName           string `json:"given_name"`
	FamilyName          string `json:"family_name"`
	MiddleName          string `json:"middle_name"`
	NickName            string `json:"nick_name"`
	PreferredUsername   string `json:"preferred_username"`
	Profile             string `json:"profile"`
	Picture             string `json:"picture"`
	Website             string `json:"website"`
	Email               string `json:"email"`
	EmailVerified       bool   `json:"email_verified"`
	Gender              string `json:"gender"`
	Birthdate           string `json:"birthdate"`
	Zoneinfo            string `json:"zoneinfo"`
	Locale              string `json:"locale"`
	PhoneNumber         string `json:"phone_number"`
	PhoneNumberVerified bool   `json:"phone_number_verified"`
	Address             struct {
		Formatted     string `json:"formatted"`
		StreetAddress string `json:"street_address"`
		Locality      string `json:"locality"`
		Region        string `json:"region"`
		PostalCode    string `json:"postal_code"`
		Country       string `json:"county"`
	} `json:"address"`
	UpdatedAt int `json:"updated_at"`
}

// UserInfo is struct to request UserInfo Endpoint.
type UserInfo struct {
	oIDCConfig oidcconfig.Response
	response   Response
	// required
	accessToken string
}

// NewUserInfo is UserInfo constructor function.
func NewUserInfo(oIDCConfig oidcconfig.Response, accessToken string) *UserInfo {
	userInfo := new(UserInfo)
	userInfo.oIDCConfig = oIDCConfig
	userInfo.accessToken = accessToken

	return userInfo
}

// Request is method to request UserInfo Endpoint.
func (userInfo *UserInfo) Request() (nerr error) {

	userInfoRequest, err := http.NewRequest(
		"POST",
		userInfo.oIDCConfig.UserInfoEndpoint,
		nil,
	)
	if err != nil {
		nerr = err
		return
	}

	userInfoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	userInfoRequest.Header.Set("Authorization", "Bearer "+userInfo.accessToken)
	response, err := http.DefaultClient.Do(userInfoRequest)
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

	buf := bytes.NewBuffer(nil)
	body := bytes.NewBuffer(nil)

	w := io.MultiWriter(buf, body)
	io.Copy(w, response.Body)

	var userInfoResponse Response
	userInfo.response = userInfoResponse
	userInfo.response.Status = response.Status
	userInfo.response.StatusCode = response.StatusCode

	rawBody, err := ioutil.ReadAll(buf)
	if err != nil {
		nerr = err
		return
	}
	userInfo.response.Body = string(rawBody)

	err = json.NewDecoder(body).Decode(&userInfo.response)
	if err != nil {
		nerr = err
		return
	}

	if response.Header.Get("WWW-Authenticate") != "" {
		parsed := header.ParseWWWAuthenticateHeader(response.Header.Get("WWW-Authenticate"))
		if parsed["realm"] != "" {
			userInfo.response.WWWAuthenticate.Realm = parsed["realm"]
		}
		if parsed["scope"] != "" {
			userInfo.response.WWWAuthenticate.Scope = parsed["scope"]
		}
		if parsed["error"] != "" {
			userInfo.response.WWWAuthenticate.Error = parsed["error"]
		}
		if parsed["error_description"] != "" {
			userInfo.response.WWWAuthenticate.ErrorDescription = parsed["error_description"]
		}
	}

	return
}

// Response is getter method of Response struct
func (userInfo *UserInfo) Response() Response {
	return userInfo.response
}
