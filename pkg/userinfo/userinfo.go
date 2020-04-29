package userinfo

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for UserInfo Response.
type Response struct {
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
	PhoneNumberVerified string `json:"phone_number_verified"`
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
	oidcconfig *oidcconfig.OIDCConfig
	// required
	accessToken string
}

// NewUserInfo is UserInfo constructor function.
func NewUserInfo(oidcconfig *oidcconfig.OIDCConfig, accessToken string, options ...Option) *UserInfo {
	userInfo := new(UserInfo)
	userInfo.oidcconfig = oidcconfig
	userInfo.accessToken = accessToken

	for _, option := range options {
		option(userInfo)
	}
	return userInfo
}

// Option is functional option for UserInfo struct initialization.
type Option func(*UserInfo) error

// Request is method to request UserInfo Endpoint.
func (userInfo *UserInfo) Request() (Response, error) {

	userInfoRequest, err := http.NewRequest(
		"POST",
		userInfo.oidcconfig.UserInfoEndpoint(),
		nil,
	)
	if err != nil {
		return Response{}, err
	}

	userInfoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	userInfoRequest.Header.Set("Authorization", "Bearer "+userInfo.accessToken)
	response, err := http.DefaultClient.Do(userInfoRequest)
	defer func() {
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
	}()

	if err != nil {
		return Response{}, err
	}

	var userInfoResponse Response
	err = json.NewDecoder(response.Body).Decode(&userInfoResponse)
	if err != nil {
		return Response{}, err
	}

	return userInfoResponse, nil
}
