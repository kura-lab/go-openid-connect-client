package userinfo

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for UserInfo Response.
type Response struct {
	Status          string
	StatusCode      int
	WWWAuthenticate struct {
		Realm            string
		Scope            string
		Error            string
		ErrorDescription string
	}
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
	response   Response
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
func (userInfo *UserInfo) Request() error {

	userInfoRequest, err := http.NewRequest(
		"POST",
		userInfo.oidcconfig.UserInfoEndpoint(),
		nil,
	)
	if err != nil {
		return err
	}

	userInfoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	userInfoRequest.Header.Set("Authorization", "Bearer "+userInfo.accessToken)
	response, err := http.DefaultClient.Do(userInfoRequest)
	defer func() {
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
	}()

	if err != nil {
		return err
	}

	var userInfoResponse Response
	err = json.NewDecoder(response.Body).Decode(&userInfoResponse)
	if err != nil {
		return err
	}
	userInfoResponse.Status = response.Status
	userInfoResponse.StatusCode = response.StatusCode
	userInfo.response = userInfoResponse

	if response.Header.Get("WWW-Authenticate") != "" {
		parsed := parseWWWAuthenticateHeader(response.Header.Get("WWW-Authenticate"))
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

	return nil
}

// Response is getter method of Response struct
func (userInfo *UserInfo) Response() Response {
	return userInfo.response
}

func parseWWWAuthenticateHeader(header string) map[string]string {

	rep := regexp.MustCompile(`\ABearer `)
	if !rep.MatchString(header) {
		return map[string]string{}
	}

	header = rep.ReplaceAllString(header, "")

	header = strings.NewReplacer(
		"\r\n", "",
		"\r", "",
		"\n", "",
	).Replace(header)

	attributes := strings.Split(header, ",")

	parsed := map[string]string{}
	for _, attribute := range attributes {
		splited := strings.Split(strings.TrimSpace(attribute), "=")
		parsed[splited[0]] = strings.Trim(splited[1], "\"")
	}

	return parsed
}
