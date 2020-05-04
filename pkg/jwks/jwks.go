package jwks

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

// Response is struct for JWKs URI Response.
type Response struct {
	Status     string
	StatusCode int
	KeySets    []struct {
		KeyID       string `json:"kid"`
		KeyType     string `json:"kty"`
		Algorithm   string `json:"alg"`
		Use         string `json:"use"`
		Modulus     string `json:"n"`
		Exponent    string `json:"e"`
		CURVE       string `json:"crv"`
		XCoordinate string `json:"x"`
		YCoordinate string `json:"y"`
	} `json:"keys"`
}

// JWKs is struct to request JWKs URI.
type JWKs struct {
	oIDCConfig oidcconfig.Response
	response   Response
}

// NewJWKs is JWKs URI constructor function.
func NewJWKs(oIDCConfig oidcconfig.Response) *JWKs {
	jWKs := new(JWKs)
	jWKs.oIDCConfig = oIDCConfig

	return jWKs
}

// Request is method to request JWKs URI.
func (jWKs *JWKs) Request() (nerr error) {
	response, err := http.Get(jWKs.oIDCConfig.JWKsURI)
	if err != nil {
		nerr = err
		return
	}
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

	var jWKsResponse Response
	err = json.NewDecoder(response.Body).Decode(&jWKsResponse)
	if err != nil {
		nerr = err
		return
	}
	jWKsResponse.Status = response.Status
	jWKsResponse.StatusCode = response.StatusCode
	jWKs.response = jWKsResponse

	return
}

// Response is getter method of Response struct
func (jWKs *JWKs) Response() Response {
	return jWKs.response
}
