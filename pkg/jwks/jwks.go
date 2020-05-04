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
func (jWKs *JWKs) Request() error {
	response, err := http.Get(jWKs.oIDCConfig.JWKsURI)
	if err != nil {
		return err
	}
	defer func() {
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
	}()

	var jWKsResponse Response
	err = json.NewDecoder(response.Body).Decode(&jWKsResponse)
	if err != nil {
		return err
	}
	jWKsResponse.Status = response.Status
	jWKsResponse.StatusCode = response.StatusCode
	jWKs.response = jWKsResponse

	return nil
}

// Response is getter method of Response struct
func (jWKs *JWKs) Response() Response {
	return jWKs.response
}
