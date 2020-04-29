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
	KeySets []struct {
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
	oidcconfig *oidcconfig.OIDCConfig
}

// NewJWKs is JWKs URI constructor function.
func NewJWKs(oidcconfig *oidcconfig.OIDCConfig) *JWKs {
	jWKs := new(JWKs)
	jWKs.oidcconfig = oidcconfig

	return jWKs
}

// Request is method to request JWKs URI.
func (jWKs *JWKs) Request() (Response, error) {
	response, err := http.Get(jWKs.oidcconfig.JWKsURI())
	if err != nil {
		return Response{}, err
	}
	defer func() {
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
	}()

	var jWKsResponse Response
	err = json.NewDecoder(response.Body).Decode(&jWKsResponse)
	if err != nil {
		return Response{}, err
	}

	return jWKsResponse, nil
}
