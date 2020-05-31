package jwks

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"gopkg.in/h2non/gock.v1"
)

func TestNewJWKsSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		Get("/jwks").
		Reply(200).
		JSON(map[string][]interface{}{
			"keys": {
				map[string]string{
					"kid": "KEY_ID_1",
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"n":   "MODULUS",
					"e":   "AQAB",
				},
				map[string]string{
					"kid": "KEY_ID_2",
					"kty": "EC",
					"alg": "ES256",
					"use": "sig",
					"crv": "P-256",
					"x":   "X_COORDINATE",
					"y":   "Y_COORDINATE",
				},
			},
		})

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.JWKsURI("https://op.example.com/jwks"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	jWKsPointer := NewJWKs(
		oIDCConfigResponse,
	)

	err := jWKsPointer.Request()

	if err != nil {
		t.Fatalf("failed to request. err: %#v", err)
	}

	response := jWKsPointer.Response()

	if response.Status != "200 OK" {
		t.Errorf("invalid http status. expected: 200 OK, actual: %v", response.Status)
	}

	if response.StatusCode != 200 {
		t.Errorf("invalid http status code. expected: 200, actual: %v", response.StatusCode)
	}

	data := []interface{}{
		map[string]string{
			"kid": "KEY_ID_1",
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"n":   "MODULUS",
			"e":   "AQAB",
			"crv": "",
			"x":   "",
			"y":   "",
		},
		map[string]string{
			"kid": "KEY_ID_2",
			"kty": "EC",
			"alg": "ES256",
			"use": "sig",
			"n":   "",
			"e":   "",
			"crv": "P-256",
			"x":   "X_COORDINATE",
			"y":   "Y_COORDINATE",
		},
	}

	for key, value := range data {

		expected := value.(map[string]string)

		if response.KeySets[key].KeyID != expected["kid"] {
			t.Errorf("invalid kid. expected: %v, actual: %v", expected["kid"], response.KeySets[key].KeyID)
		}

		if response.KeySets[key].KeyType != expected["kty"] {
			t.Errorf("invalid kty. expected: %v, actual: %v", expected["kty"], response.KeySets[key].KeyType)
		}

		if response.KeySets[key].Algorithm != expected["alg"] {
			t.Errorf("invalid alg. expected: %v, actual: %v", expected["alg"], response.KeySets[key].Algorithm)
		}

		if response.KeySets[key].Use != expected["use"] {
			t.Errorf("invalid use. expected: %v, actual: %v", expected["use"], response.KeySets[key].Use)
		}

		if response.KeySets[key].Modulus != expected["n"] {
			t.Errorf("invalid n(moduls). expected: %v, actual: %v", expected["n"], response.KeySets[key].Modulus)
		}

		if response.KeySets[key].Exponent != expected["e"] {
			t.Errorf("invalid e(exponent). expected: %v, actual: %v", expected["e"], response.KeySets[key].Exponent)
		}

		if response.KeySets[key].Curve != expected["crv"] {
			t.Errorf("invalid crv. expected: %v, actual: %v", expected["crv"], response.KeySets[key].Curve)
		}

		if response.KeySets[key].XCoordinate != expected["x"] {
			t.Errorf("invalid x coordinate. expected: %v, actual: %v", expected["x"], response.KeySets[key].XCoordinate)
		}

		if response.KeySets[key].YCoordinate != expected["y"] {
			t.Errorf("invalid y coordinate. expected: %v, actual: %v", expected["y"], response.KeySets[key].YCoordinate)
		}
	}
}

func TestNewJWKsFailure(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		Get("/jwks").
		Reply(200).
		BodyString("INVALID_BODY")

	oIDCConfigPointer := oidcconfig.NewOIDCConfig(
		oidcconfig.JWKsURI("https://op.example.com/jwks"),
	)

	oIDCConfigResponse := oIDCConfigPointer.Response()

	jWKsPointer := NewJWKs(
		oIDCConfigResponse,
	)

	err := jWKsPointer.Request()

	if err == nil {
		t.Fatalf("expect json parsing error.")
	}
}
