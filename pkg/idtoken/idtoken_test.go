package idtoken

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/jwks"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

func TestNewOIDCConfigSuccess(t *testing.T) {

	algorithms := [][]interface{}{
		{"RS256", crypto.SHA256},
		{"RS384", crypto.SHA384},
		{"RS512", crypto.SHA512},
	}

	for _, algorithm := range algorithms {

		header := map[string]string{
			"typ": "JWT",
			"alg": algorithm[0].(string),
			"kid": "KEY_ID",
		}
		jsonHeader, err := json.Marshal(header)
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

		payload := map[string]string{
			"sub": "123456789",
		}
		jsonPayload, err := json.Marshal(payload)
		encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		publicKey := privateKey.PublicKey
		modulus := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		data := encodedHeader + "." + encodedPayload

		hash := crypto.Hash.New(algorithm[1].(crypto.Hash))
		hash.Write(([]byte)(data))
		hashed := hash.Sum(nil)

		signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, algorithm[1].(crypto.Hash), hashed)

		encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

		rawIDToken := strings.Join(
			[]string{
				encodedHeader,
				encodedPayload,
				encodedSignature,
			},
			".",
		)

		config := oidcconfig.NewOIDCConfig(
			oidcconfig.Issuer("https://op.example.com"),
			oidcconfig.IDTokenSigningAlgValuesSupported([]string{algorithm[0].(string)}),
		)
		oIDCConfigResponse := config.Response()

		iDTokenPointer, err := NewIDToken(
			oIDCConfigResponse,
			rawIDToken,
		)

		if err != nil {
			t.Fatalf("failed to decode id token: %#v", err)
		}

		if err := iDTokenPointer.VerifyIDTokenHeader(); err != nil {
			t.Fatalf("invalid claim in id token header: %#v", err)
		}

		iDTokenPointerHeader := iDTokenPointer.GetIDTokenHeader()

		if iDTokenPointerHeader.Type != "JWT" {
			t.Fatalf("invalid typ. expected: JWT, actual: %v", iDTokenPointerHeader.Type)
		}
		if iDTokenPointerHeader.Algorithm != algorithm[0].(string) {
			t.Fatalf("invalid alg. expected: %v, actual: %v", algorithm[0].(string), iDTokenPointerHeader.Algorithm)
		}
		if iDTokenPointerHeader.KeyID != "KEY_ID" {
			t.Fatalf("invalid kid. expected: KEY_ID, actual: %v", iDTokenPointerHeader.KeyID)
		}

		jWKsResponse := jwks.Response{
			KeySets: []jwks.KeySet{
				{
					KeyID:     "KEY_ID",
					KeyType:   "RSA",
					Algorithm: algorithm[0].(string),
					Use:       "sig",
					Modulus:   modulus,
					Exponent:  exponent,
				},
			},
		}

		if err := iDTokenPointer.VerifySignature(jWKsResponse); err != nil {
			t.Fatalf("invalid signature: expected: true")
		}
	}
}

func TestNewOIDCConfigFailure(t *testing.T) {

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.Issuer("https://op.example.com"),
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	rawIDToken := "INVALID_HEADER.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiWU9VUl9DTElFTlRfSUQifQ.PfYYCnyibH0CQ6_tYGfcRtpeIYEp1wwn22zQQFpR2ec4buJEfodrOphVTsh3JdgfbXYGokzQBwVkKDDx1u6zrsYMfJWlni1mBdPr19NkmWvQ0dxf6ExuG5aJtWvOR_MYo0Mhzn393yxmmAZ8fwRxNinqPuN19yqlPxBXY2fD23042uWBkYDdUL3eY094OvlOU_CF06BXgNGvm0CQ9Ssm_I2LbgeOd-bmX16gznHldIsY7eE3VfUyPQCu1FbNfCkm0QxXYP4LL60GgaGx65WhD45CHN8hXOVfgMWpd73EuzdZa64iEUwJpxwf9_fdYWoRznOh5mDjI3FSc1_0AsOFfQ"

	_, err := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	if err == nil {
		t.Fatalf("success to decode id token header: %#v", err)
	}
}
