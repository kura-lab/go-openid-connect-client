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

func TestNewOIDCConfigRSASuccess(t *testing.T) {

	algorithms := [][]interface{}{
		{"RS256", crypto.SHA256},
		{"RS384", crypto.SHA384},
		{"RS512", crypto.SHA512},
		{"PS256", crypto.SHA256},
		{"PS384", crypto.SHA384},
		{"PS512", crypto.SHA512},
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

		var signature []byte
		switch algorithm[0].(string) {
		case "RS256", "RS384", "RS512":
			signature, _ = rsa.SignPKCS1v15(rand.Reader, privateKey, algorithm[1].(crypto.Hash), hashed)
		case "PS256", "PS384", "PS512":
			signature, _ = rsa.SignPSS(rand.Reader, privateKey, algorithm[1].(crypto.Hash), hashed, nil)
		}

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
			t.Fatalf("invalid signature. expected: true, alg: %v", algorithm[0].(string))
		}
	}
}

func TestNewOIDCConfigGenerateRSAPublicKeyFailures(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": "KEY_ID",
	}
	jsonHeader, _ := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	payload := map[string]string{
		"sub": "123456789",
	}
	jsonPayload, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	publicKey := privateKey.PublicKey
	modulus := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	data := encodedHeader + "." + encodedPayload

	hash := crypto.Hash.New(crypto.SHA256)
	hash.Write(([]byte)(data))
	hashed := hash.Sum(nil)

	var signature []byte
	signature, _ = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)

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
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	iDTokenPointer, _ := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	if err := iDTokenPointer.VerifyIDTokenHeader(); err != nil {
		t.Fatalf("invalid claim in id token header: %#v", err)
	}

	jWKsResponse := jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:     "KEY_ID",
				KeyType:   "RSA",
				Algorithm: "RS256",
				Use:       "INVALID_USE",
				Modulus:   modulus,
				Exponent:  exponent,
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid use of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:     "KEY_ID",
				KeyType:   "INVALID_KEY_TYPE",
				Algorithm: "RS256",
				Use:       "sig",
				Modulus:   modulus,
				Exponent:  exponent,
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid kty of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:     "KEY_ID",
				KeyType:   "RSA",
				Algorithm: "UNMATCHED_ALGORITHM",
				Use:       "sig",
				Modulus:   modulus,
				Exponent:  exponent,
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by unmatched alg of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:     "KEY_ID",
				KeyType:   "RSA",
				Algorithm: "RS256",
				Use:       "sig",
				Modulus:   "",
				Exponent:  exponent,
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by not existing modulus of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:     "KEY_ID",
				KeyType:   "RSA",
				Algorithm: "RS256",
				Use:       "sig",
				Modulus:   modulus,
				Exponent:  "",
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by not existing exponent of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:     "KEY_ID",
				KeyType:   "RSA",
				Algorithm: "RS256",
				Use:       "sig",
				Modulus:   "INVALID_MODULUS!!!",
				Exponent:  exponent,
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid modulus of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:     "KEY_ID",
				KeyType:   "RSA",
				Algorithm: "RS256",
				Use:       "sig",
				Modulus:   modulus,
				Exponent:  "INVALID_EXPONENT!!!",
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid exponent of key set")
	}
}
