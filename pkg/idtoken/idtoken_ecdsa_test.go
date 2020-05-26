package idtoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"hash"
	"math/big"
	"strings"
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/jwks"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

func TestNewOIDCConfigECDSASuccess(t *testing.T) {

	algorithms := [][]interface{}{
		{"ES256", elliptic.P256(), crypto.SHA256.New(), "P-256"},
		{"ES384", elliptic.P384(), crypto.SHA384.New(), "P-384"},
		{"ES512", elliptic.P521(), crypto.SHA512.New(), "P-521"},
	}

	for _, algorithm := range algorithms {
		header := map[string]string{
			"typ": "JWT",
			"alg": algorithm[0].(string),
			"kid": "KEY_ID",
		}
		jsonHeader, _ := json.Marshal(header)
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

		payload := map[string]string{
			"sub": "123456789",
		}
		jsonPayload, _ := json.Marshal(payload)
		encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

		ellipticCurve := algorithm[1].(elliptic.Curve)

		privateKey, _ := ecdsa.GenerateKey(ellipticCurve, rand.Reader)

		publicKey := privateKey.PublicKey

		hash := algorithm[2].(hash.Hash)
		r := big.NewInt(0)
		s := big.NewInt(0)

		data := encodedHeader + "." + encodedPayload

		hash.Write(([]byte)(data))
		hashed := hash.Sum(nil)

		r, s, _ = ecdsa.Sign(rand.Reader, privateKey, hashed)

		keySize := privateKey.Curve.Params().BitSize / 8
		if privateKey.Curve.Params().BitSize%8 > 0 {
			keySize++
		}

		var signature []byte
		rPad := keySize - len(r.Bytes())
		if rPad > 0 {
			zeroPad := make([]byte, rPad)
			signature = append(zeroPad, r.Bytes()...)
		} else {
			signature = append(signature, r.Bytes()...)
		}

		sPad := keySize - len(s.Bytes())
		if sPad > 0 {
			zeroPad := make([]byte, sPad)
			signature = append(signature, zeroPad...)
			signature = append(signature, s.Bytes()...)
		} else {
			signature = append(signature, s.Bytes()...)
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
					KeyID:       "KEY_ID",
					KeyType:     "EC",
					Algorithm:   algorithm[0].(string),
					Use:         "sig",
					Curve:       algorithm[3].(string),
					XCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
					YCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
				},
			},
		}

		if err := iDTokenPointer.VerifySignature(jWKsResponse); err != nil {
			t.Fatalf("invalid signature. expected: true, alg: %v, err:%v", algorithm[0].(string), err)
		}

	}
}

func TestNewOIDCConfigGenerateECDSAPublicKeyFailures(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "ES256",
		"kid": "KEY_ID",
	}
	jsonHeader, _ := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	payload := map[string]string{
		"sub": "123456789",
	}
	jsonPayload, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

	ellipticCurve := elliptic.P256()

	privateKey, _ := ecdsa.GenerateKey(ellipticCurve, rand.Reader)

	publicKey := privateKey.PublicKey

	hash := crypto.SHA256.New()
	r := big.NewInt(0)
	s := big.NewInt(0)

	data := encodedHeader + "." + encodedPayload

	hash.Write(([]byte)(data))
	hashed := hash.Sum(nil)

	r, s, _ = ecdsa.Sign(rand.Reader, privateKey, hashed)

	keySize := privateKey.Curve.Params().BitSize / 8
	if privateKey.Curve.Params().BitSize%8 > 0 {
		keySize++
	}

	var signature []byte
	rPad := keySize - len(r.Bytes())
	if rPad > 0 {
		zeroPad := make([]byte, rPad)
		signature = append(zeroPad, r.Bytes()...)
	} else {
		signature = append(signature, r.Bytes()...)
	}

	sPad := keySize - len(s.Bytes())
	if sPad > 0 {
		zeroPad := make([]byte, sPad)
		signature = append(signature, zeroPad...)
		signature = append(signature, s.Bytes()...)
	} else {
		signature = append(signature, s.Bytes()...)
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
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"ES256"}),
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
				KeyID:       "KEY_ID",
				KeyType:     "EC",
				Algorithm:   "ES256",
				Use:         "INVALID_USE",
				Curve:       "P-256",
				XCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
				YCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid use of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:       "KEY_ID",
				KeyType:     "INVALID_KEY_TYPE",
				Algorithm:   "ES256",
				Use:         "sig",
				Curve:       "P-256",
				XCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
				YCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid kty of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:       "KEY_ID",
				KeyType:     "EC",
				Algorithm:   "UNMATCHED_ALGORITHM",
				Use:         "sig",
				Curve:       "P-256",
				XCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
				YCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by unmatched alg of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:       "KEY_ID",
				KeyType:     "EC",
				Algorithm:   "ES256",
				Use:         "sig",
				Curve:       "P-256",
				XCoordinate: "",
				YCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by not existing x coordinate of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:       "KEY_ID",
				KeyType:     "EC",
				Algorithm:   "ES256",
				Use:         "sig",
				Curve:       "P-256",
				XCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
				YCoordinate: "",
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by not existing y coordinate of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:       "KEY_ID",
				KeyType:     "EC",
				Algorithm:   "ES256",
				Use:         "sig",
				Curve:       "P-256",
				XCoordinate: "INVALID_X_COORDIVATE!!!",
				YCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid x coordinate of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:       "KEY_ID",
				KeyType:     "EC",
				Algorithm:   "ES256",
				Use:         "sig",
				Curve:       "P-256",
				XCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
				YCoordinate: "INVALID_Y_COORDINATE!!!",
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid y coordinate of key set")
	}

	jWKsResponse = jwks.Response{
		KeySets: []jwks.KeySet{
			{
				KeyID:       "KEY_ID",
				KeyType:     "EC",
				Algorithm:   "ES256",
				Use:         "sig",
				Curve:       "INVALID_CURVE_ALGORITHM",
				XCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
				YCoordinate: base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
			},
		},
	}

	if err := iDTokenPointer.VerifySignature(jWKsResponse); err == nil {
		t.Fatalf("expect error caused by invalid curve algorithm of key set")
	}
}
