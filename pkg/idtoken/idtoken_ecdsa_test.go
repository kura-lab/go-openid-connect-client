package idtoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

		fmt.Printf("r: %#v\n", len(r.Bytes()))
		fmt.Printf("s: %#v\n", len(s.Bytes()))

		signature := r.Bytes()
		signature = append(signature, s.Bytes()...)

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

func TestNewOIDCConfigECDSAFailure(t *testing.T) {
}
