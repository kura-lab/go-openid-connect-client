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
	"time"

	myhash "github.com/kura-lab/go-openid-connect-client/pkg/hash"
	"github.com/kura-lab/go-openid-connect-client/pkg/jwks"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	mystrings "github.com/kura-lab/go-openid-connect-client/pkg/strings"
)

func TestNewOIDCConfigPayloadSuccess(t *testing.T) {

	algorithms := [][]interface{}{
		{"RS256", crypto.SHA256},
	}

	for _, algorithm := range algorithms {

		header := map[string]string{
			"typ": "JWT",
			"alg": algorithm[0].(string),
			"kid": "KEY_ID",
		}
		jsonHeader, err := json.Marshal(header)
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

		currentTime := int(time.Now().Unix())

		payload := map[string]interface{}{
			"iss": "https://op.example.com",
			"sub": "123456789",
			"aud": []string{
				"CLIENT_ID",
			},
			"exp":       currentTime + 3600,
			"iat":       currentTime,
			"auth_time": currentTime,
			"nonce":     "NONCE",
			"amr": []string{
				"sms",
			},
			"at_hash": myhash.GenerateHalfOfSHA256("ACCESS_TOKEN"),
			"acr":     "nist_auth_level 1",
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

		err = iDTokenPointer.VerifyPayloadClaims(
			Issuer(),
			Audience("CLIENT_ID"),
			Nonce("NONCE"),
			DurationIssuedAt(600),
			AccessTokenAccessTokenHash("ACCESS_TOKEN"),
		)
		if err != nil {
			t.Fatalf("invalid claim in id token payload: expected true, err: %#v", err)
		}

		iDTokenPayload := iDTokenPointer.GetIDTokenPayload()

		if iDTokenPayload.Issuer != "https://op.example.com" {
			t.Fatalf("invalid iss: expected: https://op.example.com, actual: %v", iDTokenPayload.Issuer)
		}

		if iDTokenPayload.Subject != "123456789" {
			t.Fatalf("invalid sub: expected: 123456789, actual: %v", iDTokenPayload.Subject)
		}

		if !mystrings.Contains("CLIENT_ID", iDTokenPayload.Audience) {
			t.Fatalf("invalid aud: expected: CLIENT_ID, actual: %#v", iDTokenPayload.Audience)
		}

		if iDTokenPayload.Expiration != currentTime+3600 {
			t.Fatalf("invalid exp: expected: %v, actual: %v", currentTime+3600, iDTokenPayload.Expiration)
		}

		if iDTokenPayload.IssuedAt != currentTime {
			t.Fatalf("invalid iat: expected: %v, actual: %v", currentTime, iDTokenPayload.IssuedAt)
		}

		if iDTokenPayload.AuthTime != currentTime {
			t.Fatalf("invalid auth_time: expected: %v, actual: %v", currentTime, iDTokenPayload.AuthTime)
		}

		if iDTokenPayload.Nonce != "NONCE" {
			t.Fatalf("invalid nonce: expected: NONCE, actual: %v", iDTokenPayload.Nonce)
		}

		if !mystrings.Contains("sms", iDTokenPayload.AuthenticationMethodReference) {
			t.Fatalf("invalid amr: expected: , actual: %#v", iDTokenPayload.AuthenticationMethodReference)
		}

		if iDTokenPayload.AccessTokenHash != myhash.GenerateHalfOfSHA256("ACCESS_TOKEN") {
			t.Fatalf("invalid at_hash: expected: %v, actual: %v", myhash.GenerateHalfOfSHA256("ACCESS_TOKEN"), iDTokenPayload.AccessTokenHash)
		}

		if iDTokenPayload.AuthenticationContextReference != "nist_auth_level 1" {
			t.Fatalf("invalid acr: expected: nist_auth_level 1, actual: %v", iDTokenPayload.AuthenticationContextReference)
		}
	}
}

func TestNewOIDCConfigPayloadAudienceStringSuccess(t *testing.T) {

	algorithms := [][]interface{}{
		{"RS256", crypto.SHA256},
	}

	for _, algorithm := range algorithms {

		header := map[string]string{
			"typ": "JWT",
			"alg": algorithm[0].(string),
			"kid": "KEY_ID",
		}
		jsonHeader, err := json.Marshal(header)
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

		currentTime := int(time.Now().Unix())

		payload := map[string]interface{}{
			"iss":       "https://op.example.com",
			"sub":       "123456789",
			"aud":       "CLIENT_ID",
			"exp":       currentTime + 3600,
			"iat":       currentTime,
			"auth_time": currentTime,
			"nonce":     "NONCE",
			"amr": []string{
				"sms",
			},
			"at_hash": myhash.GenerateHalfOfSHA256("ACCESS_TOKEN"),
			"acr":     "nist_auth_level 1",
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

		err = iDTokenPointer.VerifyPayloadClaims(
			Audience("CLIENT_ID"),
		)
		if err != nil {
			t.Fatalf("invalid claim in id token payload: expected true, err: %#v", err)
		}

		iDTokenPayload := iDTokenPointer.GetIDTokenPayload()

		if !mystrings.Contains("CLIENT_ID", iDTokenPayload.Audience) {
			t.Fatalf("invalid aud: expected: CLIENT_ID, actual: %#v", iDTokenPayload.Audience)
		}
	}
}

func TestNewOIDCConfigPayloadFailure(t *testing.T) {
}
