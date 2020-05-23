package idtoken

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

func TestNewOIDCConfigHeaderSuccesses(t *testing.T) {

	algorithms := [][]interface{}{
		{"RS256", []string{"RS256"}},
		{"RS512", []string{"RS256", "RS384", "RS512"}},
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

		signature := base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE"))

		rawIDToken := strings.Join(
			[]string{
				encodedHeader,
				encodedPayload,
				signature,
			},
			".",
		)

		config := oidcconfig.NewOIDCConfig(
			oidcconfig.Issuer("https://op.example.com"),
			oidcconfig.IDTokenSigningAlgValuesSupported(algorithm[1].([]string)),
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
	}
}

func TestNewOIDCConfigHeaderTypeFailure(t *testing.T) {

	algorithms := [][]interface{}{
		{"RS256", []string{"RS256"}},
	}

	for _, algorithm := range algorithms {

		header := map[string]string{
			"typ": "INVALID_JWT",
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

		signature := base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE"))

		rawIDToken := strings.Join(
			[]string{
				encodedHeader,
				encodedPayload,
				signature,
			},
			".",
		)

		config := oidcconfig.NewOIDCConfig(
			oidcconfig.Issuer("https://op.example.com"),
			oidcconfig.IDTokenSigningAlgValuesSupported(algorithm[1].([]string)),
		)
		oIDCConfigResponse := config.Response()

		iDTokenPointer, err := NewIDToken(
			oIDCConfigResponse,
			rawIDToken,
		)

		if err != nil {
			t.Fatalf("failed to decode id token: %#v", err)
		}

		if err := iDTokenPointer.VerifyIDTokenHeader(); err == nil {
			t.Fatalf("expect to success to verify id token header\n")
		}

		iDTokenPointerHeader := iDTokenPointer.GetIDTokenHeader()

		if iDTokenPointerHeader.Type != "INVALID_JWT" {
			t.Fatalf("invalid typ. expected: JWT, actual: %v", iDTokenPointerHeader.Type)
		}
		if iDTokenPointerHeader.Algorithm != algorithm[0].(string) {
			t.Fatalf("invalid alg. expected: %v, actual: %v", algorithm[0].(string), iDTokenPointerHeader.Algorithm)
		}
		if iDTokenPointerHeader.KeyID != "KEY_ID" {
			t.Fatalf("invalid kid. expected: KEY_ID, actual: %v", iDTokenPointerHeader.KeyID)
		}
	}
}

func TestNewOIDCConfigHeaderAlgorithmFailure(t *testing.T) {

	algorithms := [][]interface{}{
		{"RS256", []string{"RS256"}},
	}

	for _, algorithm := range algorithms {

		header := map[string]string{
			"typ": "JWT",
			"alg": "PS256",
			"kid": "KEY_ID",
		}
		jsonHeader, err := json.Marshal(header)
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

		payload := map[string]string{
			"sub": "123456789",
		}
		jsonPayload, err := json.Marshal(payload)
		encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

		signature := base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE"))

		rawIDToken := strings.Join(
			[]string{
				encodedHeader,
				encodedPayload,
				signature,
			},
			".",
		)

		config := oidcconfig.NewOIDCConfig(
			oidcconfig.Issuer("https://op.example.com"),
			oidcconfig.IDTokenSigningAlgValuesSupported(algorithm[1].([]string)),
		)
		oIDCConfigResponse := config.Response()

		iDTokenPointer, err := NewIDToken(
			oIDCConfigResponse,
			rawIDToken,
		)

		if err != nil {
			t.Fatalf("failed to decode id token: %#v", err)
		}

		if err := iDTokenPointer.VerifyIDTokenHeader(); err == nil {
			t.Fatalf("expect to success to verify id token header\n")
		}

		iDTokenPointerHeader := iDTokenPointer.GetIDTokenHeader()

		if iDTokenPointerHeader.Type != "JWT" {
			t.Fatalf("invalid typ. expected: JWT, actual: %v", iDTokenPointerHeader.Type)
		}
		if iDTokenPointerHeader.Algorithm != "PS256" {
			t.Fatalf("invalid alg. expected: PS256, actual: %v", iDTokenPointerHeader.Algorithm)
		}
		if iDTokenPointerHeader.KeyID != "KEY_ID" {
			t.Fatalf("invalid kid. expected: KEY_ID, actual: %v", iDTokenPointerHeader.KeyID)
		}
	}
}
