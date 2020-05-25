package idtoken

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

func TestNewOIDCConfigSuccess(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
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
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	iDTokenPointer, err := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	if err != nil {
		t.Fatalf("failed to decode id token: %#v", err)
	}

	if iDTokenPointer == nil {
		t.Fatalf("failed to initilize id token")
	}
}

func TestNewOIDCConfigDecodeHeaderFailure(t *testing.T) {

	encodedHeader := "INVALID_HEADER"

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
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	iDTokenPointer, err := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	if err == nil {
		t.Fatalf("succuess to new id token")
	}

	if iDTokenPointer != nil {
		t.Fatalf("unexpected return: %#v", iDTokenPointer)
	}
}

func TestNewOIDCConfigDecodePayloadFailure(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": "KEY_ID",
	}
	jsonHeader, err := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	encodedPayload := "INVALID_PAYLOAD"

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
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	iDTokenPointer, err := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	if err == nil {
		t.Fatalf("succuess to new id token")
	}

	if iDTokenPointer != nil {
		t.Fatalf("unexpected return: %#v", iDTokenPointer)
	}
}

func TestNewOIDCConfigDecodePayloadAudienceFailure(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": "KEY_ID",
	}
	jsonHeader, err := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	payload := map[string]interface{}{
		"sub": "123456789",
		"aud": 0,
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
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	iDTokenPointer, err := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	if err == nil {
		t.Fatalf("succuess to new id token")
	}

	if iDTokenPointer != nil {
		t.Fatalf("unexpected return: %#v", iDTokenPointer)
	}
}
