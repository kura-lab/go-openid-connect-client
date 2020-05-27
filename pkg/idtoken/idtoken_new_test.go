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

	data := []string{
		"INVALID_HEADER_DECODE_ERROR!!!",
		"INVALID_HEADER_JSON_UNMARSHAL_ERROR",
	}

	for _, header := range data {

		payload := map[string]string{
			"sub": "123456789",
		}
		jsonPayload, err := json.Marshal(payload)
		encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

		signature := base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE"))

		rawIDToken := strings.Join(
			[]string{
				header,
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
}

func TestNewOIDCConfigDecodePayloadFailure(t *testing.T) {

	data := []string{
		"INVALID_PAYLOAD_DECODE_ERROR!!!",
		"INVALID_PAYLOAD_JSON_UNMARSHAL_ERROR",
	}

	for _, payload := range data {
		header := map[string]string{
			"typ": "JWT",
			"alg": "RS256",
			"kid": "KEY_ID",
		}
		jsonHeader, err := json.Marshal(header)
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

		signature := base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE"))

		rawIDToken := strings.Join(
			[]string{
				encodedHeader,
				payload,
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

func TestNewOIDCConfigDecodeSignatureFailure(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": "KEY_ID",
	}
	jsonHeader, err := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	payload := map[string]interface{}{
		"sub": "123456789",
	}
	jsonPayload, err := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

	signature := "INVALID_SIGNATURE_DECODE_ERROR!!!"

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
