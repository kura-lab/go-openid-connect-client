package logouttoken

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	mystrings "github.com/kura-lab/go-openid-connect-client/pkg/strings"
)

func TestNewOIDCConfigPayloadSuccess(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
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
		"iat": currentTime,
		"jti": "JWT_ID",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "SESSION_ID",
	}
	jsonPayload, err := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

	rawLogoutToken := strings.Join(
		[]string{
			encodedHeader,
			encodedPayload,
			base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE")),
		},
		".",
	)

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.Issuer("https://op.example.com"),
	)
	oIDCConfigResponse := config.Response()

	logoutTokenPointer, err := NewLogoutToken(
		oIDCConfigResponse,
		rawLogoutToken,
	)

	if err != nil {
		t.Fatalf("failed to decode logout token: %#v", err)
	}

	err = logoutTokenPointer.VerifyPayloadClaims(
		Issuer(),
		Audience("CLIENT_ID"),
		DurationIssuedAt(600),
		JWTID("JWT_ID"),
	)
	if err != nil {
		t.Fatalf("invalid claim in logout token payload: expected true, err: %#v", err)
	}

	logoutTokenPayload := logoutTokenPointer.GetLogoutTokenPayload()

	if logoutTokenPayload.Issuer != "https://op.example.com" {
		t.Fatalf("invalid iss: expected: https://op.example.com, actual: %v", logoutTokenPayload.Issuer)
	}

	if logoutTokenPayload.Subject != "123456789" {
		t.Fatalf("invalid sub: expected: 123456789, actual: %v", logoutTokenPayload.Subject)
	}

	if !mystrings.Contains("CLIENT_ID", logoutTokenPayload.Audience) {
		t.Fatalf("invalid aud: expected: CLIENT_ID, actual: %#v", logoutTokenPayload.Audience)
	}

	if logoutTokenPayload.IssuedAt != currentTime {
		t.Fatalf("invalid iat: expected: %v, actual: %v", currentTime, logoutTokenPayload.IssuedAt)
	}

	if logoutTokenPayload.JWTID != "JWT_ID" {
		t.Fatalf("invalid jti: expected: JWT_ID, actual: %v", logoutTokenPayload.JWTID)
	}

	if string(logoutTokenPayload.Events) != "{\"http://schemas.openid.net/event/backchannel-logout\":{}}" {
		t.Fatalf("invalid events: expected: {\"http://schemas.openid.net/event/backchannel-logout\":{}}, actual: %s", logoutTokenPayload.Events)
	}

	if logoutTokenPayload.SessionID != "SESSION_ID" {
		t.Fatalf("invalid sid: expected: SESSION_ID, actual: %s", logoutTokenPayload.SessionID)
	}
}

func TestNewOIDCConfigPayloadAudienceStringSuccess(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": "KEY_ID",
	}
	jsonHeader, err := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	currentTime := int(time.Now().Unix())

	payload := map[string]interface{}{
		"iss": "https://op.example.com",
		"sub": "123456789",
		"aud": "CLIENT_ID",
		"iat": currentTime,
	}
	jsonPayload, err := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

	rawLogoutToken := strings.Join(
		[]string{
			encodedHeader,
			encodedPayload,
			base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE")),
		},
		".",
	)

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.Issuer("https://op.example.com"),
	)
	oIDCConfigResponse := config.Response()

	logoutTokenPointer, err := NewLogoutToken(
		oIDCConfigResponse,
		rawLogoutToken,
	)

	if err != nil {
		t.Fatalf("failed to decode logout token: %#v", err)
	}

	err = logoutTokenPointer.VerifyPayloadClaims(
		Audience("CLIENT_ID"),
	)
	if err != nil {
		t.Fatalf("invalid claim in logout token payload: expected true, err: %#v", err)
	}

	logoutTokenPayload := logoutTokenPointer.GetLogoutTokenPayload()

	if !mystrings.Contains("CLIENT_ID", logoutTokenPayload.Audience) {
		t.Fatalf("invalid aud: expected: CLIENT_ID, actual: %#v", logoutTokenPayload.Audience)
	}
}

func TestNewOIDCConfigPayloadFailure(t *testing.T) {

	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": "KEY_ID",
	}
	jsonHeader, err := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	currentTime := int(time.Now().Unix())

	payload := map[string]interface{}{
		"iss": "https://invalid-op.example.com",
		"sub": "123456789",
		"aud": []string{
			"INVALID_CLIENT_ID",
		},
		"iat": currentTime - 600,
		"jti": "INVALID_JWT_ID",
	}
	jsonPayload, err := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

	rawLogoutToken := strings.Join(
		[]string{
			encodedHeader,
			encodedPayload,
			base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE")),
		},
		".",
	)

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.Issuer("https://op.example.com"),
	)
	oIDCConfigResponse := config.Response()

	// aud claim error test
	logoutTokenPointer, _ := NewLogoutToken(
		oIDCConfigResponse,
		rawLogoutToken,
	)

	err = logoutTokenPointer.VerifyPayloadClaims(
		Issuer(),
	)
	if err == nil {
		t.Fatalf("success to verify iss claim: not expected nil")
	}

	logoutTokenPayload := logoutTokenPointer.GetLogoutTokenPayload()

	if logoutTokenPayload.Issuer != "https://invalid-op.example.com" {
		t.Fatalf("expected: https://invalid-op.example.com, actual: %v", logoutTokenPayload.Issuer)
	}

	// aud claim error test
	logoutTokenPointer, _ = NewLogoutToken(
		oIDCConfigResponse,
		rawLogoutToken,
	)

	err = logoutTokenPointer.VerifyPayloadClaims(
		Audience("CLIENT_ID"),
	)
	if err == nil {
		t.Fatalf("success to verify aud claim: not expected nil")
	}

	logoutTokenPayload = logoutTokenPointer.GetLogoutTokenPayload()

	if !mystrings.Contains("INVALID_CLIENT_ID", logoutTokenPayload.Audience) {
		t.Fatalf("expected: INVALID_CLIENT_ID, actual: %#v", logoutTokenPayload.Audience)
	}

	// iat claim error test
	logoutTokenPointer, _ = NewLogoutToken(
		oIDCConfigResponse,
		rawLogoutToken,
	)

	err = logoutTokenPointer.VerifyPayloadClaims(
		DurationIssuedAt(540),
	)
	if err == nil {
		t.Fatalf("success to verify iat claim: not expected nil")
	}

	logoutTokenPayload = logoutTokenPointer.GetLogoutTokenPayload()

	if logoutTokenPayload.IssuedAt != currentTime-600 {
		t.Fatalf("expected: %v, actual: %v", currentTime-600, logoutTokenPayload.IssuedAt)
	}

	// jti claim error test
	logoutTokenPointer, _ = NewLogoutToken(
		oIDCConfigResponse,
		rawLogoutToken,
	)

	err = logoutTokenPointer.VerifyPayloadClaims(
		JWTID("JWT_ID"),
	)
	if err == nil {
		t.Fatalf("success to verify jti claim: not expected nil")
	}
}
