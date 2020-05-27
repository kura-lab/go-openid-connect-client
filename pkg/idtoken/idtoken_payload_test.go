package idtoken

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	myhash "github.com/kura-lab/go-openid-connect-client/pkg/hash"
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

	rawIDToken := strings.Join(
		[]string{
			encodedHeader,
			encodedPayload,
			base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE")),
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

	rawIDToken := strings.Join(
		[]string{
			encodedHeader,
			encodedPayload,
			base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE")),
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
		"exp":       currentTime + 3600,
		"iat":       currentTime - 600,
		"auth_time": currentTime - 600,
		"nonce":     "INVALID_NONCE",
		"amr": []string{
			"sms",
		},
		"at_hash": myhash.GenerateHalfOfSHA256("INVALID_ACCESS_TOKEN"),
		"acr":     "nist_auth_level 1",
	}
	jsonPayload, err := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)

	rawIDToken := strings.Join(
		[]string{
			encodedHeader,
			encodedPayload,
			base64.RawURLEncoding.EncodeToString([]byte("SIGNATURE")),
		},
		".",
	)

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.Issuer("https://op.example.com"),
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	// aud claim error test
	iDTokenPointer, _ := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	err = iDTokenPointer.VerifyPayloadClaims(
		Issuer(),
	)
	if err == nil {
		t.Fatalf("success to verify iss claim: not expected nil")
	}

	iDTokenPayload := iDTokenPointer.GetIDTokenPayload()

	if iDTokenPayload.Issuer != "https://invalid-op.example.com" {
		t.Fatalf("expected: https://invalid-op.example.com, actual: %v", iDTokenPayload.Issuer)
	}

	// aud claim error test
	iDTokenPointer, _ = NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	err = iDTokenPointer.VerifyPayloadClaims(
		Audience("CLIENT_ID"),
	)
	if err == nil {
		t.Fatalf("success to verify aud claim: not expected nil")
	}

	iDTokenPayload = iDTokenPointer.GetIDTokenPayload()

	if !mystrings.Contains("INVALID_CLIENT_ID", iDTokenPayload.Audience) {
		t.Fatalf("expected: INVALID_CLIENT_ID, actual: %#v", iDTokenPayload.Audience)
	}

	// nonce claim error test
	iDTokenPointer, _ = NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	err = iDTokenPointer.VerifyPayloadClaims(
		Nonce("NONCE"),
	)
	if err == nil {
		t.Fatalf("success to verify nonce claim: not expected nil")
	}

	iDTokenPayload = iDTokenPointer.GetIDTokenPayload()

	if iDTokenPayload.Nonce != "INVALID_NONCE" {
		t.Fatalf("expected: INVALID_NONCE, actual: %v", iDTokenPayload.Nonce)
	}

	// iat claim error test
	iDTokenPointer, _ = NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	err = iDTokenPointer.VerifyPayloadClaims(
		DurationIssuedAt(540),
	)
	if err == nil {
		t.Fatalf("success to verify iat claim: not expected nil")
	}

	iDTokenPayload = iDTokenPointer.GetIDTokenPayload()

	if iDTokenPayload.IssuedAt != currentTime-600 {
		t.Fatalf("expected: %v, actual: %v", currentTime-600, iDTokenPayload.IssuedAt)
	}

	// at_hash claim error test
	iDTokenPointer, _ = NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	err = iDTokenPointer.VerifyPayloadClaims(
		AccessTokenAccessTokenHash("ACCESS_TOKEN"),
	)
	if err == nil {
		t.Fatalf("success to verify at_hash claim: not expected nil")
	}

	iDTokenPayload = iDTokenPointer.GetIDTokenPayload()

	if iDTokenPayload.AccessTokenHash != myhash.GenerateHalfOfSHA256("INVALID_ACCESS_TOKEN") {
		t.Fatalf("expected: %v, actual: %v", myhash.GenerateHalfOfSHA256("INVALID_ACCESS_TOKEN"), iDTokenPayload.AccessTokenHash)
	}
}
