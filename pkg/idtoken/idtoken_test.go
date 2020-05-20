package idtoken

import (
	"testing"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

func TestNewOIDCConfigSuccess(t *testing.T) {

	config := oidcconfig.NewOIDCConfig(
		oidcconfig.Issuer("https://op.example.com"),
		oidcconfig.IDTokenSigningAlgValuesSupported([]string{"RS256"}),
	)
	oIDCConfigResponse := config.Response()

	rawIDToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IktFWV9JRCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiWU9VUl9DTElFTlRfSUQifQ.PfYYCnyibH0CQ6_tYGfcRtpeIYEp1wwn22zQQFpR2ec4buJEfodrOphVTsh3JdgfbXYGokzQBwVkKDDx1u6zrsYMfJWlni1mBdPr19NkmWvQ0dxf6ExuG5aJtWvOR_MYo0Mhzn393yxmmAZ8fwRxNinqPuN19yqlPxBXY2fD23042uWBkYDdUL3eY094OvlOU_CF06BXgNGvm0CQ9Ssm_I2LbgeOd-bmX16gznHldIsY7eE3VfUyPQCu1FbNfCkm0QxXYP4LL60GgaGx65WhD45CHN8hXOVfgMWpd73EuzdZa64iEUwJpxwf9_fdYWoRznOh5mDjI3FSc1_0AsOFfQ"

	iDTokenPointer, err := NewIDToken(
		oIDCConfigResponse,
		rawIDToken,
	)

	if err != nil {
		t.Errorf("failed to decode id token: %#v", err)
	}

	if err := iDTokenPointer.VerifyIDTokenHeader(); err != nil {
		t.Errorf("invalid claim in id token header: %#v", err)
	}

	iDTokenPointerHeader := iDTokenPointer.GetIDTokenHeader()

	if iDTokenPointerHeader.Type != "JWT" {
		t.Errorf("invalid typ. expected: JWT, actual: %v", iDTokenPointerHeader.Type)
	}
	if iDTokenPointerHeader.Algorithm != "RS256" {
		t.Errorf("invalid alg. expected: RS256, actual: %v", iDTokenPointerHeader.Algorithm)
	}
	if iDTokenPointerHeader.KeyID != "KEY_ID" {
		t.Errorf("invalid kid. expected: KEY_ID, actual: %v", iDTokenPointerHeader.KeyID)
	}
}
