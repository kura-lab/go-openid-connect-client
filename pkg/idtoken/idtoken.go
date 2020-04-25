package idtoken

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kura-lab/go-openid-connect-client/pkg/hash"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	mystring "github.com/kura-lab/go-openid-connect-client/pkg/strings"
)

// Header is struct for decoded ID Token Header.
type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

// Payload is struct for decoded ID Token Payload.
type Payload struct {
	Issuer                         string `json:"iss"`
	Subject                        string `json:"sub"`
	Audience                       []string
	RawAudience                    json.RawMessage `json:"aud"`
	Expiration                     int             `json:"exp"`
	IssuedAt                       int             `json:"iat"`
	AuthTime                       int             `json:"auth_time"`
	Nonce                          string          `json:"nonce"`
	AuthenticationMethodReference  []string        `json:"amr"`
	AccessTokenHash                string          `json:"at_hash"`
	AuthenticationContextReference string          `json:"acr"`
}

// IDToken is struct for ID Token.
type IDToken struct {
	oidcconfig                         *oidcconfig.OIDCConfig
	iDTokenParts                       []string
	iDTokenHeader                      *Header
	iDTokenPayload                     *Payload
	decodedSignature                   []byte
	expectedIssuer                     string
	expectedAudience                   string
	expectedNonce                      string
	expectedDurationIssueAt            int
	expectedAccessTokenAccessTokenHash string
}

// NewIDToken is IDToken constructor function.
func NewIDToken(oidcconfig *oidcconfig.OIDCConfig, rawIDToken string) (*IDToken, error) {
	iDToken := new(IDToken)
	iDToken.oidcconfig = oidcconfig

	iDToken.iDTokenParts = strings.SplitN(rawIDToken, ".", 3)

	header, err := base64.RawURLEncoding.DecodeString(iDToken.iDTokenParts[0])
	if err != nil {
		return nil, err
	}
	iDTokenHeader := new(Header)
	err = json.Unmarshal(header, iDTokenHeader)
	if err != nil {
		return nil, err
	}
	iDToken.iDTokenHeader = iDTokenHeader

	decodedPayload, err := base64.RawURLEncoding.DecodeString(iDToken.iDTokenParts[1])
	if err != nil {
		return nil, err
	}

	iDTokenPayload := new(Payload)
	err = json.Unmarshal(decodedPayload, iDTokenPayload)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(iDTokenPayload.RawAudience, &iDTokenPayload.Audience); err != nil {
		var audString string
		if err := json.Unmarshal(iDTokenPayload.RawAudience, &audString); err != nil {
			return nil, err
		}
		iDTokenPayload.Audience = append(iDTokenPayload.Audience, audString)
	}

	iDToken.iDTokenPayload = iDTokenPayload

	decodedSignature, err := base64.RawURLEncoding.DecodeString(iDToken.iDTokenParts[2])
	if err != nil {
		return nil, err
	}
	iDToken.decodedSignature = decodedSignature

	return iDToken, nil
}

// VerifyIDTokenHeader is method to verify ID Token Header.
func (iDToken *IDToken) VerifyIDTokenHeader() error {
	if iDToken.iDTokenHeader.Type != "JWT" {
		return errors.New("unsupported header type")
	}
	if iDToken.iDTokenHeader.Algorithm != "RS256" {
		return errors.New("unsupported signature algorithm")
	}

	return nil
}

// GetIDTokenHeader is method to getter of Header struct.
func (iDToken *IDToken) GetIDTokenHeader() *Header {
	return iDToken.iDTokenHeader
}

// VerifySignature is method to verify ID Token signature.
func (iDToken *IDToken) VerifySignature(publicKey rsa.PublicKey) error {
	hash := crypto.Hash.New(crypto.SHA256)
	_, err := hash.Write([]byte(iDToken.iDTokenParts[0] + "." + iDToken.iDTokenParts[1]))
	if err != nil {
		return err
	}
	hashed := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed, iDToken.decodedSignature)

	return err
}

// Option is functional option for VerifyPayload function initialization.
type Option func(*IDToken) error

// Issuer is functional option to add expected issuer.
func Issuer() Option {
	return func(iDToken *IDToken) error {
		iDToken.expectedIssuer = iDToken.oidcconfig.Issuer()
		return nil
	}
}

// Audience is functional option to add expected audience.
func Audience(audience string) Option {
	return func(iDToken *IDToken) error {
		iDToken.expectedAudience = audience
		return nil
	}
}

// Nonce is functional option to add expected nonce.
func Nonce(nonce string) Option {
	return func(iDToken *IDToken) error {
		iDToken.expectedNonce = nonce
		return nil
	}
}

// IssuedAt is functional option to add expected duration of issued at.
func DurationIssuedAt(duration int) Option {
	return func(iDToken *IDToken) error {
		iDToken.expectedDurationIssueAt = duration
		return nil
	}
}

// AccessTokenAccessTokenHash is functional option to add expected access token of access token hash.
func AccessTokenAccessTokenHash(accessToken string) Option {
	return func(iDToken *IDToken) error {
		iDToken.expectedAccessTokenAccessTokenHash = accessToken
		return nil
	}
}

// VerifyPayloadClaims is method to verify claims included ID Token payload.
func (iDToken *IDToken) VerifyPayloadClaims(options ...Option) error {
	for _, option := range options {
		option(iDToken)
	}

	if iDToken.expectedIssuer != "" {
		if iDToken.expectedIssuer != iDToken.iDTokenPayload.Issuer {
			return errors.New("invalid issuer")
		}
	}

	if iDToken.expectedAudience != "" {
		if !mystring.Contains(iDToken.expectedAudience, iDToken.iDTokenPayload.Audience) {
			return errors.New("invalid audience")
		}
	}

	if iDToken.expectedNonce != "" {
		if iDToken.expectedNonce != iDToken.iDTokenPayload.Nonce {
			return errors.New("invalid nonce")
		}
	}

	if iDToken.expectedDurationIssueAt != 0 {
		if int(time.Now().Unix())-iDToken.iDTokenPayload.IssuedAt > iDToken.expectedDurationIssueAt {
			return errors.New("iat is too far away from current time")
		}
	}

	if iDToken.expectedAccessTokenAccessTokenHash != "" {
		aTHash := hash.GenerateHalfOfSHA256(iDToken.expectedAccessTokenAccessTokenHash)
		if aTHash != iDToken.iDTokenPayload.AccessTokenHash {
			return errors.New("invalid access token hash")
		}
	}

	return nil
}

// GetIDTokenPayload is method to getter of Payload struct.
func (iDToken *IDToken) GetIDTokenPayload() *Payload {
	return iDToken.iDTokenPayload
}
