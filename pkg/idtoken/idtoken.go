package idtoken

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

type IDTokenHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type IDTokenPayload struct {
	Issuer                         string `json:"iss"`
	Subject                        string `json:"sub"`
	Audience                       []string
	RawAudience                    json.RawMessage `json:"aud"`
	Expiration                     int             `json:"exp"`
	IssueAt                        int             `json:"iat"`
	AuthTime                       int             `json:"auth_time"`
	Nonce                          string          `json:"nonce"`
	AuthenticationMethodReference  []string        `json:"amr"`
	AccessTokenHash                string          `json:"at_hash"`
	AuthenticationContextReference string          `json:"acr"`
}

type IDToken struct {
	oidcconfig       *oidcconfig.OIDCConfig
	iDTokenParts     []string
	iDTokenHeader    *IDTokenHeader
	iDTokenPayload   *IDTokenPayload
	decodedSignature []byte
}

//TBD
//func NewIDToken(oidcconfig *oidcconfig.OIDCConfig, rawIDToken string, options ...Option) *IDToken {
func NewIDToken(oidcconfig *oidcconfig.OIDCConfig, rawIDToken string) (*IDToken, error) {
	iDToken := new(IDToken)
	iDToken.oidcconfig = oidcconfig

	iDToken.iDTokenParts = strings.SplitN(rawIDToken, ".", 3)

	header, err := base64.RawURLEncoding.DecodeString(iDToken.iDTokenParts[0])
	if err != nil {
		return nil, err
	}
	iDTokenHeader := new(IDTokenHeader)
	err = json.Unmarshal(header, iDTokenHeader)
	if err != nil {
		return nil, err
	}
	iDToken.iDTokenHeader = iDTokenHeader

	decodedPayload, err := base64.RawURLEncoding.DecodeString(iDToken.iDTokenParts[1])
	if err != nil {
		return nil, err
	}

	iDTokenPayload := new(IDTokenPayload)
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

	//TBD
	//for _, option := range options {
	//	option(token)
	//}
	return iDToken, nil
}

//TBD
//type Option func(*Token) error
//
//func GrantType(grantType string) Option {
//	return func(token *Token) error {
//		token.grantType = grantType
//		return nil
//	}
//}

func (iDToken *IDToken) VerifyIDTokenHeader() error {
	if iDToken.iDTokenHeader.Type != "JWT" {
		return errors.New("unsupported header type")
	}
	if iDToken.iDTokenHeader.Algorithm != "RS256" {
		return errors.New("unsupported signature algorithm")
	}

	return nil
}

func (iDToken *IDToken) GetIDTokenHeader() *IDTokenHeader {
	return iDToken.iDTokenHeader
}

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

//TBD
func (iDToken *IDToken) GetIDTokenPayload() *IDTokenPayload {
	return iDToken.iDTokenPayload
}
