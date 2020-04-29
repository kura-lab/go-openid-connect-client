package idtoken

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	myhash "github.com/kura-lab/go-openid-connect-client/pkg/hash"
	"github.com/kura-lab/go-openid-connect-client/pkg/jwks"
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
	expectedDurationIssuedAt           int
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
		return errors.New("unsupported header type. id token type supported by OpenID Connect is JWT, " +
			"actual type in id token's header is " + iDToken.iDTokenHeader.Type + ".")
	}
	if !mystring.Contains(
		iDToken.iDTokenHeader.Algorithm,
		iDToken.oidcconfig.IDTokenSigningAlgValuesSupported(),
	) {
		return errors.New("unsupported signature algorithm. actual algorithm in id token's header is " +
			iDToken.iDTokenHeader.Algorithm + ". supported signing algorithm is " +
			fmt.Sprintf("%v", iDToken.oidcconfig.IDTokenSigningAlgValuesSupported()) + ".")
	}

	return nil
}

// GetIDTokenHeader is method to getter of Header struct.
func (iDToken *IDToken) GetIDTokenHeader() *Header {
	return iDToken.iDTokenHeader
}

// VerifySignature is method to verify ID Token signature.
func (iDToken *IDToken) VerifySignature(jWKsResponse jwks.Response) error {
	switch iDToken.iDTokenHeader.Algorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		publicKey, err := iDToken.generateRSAPublicKey(jWKsResponse)
		if err != nil {
			return err
		}
		return iDToken.verifyRSASignature(publicKey)
	case "ES256", "ES384", "ES512":
		publicKey, err := iDToken.generateECDSAPublicKey(jWKsResponse)
		if err != nil {
			return err
		}
		return iDToken.verifyECDSASignature(publicKey)
	}

	return errors.New("unsupported signature algorithm. actual algorithm is " +
		iDToken.iDTokenHeader.Algorithm + ". you should call VerifyIDTokenHeader before call VerifySignature.")
}

func (iDToken *IDToken) generateRSAPublicKey(jWKsResponse jwks.Response) (rsa.PublicKey, error) {
	var modulus, exponent string
	for _, keySet := range jWKsResponse.KeySets {
		if keySet.KeyID == iDToken.iDTokenHeader.KeyID {

			if keySet.Use != "sig" {
				return rsa.PublicKey{}, errors.New("invalid use. actual use in JWK set is " + keySet.Use + ". the use should be sig.")
			} else if keySet.KeyType != "RSA" {
				return rsa.PublicKey{}, errors.New("invalid key type. actual key type in JWK set is " + keySet.KeyType + ". it's not match type in header.")
			} else if keySet.Algorithm != iDToken.iDTokenHeader.Algorithm {
				return rsa.PublicKey{}, errors.New("invalid algorithm. actual algorithm in JWK set is " + keySet.Algorithm + ". it's not match algorithm in header.")
			}

			modulus = keySet.Modulus
			exponent = keySet.Exponent
			break
		}
	}
	if modulus == "" || exponent == "" {
		return rsa.PublicKey{}, errors.New("failed to extract modulus or exponent. they might be empty in JWK set.")
	}

	decodedModulus, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	decodedExponent, err := base64.StdEncoding.DecodeString(exponent)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	var exponentBytes []byte
	if len(decodedExponent) < 8 {
		exponentBytes = make([]byte, 8-len(decodedExponent), 8)
		exponentBytes = append(exponentBytes, decodedExponent...)
	} else {
		exponentBytes = decodedExponent
	}
	reader := bytes.NewReader(exponentBytes)
	var e uint64
	err = binary.Read(reader, binary.BigEndian, &e)
	if err != nil {
		return rsa.PublicKey{}, err
	}

	return rsa.PublicKey{N: big.NewInt(0).SetBytes(decodedModulus), E: int(e)}, nil
}

func (iDToken *IDToken) generateECDSAPublicKey(jWKsResponse jwks.Response) (ecdsa.PublicKey, error) {
	var encodedX, encodedY string
	for _, keySet := range jWKsResponse.KeySets {
		if keySet.KeyID == iDToken.iDTokenHeader.KeyID {

			if keySet.Use != "sig" {
				return ecdsa.PublicKey{}, errors.New("invalid use. actual use in JWK set is " + keySet.Use + ". the use should be sig.")
			} else if keySet.KeyType != "EC" {
				return ecdsa.PublicKey{}, errors.New("invalid key type. actual key type in JWK set is " + keySet.KeyType + ". it's not match type in header.")
			} else if keySet.Algorithm != iDToken.iDTokenHeader.Algorithm {
				return ecdsa.PublicKey{}, errors.New("invalid algorithm. actual algorithm in JWK set is " + keySet.Algorithm + ". it's not match algorithm in header.")
			}

			encodedX = keySet.XCoordinate
			encodedY = keySet.YCoordinate
			break
		}
	}
	if encodedX == "" || encodedY == "" {
		return ecdsa.PublicKey{}, errors.New("failed to extract x or y coordinates. they might be empty in JWK set.")
	}

	decodedX, err := base64.RawURLEncoding.DecodeString(encodedX)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	decodedY, err := base64.StdEncoding.DecodeString(encodedY)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	var x, y *big.Int
	x = x.SetBytes(decodedX)
	y = y.SetBytes(decodedY)

	var curve elliptic.Curve
	if iDToken.iDTokenHeader.Algorithm == "ES256" {
		curve = elliptic.P256()
	} else if iDToken.iDTokenHeader.Algorithm == "ES384" {
		curve = elliptic.P384()
	} else if iDToken.iDTokenHeader.Algorithm == "ES512" {
		curve = elliptic.P521()
	} else {
		return ecdsa.PublicKey{}, errors.New("unsupported signature algorithm. actual algorithm in id token's header is " + iDToken.iDTokenHeader.Algorithm + ".")
	}

	return ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func (iDToken *IDToken) verifyRSASignature(publicKey rsa.PublicKey) error {
	var hashType crypto.Hash
	switch iDToken.iDTokenHeader.Algorithm {
	case "RS256", "PS256":
		hashType = crypto.SHA256
	case "RS384", "PS384":
		hashType = crypto.SHA384
	case "RS512", "PS512":
		hashType = crypto.SHA512
	default:
		return errors.New("unsupported signing algorithm. actual algorithm in id token's header is " + iDToken.iDTokenHeader.Algorithm + ".")
	}

	hash := crypto.Hash.New(hashType)
	if _, err := hash.Write([]byte(iDToken.iDTokenParts[0] + "." + iDToken.iDTokenParts[1])); err != nil {
		return err
	}

	switch iDToken.iDTokenHeader.Algorithm {
	case "RS256", "RS384", "RS512":
		return rsa.VerifyPKCS1v15(&publicKey, hashType, hash.Sum(nil), iDToken.decodedSignature)
	case "PS256", "PS384", "PS512":
		return rsa.VerifyPSS(&publicKey, hashType, hash.Sum(nil), iDToken.decodedSignature, nil)
	}

	return errors.New("unexpected varification error. never reach here.")
}

func (iDToken *IDToken) verifyECDSASignature(publicKey ecdsa.PublicKey) error {
	var keySize int
	var hash hash.Hash
	switch iDToken.iDTokenHeader.Algorithm {
	case "ES256":
		keySize = 32
		hash = crypto.SHA256.New()
	case "ES384":
		keySize = 48
		hash = crypto.SHA384.New()
	case "ES512":
		keySize = 66
		hash = crypto.SHA512.New()
	}

	if _, err := hash.Write([]byte(iDToken.iDTokenParts[0] + "." + iDToken.iDTokenParts[1])); err != nil {
		return err
	}

	parsedR := big.NewInt(0).SetBytes(iDToken.decodedSignature[:keySize])
	parsedS := big.NewInt(0).SetBytes(iDToken.decodedSignature[keySize:])

	if !ecdsa.Verify(&publicKey, hash.Sum(nil), parsedR, parsedS) {
		return errors.New("invalid ecdsa signature. the id token might be altered by attakers.")
	}

	return nil
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

// DurationIssuedAt is functional option to add expected duration of issued at.
func DurationIssuedAt(duration int) Option {
	return func(iDToken *IDToken) error {
		iDToken.expectedDurationIssuedAt = duration
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
			return errors.New("invalid issuer. actual isser in id token's payload is " +
				iDToken.iDTokenPayload.Issuer + ". expected issuer is " + iDToken.expectedIssuer + ".")
		}
	}

	if iDToken.expectedAudience != "" {
		if !mystring.Contains(iDToken.expectedAudience, iDToken.iDTokenPayload.Audience) {
			return errors.New("invalid audience. actual audience in id token's payload is " +
				fmt.Sprintf("%v", iDToken.iDTokenPayload.Audience) + ". expected audience is " + iDToken.expectedAudience + ".")
		}
	}

	if iDToken.expectedNonce != "" {
		if iDToken.expectedNonce != iDToken.iDTokenPayload.Nonce {
			return errors.New("invalid nonce. actual nonce in id token's payload is " +
				iDToken.iDTokenPayload.Nonce + ". attakers might replay attack(playback attack).")
		}
	}

	if iDToken.expectedDurationIssuedAt != 0 {
		currentTime := int(time.Now().Unix())
		if currentTime-iDToken.iDTokenPayload.IssuedAt > iDToken.expectedDurationIssuedAt {
			return errors.New("issued at is too far away from current time. actual issued at in id token's payload is " +
				fmt.Sprintf("%d", iDToken.iDTokenPayload.IssuedAt) + "(unix timestamp). " +
				fmt.Sprintf("%d", (currentTime-iDToken.iDTokenPayload.IssuedAt-iDToken.expectedDurationIssuedAt)) + " seconds have passed.")
		}
	}

	if iDToken.expectedAccessTokenAccessTokenHash != "" {
		aTHash := myhash.GenerateHalfOfSHA256(iDToken.expectedAccessTokenAccessTokenHash)
		if aTHash != iDToken.iDTokenPayload.AccessTokenHash {
			return errors.New("invalid access token hash. actual hash in id token's payload is " +
				iDToken.iDTokenPayload.AccessTokenHash + ". expected hash is " + aTHash + ". the access token issued with id token might be altered by attakers.")
		}
	}

	return nil
}

// GetIDTokenPayload is method to getter of Payload struct.
func (iDToken *IDToken) GetIDTokenPayload() *Payload {
	return iDToken.iDTokenPayload
}
