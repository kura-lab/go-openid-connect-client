package logouttoken

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

	"github.com/kura-lab/go-openid-connect-client/pkg/jwks"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	mystring "github.com/kura-lab/go-openid-connect-client/pkg/strings"
)

// Header is struct for decoded Logout Token Header.
type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

// Payload is struct for decoded Logout Token Payload.
type Payload struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub"`
	Audience    []string
	RawAudience json.RawMessage `json:"aud"`
	IssuedAt    int             `json:"iat"`
	Nonce       string          `json:"nonce"`
	JWTID       string          `json:"jti"`
	Events      json.RawMessage `json:"http://schemas.openid.net/event/backchannel-logout"`
	SessionID   string          `json:"sid"`
}

// LogoutToken is struct for Logout Token.
type LogoutToken struct {
	oIDCConfig               oidcconfig.Response
	logoutTokenParts         []string
	logoutTokenHeader        *Header
	logoutTokenPayload       *Payload
	decodedSignature         []byte
	expectedIssuer           string
	expectedAudience         string
	expectedDurationIssuedAt int
}

// NewLogoutToken is LogoutToken constructor function.
func NewLogoutToken(oIDCConfig oidcconfig.Response, rawLogoutToken string) (*LogoutToken, error) {
	logoutToken := new(LogoutToken)
	logoutToken.oIDCConfig = oIDCConfig

	logoutToken.logoutTokenParts = strings.SplitN(rawLogoutToken, ".", 3)

	header, err := base64.RawURLEncoding.DecodeString(logoutToken.logoutTokenParts[0])
	if err != nil {
		return nil, err
	}
	logoutTokenHeader := new(Header)
	err = json.Unmarshal(header, logoutTokenHeader)
	if err != nil {
		return nil, err
	}
	logoutToken.logoutTokenHeader = logoutTokenHeader

	decodedPayload, err := base64.RawURLEncoding.DecodeString(logoutToken.logoutTokenParts[1])
	if err != nil {
		return nil, err
	}

	logoutTokenPayload := new(Payload)
	err = json.Unmarshal(decodedPayload, logoutTokenPayload)
	if err != nil {
		return nil, err
	}

	if logoutTokenPayload.RawAudience != nil {
		if err := json.Unmarshal(logoutTokenPayload.RawAudience, &logoutTokenPayload.Audience); err != nil {
			var audString string
			if err := json.Unmarshal(logoutTokenPayload.RawAudience, &audString); err != nil {
				return nil, errors.New("unexpected type of aud claim. it assumes array type of string or string type")
			}
			logoutTokenPayload.Audience = append(logoutTokenPayload.Audience, audString)
		}
	}

	logoutToken.logoutTokenPayload = logoutTokenPayload

	decodedSignature, err := base64.RawURLEncoding.DecodeString(logoutToken.logoutTokenParts[2])
	if err != nil {
		return nil, err
	}
	logoutToken.decodedSignature = decodedSignature

	return logoutToken, nil
}

// VerifyLogoutTokenHeader is method to verify Logout Token Header.
func (logoutToken *LogoutToken) VerifyLogoutTokenHeader() error {

	if logoutToken.logoutTokenHeader.Type != "" && logoutToken.logoutTokenHeader.Type != "JWT" {
		return errors.New("unsupported header type. id token type supported by OpenID Connect is JWT, " +
			"actual type in id token's header is " + logoutToken.logoutTokenHeader.Type)
	}

	if !mystring.Contains(
		logoutToken.logoutTokenHeader.Algorithm,
		logoutToken.oIDCConfig.IDTokenSigningAlgValuesSupported,
	) {
		return errors.New("unsupported signature algorithm. actual algorithm in id token's header is " +
			logoutToken.logoutTokenHeader.Algorithm + ". supported signing algorithm is " +
			fmt.Sprintf("%v", logoutToken.oIDCConfig.IDTokenSigningAlgValuesSupported))
	}

	return nil
}

// GetLogoutTokenHeader is method to getter of Header struct.
func (logoutToken *LogoutToken) GetLogoutTokenHeader() *Header {
	return logoutToken.logoutTokenHeader
}

// VerifySignature is method to verify Logout Token signature.
func (logoutToken *LogoutToken) VerifySignature(jWKsResponse jwks.Response) error {
	switch logoutToken.logoutTokenHeader.Algorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		publicKey, err := logoutToken.generateRSAPublicKey(jWKsResponse)
		if err != nil {
			return err
		}
		return logoutToken.verifyRSASignature(publicKey)
	case "ES256", "ES384", "ES512":
		publicKey, err := logoutToken.generateECDSAPublicKey(jWKsResponse)
		if err != nil {
			return err
		}
		return logoutToken.verifyECDSASignature(publicKey)
	}

	return errors.New("unsupported signature algorithm. actual algorithm is " +
		logoutToken.logoutTokenHeader.Algorithm + ". you should call VerifyLogoutTokenHeader before call VerifySignature")
}

func (logoutToken *LogoutToken) generateRSAPublicKey(jWKsResponse jwks.Response) (rsa.PublicKey, error) {
	var modulus, exponent string
	for _, keySet := range jWKsResponse.KeySets {
		if keySet.KeyID == logoutToken.logoutTokenHeader.KeyID {

			if keySet.Use != "sig" {
				return rsa.PublicKey{}, errors.New("invalid use. actual use in JWK set is " + keySet.Use + ". the use should be sig")
			} else if keySet.KeyType != "RSA" {
				return rsa.PublicKey{}, errors.New("invalid key type. actual key type in JWK set is " + keySet.KeyType + ". it's not match type in header")
			} else if keySet.Algorithm != "" && keySet.Algorithm != logoutToken.logoutTokenHeader.Algorithm {
				return rsa.PublicKey{}, errors.New("invalid algorithm. actual algorithm in JWK set is " + keySet.Algorithm + ". it's not match algorithm in header")
			}

			modulus = keySet.Modulus
			exponent = keySet.Exponent
			break
		}
	}
	if modulus == "" || exponent == "" {
		return rsa.PublicKey{}, errors.New("failed to extract modulus or exponent. they might be empty in JWK set")
	}

	decodedModulus, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	decodedExponent, err := base64.RawURLEncoding.DecodeString(exponent)
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

func (logoutToken *LogoutToken) generateECDSAPublicKey(jWKsResponse jwks.Response) (ecdsa.PublicKey, error) {
	var encodedX, encodedY, curveAlgorithm string
	for _, keySet := range jWKsResponse.KeySets {
		if keySet.KeyID == logoutToken.logoutTokenHeader.KeyID {

			if keySet.Use != "sig" {
				return ecdsa.PublicKey{}, errors.New("invalid use. actual use in JWK set is " + keySet.Use + ". the use should be sig")
			} else if keySet.KeyType != "EC" {
				return ecdsa.PublicKey{}, errors.New("invalid key type. actual key type in JWK set is " + keySet.KeyType + ". it's not match type in header")
			} else if keySet.Algorithm != logoutToken.logoutTokenHeader.Algorithm {
				return ecdsa.PublicKey{}, errors.New("invalid algorithm. actual algorithm in JWK set is " + keySet.Algorithm + ". it's not match algorithm in header")
			}

			encodedX = keySet.XCoordinate
			encodedY = keySet.YCoordinate
			curveAlgorithm = keySet.Curve
			break
		}
	}
	if encodedX == "" || encodedY == "" {
		return ecdsa.PublicKey{}, errors.New("failed to extract x or y coordinates. they might be empty in JWK set")
	}

	decodedX, err := base64.RawURLEncoding.DecodeString(encodedX)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	decodedY, err := base64.RawURLEncoding.DecodeString(encodedY)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}

	var x, y *big.Int
	x = new(big.Int).SetBytes(decodedX)
	y = new(big.Int).SetBytes(decodedY)

	var curve elliptic.Curve
	if curveAlgorithm == "P-256" {
		curve = elliptic.P256()
	} else if curveAlgorithm == "P-384" {
		curve = elliptic.P384()
	} else if curveAlgorithm == "P-521" {
		curve = elliptic.P521()
	} else {
		return ecdsa.PublicKey{}, errors.New("unsupported curve algorithm. actual algorithm in jwk set is " + curveAlgorithm)
	}

	return ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func (logoutToken *LogoutToken) verifyRSASignature(publicKey rsa.PublicKey) error {
	var hashType crypto.Hash
	switch logoutToken.logoutTokenHeader.Algorithm {
	case "RS256", "PS256":
		hashType = crypto.SHA256
	case "RS384", "PS384":
		hashType = crypto.SHA384
	case "RS512", "PS512":
		hashType = crypto.SHA512
	default:
		return errors.New("unsupported signing algorithm. actual algorithm in id token's header is " + logoutToken.logoutTokenHeader.Algorithm)
	}

	hash := crypto.Hash.New(hashType)
	if _, err := hash.Write([]byte(logoutToken.logoutTokenParts[0] + "." + logoutToken.logoutTokenParts[1])); err != nil {
		return err
	}

	switch logoutToken.logoutTokenHeader.Algorithm {
	case "RS256", "RS384", "RS512":
		return rsa.VerifyPKCS1v15(&publicKey, hashType, hash.Sum(nil), logoutToken.decodedSignature)
	case "PS256", "PS384", "PS512":
		return rsa.VerifyPSS(&publicKey, hashType, hash.Sum(nil), logoutToken.decodedSignature, nil)
	}

	return errors.New("unexpected varification error. never reach here")
}

func (logoutToken *LogoutToken) verifyECDSASignature(publicKey ecdsa.PublicKey) error {
	var keySize int
	var hash hash.Hash
	switch logoutToken.logoutTokenHeader.Algorithm {
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

	if _, err := hash.Write([]byte(logoutToken.logoutTokenParts[0] + "." + logoutToken.logoutTokenParts[1])); err != nil {
		return err
	}

	parsedR := big.NewInt(0).SetBytes(logoutToken.decodedSignature[:keySize])
	parsedS := big.NewInt(0).SetBytes(logoutToken.decodedSignature[keySize:])

	if !ecdsa.Verify(&publicKey, hash.Sum(nil), parsedR, parsedS) {
		return errors.New("invalid ecdsa signature. the id token might be altered by attakers")
	}

	return nil
}

// Option is functional option for VerifyPayload function initialization.
type Option func(*LogoutToken) error

// Issuer is functional option to add expected issuer.
func Issuer() Option {
	return func(logoutToken *LogoutToken) error {
		logoutToken.expectedIssuer = logoutToken.oIDCConfig.Issuer
		return nil
	}
}

// Audience is functional option to add expected audience.
func Audience(audience string) Option {
	return func(logoutToken *LogoutToken) error {
		logoutToken.expectedAudience = audience
		return nil
	}
}

// DurationIssuedAt is functional option to add expected duration of issued at.
func DurationIssuedAt(duration int) Option {
	return func(logoutToken *LogoutToken) error {
		logoutToken.expectedDurationIssuedAt = duration
		return nil
	}
}

// VerifyPayloadClaims is method to verify claims included Logout Token payload.
func (logoutToken *LogoutToken) VerifyPayloadClaims(options ...Option) error {
	for _, option := range options {
		option(logoutToken)
	}

	if logoutToken.expectedIssuer != "" {
		if logoutToken.expectedIssuer != logoutToken.logoutTokenPayload.Issuer {
			return errors.New("invalid issuer. actual isser in id token's payload is " +
				logoutToken.logoutTokenPayload.Issuer + ". expected issuer is " + logoutToken.expectedIssuer)
		}
	}

	if logoutToken.expectedAudience != "" {
		if !mystring.Contains(logoutToken.expectedAudience, logoutToken.logoutTokenPayload.Audience) {
			return errors.New("invalid audience. actual audience in id token's payload is " +
				fmt.Sprintf("%v", logoutToken.logoutTokenPayload.Audience) + ". expected audience is " + logoutToken.expectedAudience)
		}
	}

	if logoutToken.expectedDurationIssuedAt != 0 {
		currentTime := int(time.Now().Unix())
		if currentTime-logoutToken.logoutTokenPayload.IssuedAt > logoutToken.expectedDurationIssuedAt {
			return errors.New("issued at is too far away from current time. actual issued at in id token's payload is " +
				fmt.Sprintf("%d", logoutToken.logoutTokenPayload.IssuedAt) + "(unix timestamp). " +
				fmt.Sprintf("%d", (currentTime-logoutToken.logoutTokenPayload.IssuedAt-logoutToken.expectedDurationIssuedAt)) + " seconds have passed")
		}
	}

	if logoutToken.logoutTokenPayload.Nonce != "" {
		return errors.New("contain nonce. logout token does not contain nonce. nonce: " + logoutToken.logoutTokenPayload.Nonce)
	}

	return nil
}

// GetLogoutTokenPayload is method to getter of Payload struct.
func (logoutToken *LogoutToken) GetLogoutTokenPayload() *Payload {
	return logoutToken.logoutTokenPayload
}
