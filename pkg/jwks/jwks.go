package jwks

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
)

type JWKsResponse struct {
	KeySets []struct {
		KeyID     string `json:"kid"`
		KeyType   string `json:"kty"`
		Algorithm string `json:"alg"`
		Use       string `json:"use"`
		Modulus   string `json:"n"`
		Exponent  string `json:"e"`
	} `json:"keys"`
}

type JWKs struct {
	oidcconfig *oidcconfig.OIDCConfig
	keyID      string
	algorithm  string
}

func NewJWKs(oidcconfig *oidcconfig.OIDCConfig, keyID string, algorithm string) *JWKs {
	jWKs := new(JWKs)
	jWKs.oidcconfig = oidcconfig
	jWKs.keyID = keyID
	jWKs.algorithm = algorithm

	return jWKs
}

func (jWKs *JWKs) Request() (rsa.PublicKey, error) {
	response, err := http.Get(jWKs.oidcconfig.JWKsURI())
	if err != nil {
		return rsa.PublicKey{}, err
	}
	defer func() {
		_, err = io.Copy(ioutil.Discard, response.Body)
		if err != nil {
			log.Panic(err)
		}
		err = response.Body.Close()
		if err != nil {
			log.Panic(err)
		}
	}()

	var jWKsResponse JWKsResponse
	err = json.NewDecoder(response.Body).Decode(&jWKsResponse)
	if err != nil {
		return rsa.PublicKey{}, err
	}

	var modulus, exponent string
	for _, keySet := range jWKsResponse.KeySets {
		if keySet.KeyID == jWKs.keyID {
			if keySet.Use != "sig" || keySet.KeyType != "RSA" || keySet.Algorithm != jWKs.algorithm {
				return rsa.PublicKey{}, err
			}
			modulus = keySet.Modulus
			exponent = keySet.Exponent
			break
		}
	}
	if modulus == "" || exponent == "" {
		return rsa.PublicKey{}, err
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
