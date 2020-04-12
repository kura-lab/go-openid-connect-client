package hash

import (
	"crypto/sha256"
	"encoding/base64"
)

func GenerateHalfOfSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	halfOfHash := hash[:len(hash)/2]
	return base64.RawURLEncoding.EncodeToString(halfOfHash)
}

func GenerateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:len(hash)])
}
