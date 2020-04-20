package hash

import (
	"crypto/sha256"
	"encoding/base64"
)

// GenerateHalfOfSHA256 is function to generate URL-safe encoded half of SHA-256 hash.
func GenerateHalfOfSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	halfOfHash := hash[:len(hash)/2]
	return base64.RawURLEncoding.EncodeToString(halfOfHash)
}

// GenerateSHA256 is function to generate URL-safe encoded SHA-256 hash.
func GenerateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:len(hash)])
}
