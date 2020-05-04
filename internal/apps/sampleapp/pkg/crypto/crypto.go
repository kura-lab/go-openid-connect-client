package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	myrand "github.com/kura-lab/go-openid-connect-client/internal/apps/sampleapp/pkg/rand"
)

func GenerateRandomAESKey128bit() []byte {
	return []byte(myrand.GenerateRandomString(16))
}

func GenerateRandomAESKey192bit() []byte {
	return []byte(myrand.GenerateRandomString(24))
}

func GenerateRandomAESKey256bit() []byte {
	return []byte(myrand.GenerateRandomString(32))
}

func EnctyptAESToString(key []byte, src []byte) string {
	src = padPKCS7(src)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encrypted := make([]byte, aes.BlockSize+len(src))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	encryptMode := cipher.NewCBCEncrypter(block, iv)
	encryptMode.CryptBlocks(encrypted[aes.BlockSize:], src)

	return string(encrypted)
}

func DecryptAESToString(key []byte, iv []byte, src []byte, size int) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	decryptMode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, size)
	encrypted := src
	decryptMode.CryptBlocks(decrypted, encrypted[aes.BlockSize:])

	return string(unpadPKCS7(decrypted))
}

// PKCS7#Padding: 1-255byte block size padding
func padPKCS7(b []byte) []byte {
	padSize := aes.BlockSize - (len(b) % aes.BlockSize)
	fmt.Printf("aes.BlockSize: %d\n", aes.BlockSize) // 16
	fmt.Printf("padSize      : %d\n", padSize)
	padded := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(b, padded...)
}

func unpadPKCS7(b []byte) []byte {
	padSize := int(b[len(b)-1])
	return b[:len(b)-padSize]
}
