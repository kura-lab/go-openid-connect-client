package rand

import (
	"math/rand"
	"time"
)

// GenerateRandomString is function to generate ramdom string.
func GenerateRandomString(number int) string {
	rand.Seed(time.Now().UnixNano())
	letters := getLetters()
	result := make([]rune, number)
	for i := range result {
		result[i] = letters[rand.Intn(len(letters))]
	}
	return string(result)
}

func getLetters() []rune {
	return []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}
