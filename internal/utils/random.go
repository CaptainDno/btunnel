package utils

import (
	mrand "math/rand"
)

func GenerateRandomDigits(n int) string {
	const digits = "0123456789"
	result := make([]byte, n)
	for i := range result {
		// Generate a random index
		randomIndex := mrand.Intn(len(digits))
		result[i] = digits[randomIndex]
	}

	return string(result)
}
