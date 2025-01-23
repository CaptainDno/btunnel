package utils

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"math/big"
)

func NewGCM(key []byte) (gcm cipher.AEAD, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func GenerateRandomInt(min, max int) (int, error) {
	if min > max {
		return 0, fmt.Errorf("min should be less than or equal to max")
	}

	// Calculate the range
	rangeSize := max - min + 1

	// Generate a cryptographically secure random number in [0, rangeSize)
	nBig, err := crand.Int(crand.Reader, big.NewInt(int64(rangeSize)))
	if err != nil {
		return 0, err
	}

	// Offset by the minimum value
	return int(nBig.Int64()) + min, nil
}
