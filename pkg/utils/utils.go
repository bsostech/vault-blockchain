package utils

import (
	"crypto/ecdsa"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum/common/math"
)

// ZeroKey removes the key from memory
func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

// ValidNumber returns a valid positive integer
func ValidNumber(input string) *big.Int {
	if input == "" {
		return big.NewInt(0)
	}
	matched, err := regexp.MatchString("([0-9])", input)
	if !matched || err != nil {
		return nil
	}
	amount := math.MustParseBig256(input)
	return amount.Abs(amount)
}
