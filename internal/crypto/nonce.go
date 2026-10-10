package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

func NewNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}
