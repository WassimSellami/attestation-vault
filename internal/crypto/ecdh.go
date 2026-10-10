package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const sharedKeyInfo = "attestation-vault"

func GenerateKeyPair() (pub, priv []byte, err error) {
	priv = make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive public key: %w", err)
	}

	return pub, priv, nil
}

func DeriveSharedKey(priv, peerPub []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sharedSecret, nil, []byte(sharedKeyInfo)), key); err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}

	return key, nil
}
