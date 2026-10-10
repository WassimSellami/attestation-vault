package secret

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"attestation-vault/internal/attestation"
	"attestation-vault/internal/crypto"
	"attestation-vault/internal/policy"
)

type storedSecret struct {
	name       string
	ciphertext []byte
	wrappedKey []byte
	dataKey    []byte
}

type Service struct {
	masterKey []byte
	store     map[string]*storedSecret
	engine    *policy.Engine
	verifier  attestation.Verifier
}

func New(masterKey []byte, engine *policy.Engine, v attestation.Verifier) *Service {
	return &Service{
		masterKey: masterKey,
		store:     map[string]*storedSecret{},
		engine:    engine,
		verifier:  v,
	}
}

func (s *Service) Store(name, value string) error {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return fmt.Errorf("generate data key: %w", err)
	}

	ct, err := crypto.Encrypt(dataKey, []byte(value))
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}

	wrapped, err := crypto.Encrypt(s.masterKey, dataKey)
	if err != nil {
		return fmt.Errorf("wrap data key: %w", err)
	}

	s.store[name] = &storedSecret{
		name:       name,
		ciphertext: ct,
		wrappedKey: wrapped,
		dataKey:    dataKey, // MVP only
	}
	return nil
}

func (s *Service) Release(ctx context.Context, name string, q attestation.Quote, clientPub []byte) ([]byte, []byte, error) {
	// 1. Verify attestation (consume nonce).
	if err := s.verifier.Verify(ctx, q); err != nil {
		return nil, nil, fmt.Errorf("attestation: %w", err)
	}

	// 2. Authorize.
	if err := s.engine.Authorize(name, q.Measurement, q.ConfigHash); err != nil {
		return nil, nil, fmt.Errorf("policy: %w", err)
	}

	// 3. Fetch.
	rec, ok := s.store[name]
	if !ok {
		return nil, nil, fmt.Errorf("secret %q not found", name)
	}

	// 4. Decrypt value locally.
	value, err := crypto.Decrypt(rec.dataKey, rec.ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt: %w", err)
	}

	// 5. Derive shared key with client's ephemeral pubkey.
	serverPub, serverPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	sharedKey, err := crypto.DeriveSharedKey(serverPriv, clientPub)
	if err != nil {
		return nil, nil, err
	}

	// 6. Re-encrypt for the client.
	out, err := crypto.Encrypt(sharedKey, value)
	if err != nil {
		return nil, nil, err
	}

	return out, serverPub, nil
}

// helper for hash binding (used by tests)
func HashNonceConfig(nonceHex, configHashHex string) []byte {
	n, _ := hex.DecodeString(nonceHex)
	c, _ := hex.DecodeString(configHashHex)
	h := sha256.New()
	h.Write(n)
	h.Write(c)
	return h.Sum(nil)
}
