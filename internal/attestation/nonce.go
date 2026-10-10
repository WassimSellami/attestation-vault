package attestation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

type nonceStore struct {
	mu     sync.Mutex
	issued map[string]time.Time
	ttl    time.Duration
}

func NewNonceStore(ttl time.Duration) *nonceStore {
	return &nonceStore{
		issued: make(map[string]time.Time),
		ttl:    ttl,
	}
}

func (s *nonceStore) Issue() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(buf)

	s.mu.Lock()
	s.issued[nonce] = time.Now()
	s.mu.Unlock()

	return nonce, nil
}

func (s *nonceStore) Consume(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	issuedAt, ok := s.issued[nonce]
	if !ok {
		return fmt.Errorf("unknown nonce")
	}
	delete(s.issued, nonce)

	if time.Since(issuedAt) > s.ttl {
		return fmt.Errorf("nonce expired")
	}
	return nil
}

func (s *nonceStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for n, t := range s.issued {
		if now.Sub(t) > s.ttl {
			delete(s.issued, n)
		}
	}
}
