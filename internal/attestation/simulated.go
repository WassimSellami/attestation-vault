package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

type SimulatedVerifier struct {
	nonceStore *NonceStore
}

func NewSimulatedVerifier(nonceStore *NonceStore) *SimulatedVerifier {
	return &SimulatedVerifier{nonceStore: nonceStore}
}

func (v *SimulatedVerifier) Verify(ctx context.Context, q Quote) error {
	if len(q.Signature) == 0 {
		return fmt.Errorf("missing signature")
	}
	nonce, err := hex.DecodeString(q.Nonce)
	if err != nil {
		return fmt.Errorf("bad nonce: %w", err)
	}

	configHash, err := hex.DecodeString(q.ConfigHash)
	if err != nil {
		return fmt.Errorf("bad config hash: %w", err)
	}

	h := sha256.New()
	h.Write(nonce)
	h.Write(configHash)
	expected := h.Sum(nil)

	if subtle.ConstantTimeCompare(expected, q.ReportData) != 1 {
		return fmt.Errorf("report_data does not bind nonce and config hash")
	}

	if v.nonceStore == nil {
		return fmt.Errorf("nonce store is not configured")
	}
	if err := v.nonceStore.Consume(q.Nonce); err != nil {
		return fmt.Errorf("consume nonce: %w", err)
	}

	return nil
}
