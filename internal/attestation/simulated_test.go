package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestSimulatedVerify(t *testing.T) {
	nonceStore := NewNonceStore(time.Minute)
	nonceString, err := nonceStore.Issue()
	if err != nil {
		t.Fatalf("issue nonce: %v", err)
	}
	nonce, err := hex.DecodeString(nonceString)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	configHash := []byte("config-hash")
	reportData := sha256.Sum256(append(append([]byte{}, nonce...), configHash...))

	validQuote := Quote{
		Nonce:      nonceString,
		ConfigHash: hex.EncodeToString(configHash),
		Signature:  []byte("signature"),
		ReportData: reportData[:],
	}

	tests := []struct {
		name    string
		quote   Quote
		wantErr bool
	}{
		{name: "valid quote", quote: validQuote},
		{name: "missing signature", quote: Quote{Nonce: validQuote.Nonce, ConfigHash: validQuote.ConfigHash, ReportData: validQuote.ReportData}, wantErr: true},
		{name: "wrong report data", quote: Quote{Nonce: validQuote.Nonce, ConfigHash: validQuote.ConfigHash, Signature: validQuote.Signature, ReportData: []byte("wrong")}, wantErr: true},
		{name: "invalid nonce", quote: Quote{Nonce: "not-hex", ConfigHash: validQuote.ConfigHash, Signature: validQuote.Signature, ReportData: validQuote.ReportData}, wantErr: true},
	}

	verifier := NewSimulatedVerifier(nonceStore)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifier.Verify(context.Background(), test.quote)
			if (err != nil) != test.wantErr {
				t.Fatalf("Verify() error = %v, want error: %t", err, test.wantErr)
			}
		})
	}

	t.Run("replayed nonce", func(t *testing.T) {
		err := verifier.Verify(context.Background(), validQuote)
		if err == nil {
			t.Fatal("Verify() accepted a replayed nonce")
		}
		if !strings.Contains(err.Error(), "unknown nonce") {
			t.Fatalf("Verify() error = %v, want unknown nonce error", err)
		}
	})
}
