package attestation

import "context"

type Quote struct {
	Nonce       string
	ConfigHash  string
	Measurement string
	Signature   []byte
	ReportData  []byte
}

type Verifier interface {
	Verify(ctx context.Context, q Quote) error
}
