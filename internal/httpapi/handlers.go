package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"attestation-vault/internal/attestation"
	"attestation-vault/internal/secret"
)

type Handlers struct {
	Nonces  *attestation.NonceStore
	Secrets *secret.Service
}

// POST /api/v1/attest/challenge
func (h *Handlers) Challenge(w http.ResponseWriter, r *http.Request) {
	nonce, err := h.Nonces.Issue()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
}

type releaseRequest struct {
	Name  string `json:"name"`
	Quote struct {
		Nonce       string `json:"nonce"`
		ConfigHash  string `json:"config_hash"`
		Measurement string `json:"measurement"`
		Signature   string `json:"signature"`
		ReportData  string `json:"report_data"`
	} `json:"quote"`
	ClientPubkey string `json:"client_pubkey"` // hex
}

// POST /api/v1/attest/release
func (h *Handlers) Release(w http.ResponseWriter, r *http.Request) {
	var req releaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}

	sig, _ := hex.DecodeString(req.Quote.Signature)
	rd, _ := hex.DecodeString(req.Quote.ReportData)
	clientPub, err := hex.DecodeString(req.ClientPubkey)
	if err != nil {
		http.Error(w, "bad pubkey", 400)
		return
	}

	q := attestation.Quote{
		Nonce:       req.Quote.Nonce,
		ConfigHash:  req.Quote.ConfigHash,
		Measurement: req.Quote.Measurement,
		Signature:   sig,
		ReportData:  rd,
	}

	ciphertext, serverPub, err := h.Secrets.Release(r.Context(), req.Name, q, clientPub)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"ciphertext":    hex.EncodeToString(ciphertext),
		"server_pubkey": hex.EncodeToString(serverPub),
	})
}
