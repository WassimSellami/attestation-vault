package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"attestation-vault/internal/crypto"
)

const serverURL = "http://localhost:8080"

type challengeResponse struct {
	Nonce string `json:"nonce"`
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
	ClientPubkey string `json:"client_pubkey"`
}

type releaseResponse struct {
	Ciphertext string `json:"ciphertext"`
	ServerPub  string `json:"server_pubkey"`
}

func main() {
	challenge, err := postJSON[challengeResponse]("/api/v1/attest/challenge", nil)
	if err != nil {
		panic(fmt.Errorf("request challenge: %w", err))
	}

	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil {
		panic(fmt.Errorf("decode nonce: %w", err))
	}
	fmt.Printf("nonce: %x\n", nonce)
	configHash := []byte("config-hash")
	reportData := sha256.Sum256(append(append([]byte{}, nonce...), configHash...))

	clientPub, clientPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		panic(fmt.Errorf("generate client key pair: %w", err))
	}

	request := releaseRequest{Name: "stripe-key"}
	request.Quote.Nonce = challenge.Nonce
	request.Quote.ConfigHash = hex.EncodeToString(configHash)
	request.Quote.Measurement = "deadbeef"
	request.Quote.Signature = hex.EncodeToString([]byte("signature"))
	request.Quote.ReportData = hex.EncodeToString(reportData[:])
	request.ClientPubkey = hex.EncodeToString(clientPub)

	release, err := postJSON[releaseResponse]("/api/v1/attest/release", request)
	if err != nil {
		panic(fmt.Errorf("release secret: %w", err))
	}

	serverPub, err := hex.DecodeString(release.ServerPub)
	if err != nil {
		panic(fmt.Errorf("decode server public key: %w", err))
	}
	sharedKey, err := crypto.DeriveSharedKey(clientPriv, serverPub)
	if err != nil {
		panic(fmt.Errorf("derive shared key: %w", err))
	}
	ciphertext, err := hex.DecodeString(release.Ciphertext)
	if err != nil {
		panic(fmt.Errorf("decode ciphertext: %w", err))
	}
	secret, err := crypto.Decrypt(sharedKey, ciphertext)
	if err != nil {
		panic(fmt.Errorf("decrypt secret: %w", err))
	}

	fmt.Println(string(secret))
}

func postJSON[T any](path string, request any) (T, error) {
	var response T
	body, err := json.Marshal(request)
	if err != nil {
		return response, err
	}

	responseBody, err := http.Post(serverURL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return response, err
	}
	defer responseBody.Body.Close()

	data, err := io.ReadAll(responseBody.Body)
	if err != nil {
		return response, err
	}
	if responseBody.StatusCode < http.StatusOK || responseBody.StatusCode >= http.StatusMultipleChoices {
		return response, fmt.Errorf("server returned %s: %s", responseBody.Status, data)
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return response, err
	}
	return response, nil
}
