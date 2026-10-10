package main

import (
	"attestation-vault/internal/attestation"
	"attestation-vault/internal/httpapi"
	"attestation-vault/internal/policy"
	"attestation-vault/internal/secret"
	"crypto/rand"
	"log"
	"net/http"
	"time"
)

func main() {
	masterKey := make([]byte, 32)
	rand.Read(masterKey) // MVP: random each run. Prod: from env/KMS.

	nonces := attestation.NewNonceStore(60 * time.Second)
	verifier := attestation.NewSimulatedVerifier(nonces)

	engine := policy.NewEngine()
	engine.Add(&policy.Policy{
		Name:                "stripe-key",
		AllowedMeasurements: map[string]bool{"deadbeef": true},
	})

	svc := secret.New(masterKey, engine, verifier)
	h := &httpapi.Handlers{Nonces: nonces, Secrets: svc}

	go func() {
		t := time.NewTicker(30 * time.Second)
		for range t.C {
			nonces.Cleanup()
		}
	}()

	log.Println("listening :8080")
	log.Fatal(http.ListenAndServe(":8080", httpapi.NewRouter(h)))
}
