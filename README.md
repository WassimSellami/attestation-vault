# Attestation Vault

A small Go demo that releases an encrypted secret only after simulated attestation and policy checks.

## Features

- One-time, expiring nonce challenges
- Simulated quote verification and replay protection
- Measurement-based secret access policies
- AES-GCM encryption and X25519 client/server key exchange

## Workflow

The demo client performs the following flow:

1. The client requests a challenge from `POST /api/v1/attest/challenge`.
2. The server creates a random, expiring nonce and stores it for one-time use.
3. The client computes `report_data = SHA-256(nonce || config_hash)`, generates an ephemeral X25519 key pair, and builds a simulated quote with:
	- measurement: `deadbeef`
	- config hash: `config-hash`
	- signature: a non-empty simulated signature
	- client public key
4. The client sends the quote to `POST /api/v1/attest/release` for the `stripe-key` secret.
5. The server verifies the quote, checks that the nonce has not expired or been used, and consumes the nonce to prevent replay.
6. The server checks the `stripe-key` policy. The measurement must be `deadbeef`.
7. The server generates an ephemeral X25519 key pair, derives a shared key with the client's public key, encrypts the secret with AES-GCM, and returns the ciphertext and server public key.
8. The client derives the same shared key, decrypts the ciphertext, and prints `sk_top_secret_value`.

The nonce is valid for 60 seconds and can only be used once. The server keeps secrets, nonces, and the master key in memory, so restarting the server resets the demo state.

## Installation

Requires Go 1.27.2 or later.

```bash
go mod download
```

## Usage

Start the server:

```bash
go run ./cmd/server
```

In a second terminal, run the demo client:

```bash
go run ./cmd/client
```

The client should print:

```text
sk_top_secret_value
```

The server listens on `http://localhost:8080`.

## Configuration

There are no environment variables currently. The demo uses an in-memory store, creates a new master key on each server start, and accepts measurement `deadbeef` for `stripe-key`.