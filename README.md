# Attestation Vault

A small Go demo that releases an encrypted secret only after simulated attestation and policy checks.

## Features

- One-time, expiring nonce challenges
- Simulated quote verification and replay protection
- Measurement-based secret access policies
- AES-GCM encryption and X25519 client/server key exchange

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

## License

Not specified.
