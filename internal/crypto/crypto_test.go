package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("hello")
	ciphertext, _ := Encrypt(key, plaintext)
	decrypted, _ := Decrypt(key, ciphertext)
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text = %q, want %q", decrypted, plaintext)
	}
}

func TestDeriveSharedKey(t *testing.T) {
	publicKeyA, privateKeyA, _ := GenerateKeyPair()
	publicKeyB, privateKeyB, _ := GenerateKeyPair()
	sharedKeyA, _ := DeriveSharedKey(privateKeyA, publicKeyB)
	sharedKeyB, _ := DeriveSharedKey(privateKeyB, publicKeyA)

	if !bytes.Equal(sharedKeyA, sharedKeyB) {
		t.Fatal("shared keys do not match")
	}
}
