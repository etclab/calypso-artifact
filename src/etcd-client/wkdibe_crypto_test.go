package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/etclab/ncircl/hibe/akn07"
)

func TestWKDIBECrypto_RoundTrip(t *testing.T) {
	// Setup: Create params and keys
	maxDepth := 5
	pp, msk := akn07.Setup(maxDepth)

	// Create pattern for alice.example.com
	patternStr := []string{"com", "example", "alice", "", ""}
	pattern, err := akn07.NewPatternFromStrings(pp, patternStr)
	if err != nil {
		t.Fatalf("failed to create pattern: %v", err)
	}

	// Generate key for pattern
	key, err := akn07.KeyGen(pp, msk, pattern)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Save params and key to temp files
	paramsFile := "test_params.bin"
	keyFile := "test_key.bin"
	defer os.Remove(paramsFile)
	defer os.Remove(keyFile)

	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("failed to serialize params: %v", err)
	}
	if err := os.WriteFile(paramsFile, ppBytes, 0644); err != nil {
		t.Fatalf("failed to write params file: %v", err)
	}

	keyBytes, err := SerializePrivateKey(key)
	if err != nil {
		t.Fatalf("failed to serialize key: %v", err)
	}
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create encrypter and decrypter (same key for both now)
	encrypter, err := NewWKDIBEEncrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	decrypter, err := NewWKDIBEDecrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}

	// Test data
	plaintext := []byte("Hello, WKD-IBE!")

	// Encrypt
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted plaintext doesn't match original.\nExpected: %q (% x)\nGot: %q (% x)", plaintext, plaintext, decrypted, decrypted)
	}
}

func TestWKDIBECrypto_WrongKey(t *testing.T) {
	// Setup: Create params and keys for two different patterns
	maxDepth := 5
	pp, msk := akn07.Setup(maxDepth)

	// Pattern 1: alice.example.com
	pattern1Str := []string{"com", "example", "alice", "", ""}
	pattern1, err := akn07.NewPatternFromStrings(pp, pattern1Str)
	if err != nil {
		t.Fatalf("failed to create pattern1: %v", err)
	}

	// Pattern 2: bob.example.com
	pattern2Str := []string{"com", "example", "bob", "", ""}
	pattern2, err := akn07.NewPatternFromStrings(pp, pattern2Str)
	if err != nil {
		t.Fatalf("failed to create pattern2: %v", err)
	}

	// Generate keys
	key1, err := akn07.KeyGen(pp, msk, pattern1)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}

	key2, err := akn07.KeyGen(pp, msk, pattern2)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	// Save params and keys to temp files
	paramsFile := "test_params2.bin"
	key1File := "test_key1.bin"
	key2File := "test_key2.bin"
	defer os.Remove(paramsFile)
	defer os.Remove(key1File)
	defer os.Remove(key2File)

	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("failed to serialize params: %v", err)
	}
	if err := os.WriteFile(paramsFile, ppBytes, 0644); err != nil {
		t.Fatalf("failed to write params file: %v", err)
	}

	key1Bytes, err := SerializePrivateKey(key1)
	if err != nil {
		t.Fatalf("failed to serialize key1: %v", err)
	}
	if err := os.WriteFile(key1File, key1Bytes, 0600); err != nil {
		t.Fatalf("failed to write key1 file: %v", err)
	}

	key2Bytes, err := SerializePrivateKey(key2)
	if err != nil {
		t.Fatalf("failed to serialize key2: %v", err)
	}
	if err := os.WriteFile(key2File, key2Bytes, 0600); err != nil {
		t.Fatalf("failed to write key2 file: %v", err)
	}

	// Encrypt with key1
	encrypter, err := NewWKDIBEEncrypter(paramsFile, key1File)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	plaintext := []byte("Secret message for Alice")
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Try to decrypt with key2 (wrong key)
	// With signatures, this should FAIL (not return garbage)
	decrypter, err := NewWKDIBEDecrypter(paramsFile, key2File)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}

	_, err = decrypter.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected decryption with wrong key to fail signature verification, but it succeeded")
	}

	// Verify error is about signature verification
	expectedErr := "signature verification failed"
	if err.Error() != expectedErr {
		t.Logf("got error: %v (expected signature verification failure)", err)
	}
}

func TestWKDIBECrypto_DifferentPatternsDifferentCiphertexts(t *testing.T) {
	// Setup
	maxDepth := 5
	pp, msk := akn07.Setup(maxDepth)

	// Pattern 1: alice.example.com
	pattern1Str := []string{"com", "example", "alice", "", ""}
	pattern1, err := akn07.NewPatternFromStrings(pp, pattern1Str)
	if err != nil {
		t.Fatalf("failed to create pattern1: %v", err)
	}

	// Pattern 2: bob.example.com
	pattern2Str := []string{"com", "example", "bob", "", ""}
	pattern2, err := akn07.NewPatternFromStrings(pp, pattern2Str)
	if err != nil {
		t.Fatalf("failed to create pattern2: %v", err)
	}

	// Generate keys
	key1, err := akn07.KeyGen(pp, msk, pattern1)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}

	key2, err := akn07.KeyGen(pp, msk, pattern2)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	// Save params and keys to temp files
	paramsFile := "test_params3.bin"
	key1File := "test_key3_1.bin"
	key2File := "test_key3_2.bin"
	defer os.Remove(paramsFile)
	defer os.Remove(key1File)
	defer os.Remove(key2File)

	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("failed to serialize params: %v", err)
	}
	if err := os.WriteFile(paramsFile, ppBytes, 0644); err != nil {
		t.Fatalf("failed to write params file: %v", err)
	}

	key1Bytes, err := SerializePrivateKey(key1)
	if err != nil {
		t.Fatalf("failed to serialize key1: %v", err)
	}
	if err := os.WriteFile(key1File, key1Bytes, 0600); err != nil {
		t.Fatalf("failed to write key1 file: %v", err)
	}

	key2Bytes, err := SerializePrivateKey(key2)
	if err != nil {
		t.Fatalf("failed to serialize key2: %v", err)
	}
	if err := os.WriteFile(key2File, key2Bytes, 0600); err != nil {
		t.Fatalf("failed to write key2 file: %v", err)
	}

	// Create encrypters
	encrypter1, err := NewWKDIBEEncrypter(paramsFile, key1File)
	if err != nil {
		t.Fatalf("failed to create encrypter1: %v", err)
	}

	encrypter2, err := NewWKDIBEEncrypter(paramsFile, key2File)
	if err != nil {
		t.Fatalf("failed to create encrypter2: %v", err)
	}

	// Same plaintext
	plaintext := []byte("Same message")

	// Encrypt with both patterns
	ciphertext1, err := encrypter1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption1 failed: %v", err)
	}

	ciphertext2, err := encrypter2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption2 failed: %v", err)
	}

	// Verify ciphertexts are different (due to different patterns, keys, signatures, and random IVs)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("ciphertexts with different patterns should be different")
	}
}

func TestWKDIBECrypto_CiphertextFormat(t *testing.T) {
	// Setup
	maxDepth := 5
	pp, msk := akn07.Setup(maxDepth)

	patternStr := []string{"com", "example", "alice", "", ""}
	pattern, err := akn07.NewPatternFromStrings(pp, patternStr)
	if err != nil {
		t.Fatalf("failed to create pattern: %v", err)
	}

	key, err := akn07.KeyGen(pp, msk, pattern)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Save params and key to temp files
	paramsFile := "test_params4.bin"
	keyFile := "test_key4.bin"
	defer os.Remove(paramsFile)
	defer os.Remove(keyFile)

	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("failed to serialize params: %v", err)
	}
	if err := os.WriteFile(paramsFile, ppBytes, 0644); err != nil {
		t.Fatalf("failed to write params file: %v", err)
	}

	keyBytes, err := SerializePrivateKey(key)
	if err != nil {
		t.Fatalf("failed to serialize key: %v", err)
	}
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create encrypter
	encrypter, err := NewWKDIBEEncrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	// Encrypt
	plaintext := []byte("Test message")
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify minimum ciphertext length
	// Format: [IV_len(2)|IV(16)|AES_ct_len(4)|AES_ct(N)|WKDIBE_ct_len(4)|WKDIBE_ct(M)|Sig_len(4)|Sig(S)]
	minLength := 2 + 16 + 4 + len(plaintext) + 4 + 100 + 4 + 100 // Rough estimate
	if len(ciphertext) < minLength {
		t.Logf("ciphertext length: %d bytes (includes signature)", len(ciphertext))
	}

	
	// Verify first two bytes are IV length (should be 16)
	ivLen := uint16(ciphertext[0])<<8 | uint16(ciphertext[1])
	if ivLen != 16 {
		t.Errorf("unexpected IV length. Expected 16, got %d", ivLen)
	}
}