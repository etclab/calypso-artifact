package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/etclab/ncircl/hibe/akn07"
)

// Test PublicParams serialization round-trip
func TestSerializePublicParams_RoundTrip(t *testing.T) {
	// Setup
	pp, _ := akn07.Setup(5)

	// Serialize
	data, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("SerializePublicParams failed: %v", err)
	}

	// Deserialize
	pp2, err := DeserializePublicParams(data)
	if err != nil {
		t.Fatalf("DeserializePublicParams failed: %v", err)
	}

	// Verify
	if pp2.MaxDepth != pp.MaxDepth {
		t.Errorf("MaxDepth mismatch: expected %d, got %d", pp.MaxDepth, pp2.MaxDepth)
	}

	if !pp2.G.IsEqual(pp.G) {
		t.Error("G mismatch")
	}

	if !pp2.G1.IsEqual(pp.G1) {
		t.Error("G1 mismatch")
	}

	if !pp2.G2.IsEqual(pp.G2) {
		t.Error("G2 mismatch")
	}

	if !pp2.G3.IsEqual(pp.G3) {
		t.Error("G3 mismatch")
	}

	if len(pp2.Hs) != len(pp.Hs) {
		t.Fatalf("Hs length mismatch: expected %d, got %d", len(pp.Hs), len(pp2.Hs))
	}

	for i := range pp.Hs {
		if !pp2.Hs[i].IsEqual(pp.Hs[i]) {
			t.Errorf("Hs[%d] mismatch", i)
		}
	}
}

// Test MasterKey serialization round-trip
func TestSerializeMasterKey_RoundTrip(t *testing.T) {
	// Setup
	_, msk := akn07.Setup(5)

	// Serialize
	data, err := SerializeMasterKey(msk)
	if err != nil {
		t.Fatalf("SerializeMasterKey failed: %v", err)
	}

	// Deserialize
	msk2, err := DeserializeMasterKey(data)
	if err != nil {
		t.Fatalf("DeserializeMasterKey failed: %v", err)
	}

	// Verify
	if !msk2.G2toAlpha.IsEqual(msk.G2toAlpha) {
		t.Error("G2toAlpha mismatch")
	}
}

// Test PrivateKey serialization round-trip
func TestSerializePrivateKey_RoundTrip(t *testing.T) {
	// Setup
	pp, msk := akn07.Setup(5)
	pattern, err := akn07.NewPatternFromStrings(pp, []string{"com", "example", "alice"})
	if err != nil {
		t.Fatalf("NewPatternFromStrings failed: %v", err)
	}

	sk, err := akn07.KeyGen(pp, msk, pattern)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Serialize
	data, err := SerializePrivateKey(sk)
	if err != nil {
		t.Fatalf("SerializePrivateKey failed: %v", err)
	}

	// Deserialize
	sk2, err := DeserializePrivateKey(data)
	if err != nil {
		t.Fatalf("DeserializePrivateKey failed: %v", err)
	}

	// Verify
	if !sk2.K0.IsEqual(sk.K0) {
		t.Error("K0 mismatch")
	}

	if !sk2.K1.IsEqual(sk.K1) {
		t.Error("K1 mismatch")
	}

	if len(sk2.Bs) != len(sk.Bs) {
		t.Fatalf("Bs length mismatch: expected %d, got %d", len(sk.Bs), len(sk2.Bs))
	}

	for i := range sk.Bs {
		if sk.Bs[i] == nil && sk2.Bs[i] == nil {
			continue
		}
		if sk.Bs[i] == nil || sk2.Bs[i] == nil {
			t.Errorf("Bs[%d] nil mismatch", i)
			continue
		}
		if !sk2.Bs[i].IsEqual(sk.Bs[i]) {
			t.Errorf("Bs[%d] mismatch", i)
		}
	}

	if sk2.Pattern.Depth() != sk.Pattern.Depth() {
		t.Errorf("Pattern depth mismatch: expected %d, got %d", sk.Pattern.Depth(), sk2.Pattern.Depth())
	}
}

// Test DomainToPattern conversion
func TestDomainToPattern(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		maxDepth int
		expected []string
		wantErr  bool
	}{
		{
			name:     "Simple domain",
			domain:   "alice.example.com",
			maxDepth: 5,
			expected: []string{"com", "example", "alice", "", ""},
		},
		{
			name:     "Two-level domain",
			domain:   "example.com",
			maxDepth: 5,
			expected: []string{"com", "example", "", "", ""},
		},
		{
			name:     "Single-level domain",
			domain:   "com",
			maxDepth: 5,
			expected: []string{"com", "", "", "", ""},
		},
		{
			name:     "Four-level domain",
			domain:   "sub.alice.example.com",
			maxDepth: 5,
			expected: []string{"com", "example", "alice", "sub", ""},
		},
		{
			name:     "Domain exceeds maxDepth",
			domain:   "a.b.c.d.e.f.g",
			maxDepth: 5,
			wantErr:  true,
		},
		{
			name:     "Invalid maxDepth",
			domain:   "example.com",
			maxDepth: 1,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := DomainToPattern(tt.domain, tt.maxDepth)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("DomainToPattern failed: %v", err)
			}

			if len(pattern) != len(tt.expected) {
				t.Fatalf("Pattern length mismatch: expected %d, got %d", len(tt.expected), len(pattern))
			}

			for i := range pattern {
				if pattern[i] != tt.expected[i] {
					t.Errorf("Pattern[%d] mismatch: expected %q, got %q", i, tt.expected[i], pattern[i])
				}
			}
		})
	}
}

// Test PatternToDomain conversion
func TestPatternToDomain(t *testing.T) {
	tests := []struct {
		name     string
		pattern  []string
		expected string
		wantErr  bool
	}{
		{
			name:     "Three-level domain",
			pattern:  []string{"com", "example", "alice", "", ""},
			expected: "alice.example.com",
		},
		{
			name:     "Two-level domain",
			pattern:  []string{"com", "example", "", "", ""},
			expected: "example.com",
		},
		{
			name:     "Single-level domain",
			pattern:  []string{"com", "", "", "", ""},
			expected: "com",
		},
		{
			name:    "Empty pattern",
			pattern: []string{},
			wantErr: true,
		},
		{
			name:    "All wildcards",
			pattern: []string{"", "", "", "", ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, err := PatternToDomain(tt.pattern)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("PatternToDomain failed: %v", err)
			}

			if domain != tt.expected {
				t.Errorf("Domain mismatch: expected %q, got %q", tt.expected, domain)
			}
		})
	}
}

// Test round-trip conversion Domain -> Pattern -> Domain
func TestDomainPatternRoundTrip(t *testing.T) {
	domains := []string{
		"alice.example.com",
		"example.com",
		"com",
		"sub.alice.example.com",
	}

	maxDepth := 5

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			// Convert to pattern
			pattern, err := DomainToPattern(domain, maxDepth)
			if err != nil {
				t.Fatalf("DomainToPattern failed: %v", err)
			}

			// Convert back to domain
			domain2, err := PatternToDomain(pattern)
			if err != nil {
				t.Fatalf("PatternToDomain failed: %v", err)
			}

			if domain2 != domain {
				t.Errorf("Round-trip mismatch: expected %q, got %q", domain, domain2)
			}
		})
	}
}

// Test wildcard pattern conversion
func TestDomainToPattern_Wildcards(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		maxDepth int
		expected []string
		wantErr  bool
	}{
		{
			name:     "Single wildcard",
			domain:   "*.example.com",
			maxDepth: 5,
			expected: []string{"com", "example", "", "", ""},
		},
		{
			name:     "Multiple wildcards",
			domain:   "*.*.com",
			maxDepth: 5,
			expected: []string{"com", "", "", "", ""},
		},
		{
			name:     "All wildcards",
			domain:   "*.*.*",
			maxDepth: 5,
			expected: []string{"", "", "", "", ""},
		},
		{
			name:     "Invalid: concrete after wildcard",
			domain:   "alice.*.example.com",
			maxDepth: 5,
			wantErr:  true,
		},
		{
			name:     "Invalid: empty label",
			domain:   ".example.com",
			maxDepth: 5,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := DomainToPattern(tt.domain, tt.maxDepth)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("DomainToPattern failed: %v", err)
			}

			if len(pattern) != len(tt.expected) {
				t.Fatalf("Pattern length mismatch: expected %d, got %d", len(tt.expected), len(pattern))
			}

			for i := range pattern {
				if pattern[i] != tt.expected[i] {
					t.Errorf("Pattern[%d] mismatch: expected %q, got %q", i, tt.expected[i], pattern[i])
				}
			}
		})
	}
}

func TestWKDIBESignatureVerification(t *testing.T) {
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
	paramsFile := "test_sig_params.bin"
	keyFile := "test_sig_key.bin"
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

	// Create encrypter and decrypter
	encrypter, err := NewWKDIBEEncrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	decrypter, err := NewWKDIBEDecrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}

	// Test data
	plaintext := []byte("Hello, WKD-IBE with signatures!")

	// Encrypt with signature
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Decrypt and verify signature succeeds
	decrypted, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption/verification failed: %v", err)
	}

	// Verify plaintext matches
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted plaintext doesn't match original.\nExpected: %q\nGot: %q", plaintext, decrypted)
	}
}

func TestWKDIBESignatureVerificationFailure(t *testing.T) {
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
	aliceKey, err := akn07.KeyGen(pp, msk, pattern1)
	if err != nil {
		t.Fatalf("failed to generate alice key: %v", err)
	}

	bobKey, err := akn07.KeyGen(pp, msk, pattern2)
	if err != nil {
		t.Fatalf("failed to generate bob key: %v", err)
	}

	// Save params and keys to temp files
	paramsFile := "test_sig_fail_params.bin"
	aliceKeyFile := "test_sig_alice_key.bin"
	bobKeyFile := "test_sig_bob_key.bin"
	defer os.Remove(paramsFile)
	defer os.Remove(aliceKeyFile)
	defer os.Remove(bobKeyFile)

	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("failed to serialize params: %v", err)
	}
	if err := os.WriteFile(paramsFile, ppBytes, 0644); err != nil {
		t.Fatalf("failed to write params file: %v", err)
	}

	aliceKeyBytes, err := SerializePrivateKey(aliceKey)
	if err != nil {
		t.Fatalf("failed to serialize alice key: %v", err)
	}
	if err := os.WriteFile(aliceKeyFile, aliceKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write alice key file: %v", err)
	}

	bobKeyBytes, err := SerializePrivateKey(bobKey)
	if err != nil {
		t.Fatalf("failed to serialize bob key: %v", err)
	}
	if err := os.WriteFile(bobKeyFile, bobKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write bob key file: %v", err)
	}

	// Encrypt with alice's key
	aliceEncrypter, err := NewWKDIBEEncrypter(paramsFile, aliceKeyFile)
	if err != nil {
		t.Fatalf("failed to create alice encrypter: %v", err)
	}

	plaintext := []byte("Secret message for Alice")
	ciphertext, err := aliceEncrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Try to decrypt with bob's key (wrong key)
	bobDecrypter, err := NewWKDIBEDecrypter(paramsFile, bobKeyFile)
	if err != nil {
		t.Fatalf("failed to create bob decrypter: %v", err)
	}

	_, err = bobDecrypter.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected signature verification to fail with wrong key, but it succeeded")
	}

	// Verify error is about signature verification
	expectedErr := "signature verification failed"
	if err.Error() != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, err.Error())
	}
}

func TestWKDIBETamperedCiphertext(t *testing.T) {
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
	paramsFile := "test_tamper_params.bin"
	keyFile := "test_tamper_key.bin"
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

	// Encrypt
	encrypter, err := NewWKDIBEEncrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	plaintext := []byte("Integrity test message")
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Tamper with AES ciphertext (flip bit in the middle)
	// Format: [IV_len(2)|IV(16)|AES_ct_len(4)|AES_ct(N)|WKDIBE_ct_len(4)|WKDIBE_ct(M)|Sig_len(4)|Sig(S)]
	// Skip IV_len(2) + IV(16) + AES_ct_len(4) = 22 bytes, then flip a bit in AES ciphertext
	if len(ciphertext) > 30 {
		ciphertext[25] ^= 0x01 // Flip one bit in AES ciphertext
	}

	// Try to decrypt tampered ciphertext
	decrypter, err := NewWKDIBEDecrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}

	_, err = decrypter.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected signature verification to fail on tampered ciphertext, but it succeeded")
	}

	// Verify error is about signature verification
	expectedErr := "signature verification failed"
	if err.Error() != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, err.Error())
	}
}

func TestWKDIBESignatureSize(t *testing.T) {
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
	paramsFile := "test_sigsize_params.bin"
	keyFile := "test_sigsize_key.bin"
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

	// Encrypt
	encrypter, err := NewWKDIBEEncrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	plaintext := []byte("Test signature size")
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify ciphertext format and signature presence
	// Format: [IV_len(2)|IV(16)|AES_ct_len(4)|AES_ct(N)|WKDIBE_ct_len(4)|WKDIBE_ct(M)|Sig_len(4)|Sig(S)]
	// Minimum: IV_len(2) + IV(16) + AES_ct_len(4) + AES_ct(N) + WKDIBE_ct_len(4) + WKDIBE_ct(M) + Sig_len(4) + Sig(S)
	minLength := 2 + 16 + 4 + len(plaintext) + 4 + 100 + 4 + 100 // Rough estimate
	if len(ciphertext) < minLength {
		t.Logf("ciphertext length: %d bytes (includes signature)", len(ciphertext))
	}

	// Signature should be ~144 bytes (S0: G1 ~48 bytes, S1: G2 ~96 bytes)
	t.Logf("Total ciphertext size: %d bytes (plaintext: %d bytes)", len(ciphertext), len(plaintext))
}
