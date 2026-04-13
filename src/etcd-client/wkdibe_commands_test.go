package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Helper: Setup WKD-IBE system with automatic cleanup
func setupWKDIBE(t *testing.T, maxDepth int) (paramsFile, masterFile string) {
	t.Helper()
	tmpDir := t.TempDir()
	paramsFile = filepath.Join(tmpDir, "params.bin")
	masterFile = filepath.Join(tmpDir, "master.key")

	HandleWKDIBECommands([]string{
		"setup", "--max-depth", strconv.Itoa(maxDepth),
		"--output", paramsFile,
		"--master-key", masterFile,
	})

	return paramsFile, masterFile
}

// Helper: Verify key file exists and can be deserialized
func verifyKeyFile(t *testing.T, keyFile string) {
	t.Helper()

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatalf("key file not created: %v", err)
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}

	if _, err := DeserializePrivateKey(keyBytes); err != nil {
		t.Fatalf("failed to deserialize key: %v", err)
	}
}

func TestWKDIBESetup(t *testing.T) {
	tests := []struct {
		name     string
		maxDepth int
	}{
		{"default depth", 5},
		{"custom depth", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsFile, masterFile := setupWKDIBE(t, tt.maxDepth)

			// Verify params
			ppBytes, err := os.ReadFile(paramsFile)
			if err != nil {
				t.Fatalf("failed to read params: %v", err)
			}

			pp, err := DeserializePublicParams(ppBytes)
			if err != nil {
				t.Fatalf("failed to deserialize params: %v", err)
			}

			if pp.MaxDepth != tt.maxDepth {
				t.Errorf("expected MaxDepth=%d, got %d", tt.maxDepth, pp.MaxDepth)
			}

			// Verify master key
			mkBytes, err := os.ReadFile(masterFile)
			if err != nil {
				t.Fatalf("failed to read master key: %v", err)
			}

			if _, err := DeserializeMasterKey(mkBytes); err != nil {
				t.Fatalf("failed to deserialize master key: %v", err)
			}
		})
	}
}

func TestWKDIBEKeyGen(t *testing.T) {
	paramsFile, masterFile := setupWKDIBE(t, 5)
	keyFile := filepath.Join(t.TempDir(), "alice.key")

	HandleWKDIBECommands([]string{
		"keygen", "--params", paramsFile, "--master-key", masterFile,
		"--domain", "alice.example.com", "--output", keyFile,
	})

	verifyKeyFile(t, keyFile)

	// Functional test: verify key can encrypt/decrypt
	encrypter, err := NewWKDIBEEncrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	decrypter, err := NewWKDIBEDecrypter(paramsFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}

	plaintext := []byte("test message")
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("got %s, want %s", decrypted, plaintext)
	}
}

func TestWKDIBEKeyDerive(t *testing.T) {
	paramsFile, masterFile := setupWKDIBE(t, 5)
	tmpDir := t.TempDir()
	parentKey := filepath.Join(tmpDir, "parent.key")
	childKey := filepath.Join(tmpDir, "child.key")

	// Generate parent key
	HandleWKDIBECommands([]string{
		"keygen", "--params", paramsFile, "--master-key", masterFile,
		"--domain", "example.com", "--output", parentKey,
	})

	// Derive child key from parent
	HandleWKDIBECommands([]string{
		"keyder", "--params", paramsFile, "--parent-key", parentKey,
		"--domain", "alice.example.com", "--output", childKey,
	})

	verifyKeyFile(t, childKey)
}

func TestWKDIBEKeyHierarchy(t *testing.T) {
	paramsFile, masterFile := setupWKDIBE(t, 5)
	tmpDir := t.TempDir()
	parentKey := filepath.Join(tmpDir, "parent.key")
	childKey := filepath.Join(tmpDir, "child.key")

	// Setup hierarchy: parent (example.com) → child (alice.example.com)
	HandleWKDIBECommands([]string{
		"keygen", "--params", paramsFile, "--master-key", masterFile,
		"--domain", "example.com", "--output", parentKey,
	})
	HandleWKDIBECommands([]string{
		"keyder", "--params", paramsFile, "--parent-key", parentKey,
		"--domain", "alice.example.com", "--output", childKey,
	})

	// Create encrypters and decrypters (use keys for encryption now)
	childEncrypter, _ := NewWKDIBEEncrypter(paramsFile, childKey)
	parentEncrypter, _ := NewWKDIBEEncrypter(paramsFile, parentKey)
	childDecrypter, _ := NewWKDIBEDecrypter(paramsFile, childKey)
	parentDecrypter, _ := NewWKDIBEDecrypter(paramsFile, parentKey)

	t.Run("child key decrypts child ciphertext", func(t *testing.T) {
		plaintext := []byte("message for alice")
		ct, _ := childEncrypter.Encrypt(plaintext)

		got, err := childDecrypter.Decrypt(ct)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("got %s, want %s", got, plaintext)
		}
	})

	t.Run("parent key decrypts parent ciphertext", func(t *testing.T) {
		plaintext := []byte("message for example.com")
		ct, _ := parentEncrypter.Encrypt(plaintext)

		got, err := parentDecrypter.Decrypt(ct)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("got %s, want %s", got, plaintext)
		}
	})

	t.Run("parent key CANNOT decrypt child ciphertext (signature failure)", func(t *testing.T) {
		plaintext := []byte("message for alice")
		ct, _ := childEncrypter.Encrypt(plaintext)

		// With signatures, parent decryption should FAIL verification
		_, err := parentDecrypter.Decrypt(ct)
		if err == nil {
			t.Error("expected parent key decryption to fail signature verification for child ciphertext")
		}

		// Optionally verify it's a signature verification error
		if err.Error() != "signature verification failed" {
			t.Logf("got error: %v (expected signature verification failure)", err)
		}
	})
}
