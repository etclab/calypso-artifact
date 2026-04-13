package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Helper: Setup Calypso system with automatic cleanup
func setupCalypso(t *testing.T, maxDepth int) (paramsFile, authorityFile string) {
	t.Helper()
	tmpDir := t.TempDir()
	paramsFile = filepath.Join(tmpDir, "params.bin")
	authorityFile = filepath.Join(tmpDir, "authority.bin")

	HandleCalypsoCommands([]string{
		"setup", "--max-depth", strconv.Itoa(maxDepth),
		"--output", paramsFile,
		"--authority", authorityFile,
	})

	return paramsFile, authorityFile
}

// Helper: Verify Calypso key file exists and can be deserialized
func verifyCalypsoKeyFile(t *testing.T, keyFile string) {
	t.Helper()

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatalf("key file not created: %v", err)
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("failed to read key: %v", err)
	}

	if _, err := DeserializeCalypsoPrivateKey(keyBytes); err != nil {
		t.Fatalf("failed to deserialize key: %v", err)
	}
}

func TestCalypsoSetup(t *testing.T) {
	tests := []struct {
		name     string
		maxDepth int
	}{
		{"default depth", 5},
		{"custom depth", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramsFile, authorityFile := setupCalypso(t, tt.maxDepth)

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

			// Verify authority
			authBytes, err := os.ReadFile(authorityFile)
			if err != nil {
				t.Fatalf("failed to read authority: %v", err)
			}

			auth, err := DeserializeAuthority(authBytes)
			if err != nil {
				t.Fatalf("failed to deserialize authority: %v", err)
			}

			if auth.PublicParams.MaxDepth != tt.maxDepth {
				t.Errorf("authority MaxDepth=%d, want %d", auth.PublicParams.MaxDepth, tt.maxDepth)
			}
		})
	}
}

func TestCalypsoKeyGenWriter(t *testing.T) {
	paramsFile, authorityFile := setupCalypso(t, 5)
	keyFile := filepath.Join(t.TempDir(), "alice-writer.key")

	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "alice.example.com", "--writer", "--output", keyFile,
	})

	verifyCalypsoKeyFile(t, keyFile)

	// Verify key is a writer key
	keyBytes, _ := os.ReadFile(keyFile)
	key, _ := DeserializeCalypsoPrivateKey(keyBytes)

	if !key.IsWriter() {
		t.Error("expected writer key, got reader key")
	}

	if key.DomainName != "alice.example.com" {
		t.Errorf("expected domain=alice.example.com, got %s", key.DomainName)
	}
}

func TestCalypsoKeyGenReader(t *testing.T) {
	paramsFile, authorityFile := setupCalypso(t, 5)
	keyFile := filepath.Join(t.TempDir(), "alice-reader.key")

	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "alice.example.com", "--output", keyFile,
	})

	verifyCalypsoKeyFile(t, keyFile)

	// Verify key is a reader key (no --writer flag)
	keyBytes, _ := os.ReadFile(keyFile)
	key, _ := DeserializeCalypsoPrivateKey(keyBytes)

	if key.IsWriter() {
		t.Error("expected reader key, got writer key")
	}

	if key.DomainName != "alice.example.com" {
		t.Errorf("expected domain=alice.example.com, got %s", key.DomainName)
	}
}

func TestCalypsoReaderDerivation(t *testing.T) {
	paramsFile, authorityFile := setupCalypso(t, 5)
	tmpDir := t.TempDir()
	writerKey := filepath.Join(tmpDir, "writer.key")
	readerKey := filepath.Join(tmpDir, "reader.key")

	// Generate writer key
	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "alice.example.com", "--writer", "--output", writerKey,
	})

	// Derive reader from writer
	HandleCalypsoCommands([]string{
		"reader", "--writer", writerKey, "--output", readerKey,
	})

	verifyCalypsoKeyFile(t, readerKey)

	// Verify derived key is reader
	readerBytes, _ := os.ReadFile(readerKey)
	rKey, _ := DeserializeCalypsoPrivateKey(readerBytes)

	if rKey.IsWriter() {
		t.Error("expected reader key, got writer key")
	}

	if rKey.DomainName != "alice.example.com" {
		t.Errorf("expected domain=alice.example.com, got %s", rKey.DomainName)
	}
}

func TestCalypsoKeyDerive(t *testing.T) {
	paramsFile, authorityFile := setupCalypso(t, 5)
	tmpDir := t.TempDir()
	parentKey := filepath.Join(tmpDir, "wildcard.key")
	childKey := filepath.Join(tmpDir, "alice.key")

	// Generate wildcard writer key
	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "*.example.com", "--writer", "--output", parentKey,
	})

	// Derive child key from wildcard parent
	HandleCalypsoCommands([]string{
		"keyder", "--params", paramsFile, "--parent-key", parentKey,
		"--domain", "alice.example.com", "--output", childKey,
	})

	verifyCalypsoKeyFile(t, childKey)

	// Verify child inherits writer status
	childBytes, _ := os.ReadFile(childKey)
	cKey, _ := DeserializeCalypsoPrivateKey(childBytes)

	if !cKey.IsWriter() {
		t.Error("child should inherit writer status from parent")
	}

	if cKey.DomainName != "alice.example.com" {
		t.Errorf("expected domain=alice.example.com, got %s", cKey.DomainName)
	}
}

func TestCalypsoWildcardHierarchy(t *testing.T) {
	paramsFile, authorityFile := setupCalypso(t, 5)
	tmpDir := t.TempDir()
	wildcardWriter := filepath.Join(tmpDir, "wildcard-writer.key")
	aliceWriter := filepath.Join(tmpDir, "alice-writer.key")
	aliceReader := filepath.Join(tmpDir, "alice-reader.key")

	// Setup: wildcard writer → alice writer → alice reader
	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "*.example.com", "--writer", "--output", wildcardWriter,
	})
	HandleCalypsoCommands([]string{
		"keyder", "--params", paramsFile, "--parent-key", wildcardWriter,
		"--domain", "alice.example.com", "--output", aliceWriter,
	})
	HandleCalypsoCommands([]string{
		"reader", "--writer", aliceWriter, "--output", aliceReader,
	})

	// Create encrypter and decrypters
	aliceEnc, err := NewCalypsoEncrypter(paramsFile, aliceWriter, "alice.example.com")
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	aliceWriterDec, err := NewCalypsoDecrypter(paramsFile, aliceWriter, "alice.example.com")
	if err != nil {
		t.Fatalf("failed to create writer decrypter: %v", err)
	}

	aliceReaderDec, err := NewCalypsoDecrypter(paramsFile, aliceReader, "alice.example.com")
	if err != nil {
		t.Fatalf("failed to create reader decrypter: %v", err)
	}

	t.Run("writer key encrypts and decrypts", func(t *testing.T) {
		expected := "message for alice"
		ct, err := aliceEnc.Encrypt([]byte(expected))
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		got, err := aliceWriterDec.Decrypt(ct)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(got) != expected {
			t.Errorf("got %s, want %s", got, expected)
		}
	})

	t.Run("reader key decrypts", func(t *testing.T) {
		expected := "message for alice reader"
		ct, err := aliceEnc.Encrypt([]byte(expected))
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		got, err := aliceReaderDec.Decrypt(ct)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(got) != expected {
			t.Errorf("got %s, want %s", got, expected)
		}
	})

	t.Run("wildcard parent fails domain validation", func(t *testing.T) {
		expected := "alice's secret"
		ct, err := aliceEnc.Encrypt([]byte(expected))
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Create wildcard decrypter - key's DomainName is "*.example.com"
		wildcardDec, err := NewCalypsoDecrypter(paramsFile, wildcardWriter, "*.example.com")
		if err != nil {
			t.Fatalf("failed to create wildcard decrypter: %v", err)
		}

		// Wildcard parent tries to decrypt alice child ciphertext
		// Fails domain validation: DecryptAndVerify requires concrete domain, rejects "*.example.com"
		// Expected: "Invalid domain name" error (downward delegation enforced)
		_, err = wildcardDec.Decrypt(ct)
		if err == nil {
			t.Error("Expected domain validation to fail for wildcard parent, but it succeeded!")
		}
	})
}

func TestCalypsoAccessControl(t *testing.T) {
	paramsFile, authorityFile := setupCalypso(t, 5)
	tmpDir := t.TempDir()
	aliceWriter := filepath.Join(tmpDir, "alice-writer.key")
	bobWriter := filepath.Join(tmpDir, "bob-writer.key")

	// Create two separate writer keys
	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "alice.example.com", "--writer", "--output", aliceWriter,
	})
	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "bob.example.com", "--writer", "--output", bobWriter,
	})

	// Create encrypters and decrypters
	aliceEnc, _ := NewCalypsoEncrypter(paramsFile, aliceWriter, "alice.example.com")
	aliceDec, _ := NewCalypsoDecrypter(paramsFile, aliceWriter, "alice.example.com")
	bobDec, _ := NewCalypsoDecrypter(paramsFile, bobWriter, "bob.example.com")

	t.Run("correct key decrypts successfully", func(t *testing.T) {
		expected := "alice's secret"
		ct, _ := aliceEnc.Encrypt([]byte(expected))

		got, err := aliceDec.Decrypt(ct)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(got) != expected {
			t.Errorf("got %s, want %s", got, expected)
		}
	})

	t.Run("wrong key fails signature verification", func(t *testing.T) {
		expected := "alice's secret"
		ct, _ := aliceEnc.Encrypt([]byte(expected))

		// Bob attempts to decrypt Alice's message
		// Wrong WKD-IBE key → wrong Gt → wrong AES key → garbage plaintext
		// Signature verification FAILS: Alice signed with her pattern, Bob verifies with his pattern
		// Expected: error from signature verification failure
		_, err := bobDec.Decrypt(ct)
		if err == nil {
			t.Error("Expected signature verification to fail with wrong key, but it succeeded!")
		}
	})
}

func TestCalypsoAccessControlDerivedSiblings(t *testing.T) {
	paramsFile, authorityFile := setupCalypso(t, 5)
	tmpDir := t.TempDir()
	wildcardWriter := filepath.Join(tmpDir, "wildcard-writer.key")
	aliceWriter := filepath.Join(tmpDir, "alice-writer.key")
	bobWriter := filepath.Join(tmpDir, "bob-writer.key")

	// Create wildcard key, then derive alice and bob from it
	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", "*.example.com", "--writer", "--output", wildcardWriter,
	})
	HandleCalypsoCommands([]string{
		"keyder", "--params", paramsFile, "--parent-key", wildcardWriter,
		"--domain", "alice.example.com", "--output", aliceWriter,
	})
	HandleCalypsoCommands([]string{
		"keyder", "--params", paramsFile, "--parent-key", wildcardWriter,
		"--domain", "bob.example.com", "--output", bobWriter,
	})

	// Create encrypters and decrypters
	aliceEnc, _ := NewCalypsoEncrypter(paramsFile, aliceWriter, "alice.example.com")
	aliceDec, _ := NewCalypsoDecrypter(paramsFile, aliceWriter, "alice.example.com")
	bobDec, _ := NewCalypsoDecrypter(paramsFile, bobWriter, "bob.example.com")

	t.Run("alice decrypts her own message", func(t *testing.T) {
		expected := "alice's secret"
		ct, _ := aliceEnc.Encrypt([]byte(expected))

		got, err := aliceDec.Decrypt(ct)
		if err != nil {
			t.Fatalf("alice decryption failed: %v", err)
		}
		if string(got) != expected {
			t.Errorf("got %s, want %s", got, expected)
		}
	})

	t.Run("bob (derived sibling) fails signature verification", func(t *testing.T) {
		expected := "alice's secret"
		ct, _ := aliceEnc.Encrypt([]byte(expected))

		// Bob's key is a sibling derived from same wildcard parent
		// Wrong WKD-IBE pattern → signature verification fails
		// Expected: error from signature verification (sibling isolation enforced by signatures)
		_, err := bobDec.Decrypt(ct)
		if err == nil {
			t.Error("Expected signature verification to fail for sibling key, but it succeeded!")
		}
	})
}