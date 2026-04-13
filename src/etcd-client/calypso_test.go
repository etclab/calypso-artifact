package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/etclab/calypso"
)

// TestCalypsoEncryptDecryptRoundTrip tests basic Calypso encrypt/decrypt functionality
func TestCalypsoEncryptDecryptRoundTrip(t *testing.T) {
	// Setup
	maxDepth := 5
	domain := "alice.example.com"

	// Create authority
	auth := calypso.NewAuthority(maxDepth)

	// Issue writer key for domain
	writerKey, err := auth.IssueKey(domain, true)
	if err != nil {
		t.Fatalf("IssueKey failed: %v", err)
	}

	// Create temporary files for params and writer key
	tmpDir := t.TempDir()
	paramsFile := tmpDir + "/params.bin"
	writerKeyFile := tmpDir + "/writer.key"

	// Serialize and save params
	paramsData, err := SerializePublicParams(auth.PublicParams)
	if err != nil {
		t.Fatalf("SerializePublicParams failed: %v", err)
	}
	if err := os.WriteFile(paramsFile, paramsData, 0644); err != nil {
		t.Fatalf("Failed to write params file: %v", err)
	}

	// Serialize and save writer key
	keyData, err := SerializeCalypsoPrivateKey(writerKey)
	if err != nil {
		t.Fatalf("SerializeCalypsoPrivateKey failed: %v", err)
	}
	if err := os.WriteFile(writerKeyFile, keyData, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create DNS record
	record := &DNSRecord{Host: "10.0.0.1", TTL: 300}
	plaintext, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Failed to marshal record: %v", err)
	}

	// Create encrypter and encrypt
	encrypter, err := NewCalypsoEncrypter(paramsFile, writerKeyFile, domain)
	if err != nil {
		t.Fatalf("NewCalypsoEncrypter failed: %v", err)
	}

	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Create decrypter and decrypt
	decrypter, err := NewCalypsoDecrypter(paramsFile, writerKeyFile, domain)
	if err != nil {
		t.Fatalf("NewCalypsoDecrypter failed: %v", err)
	}

	decryptedPlaintext, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify plaintext matches
	var decryptedRecord DNSRecord
	if err := json.Unmarshal(decryptedPlaintext, &decryptedRecord); err != nil {
		t.Fatalf("Failed to unmarshal decrypted record: %v", err)
	}

	if decryptedRecord.Host != record.Host {
		t.Errorf("Host mismatch: expected %s, got %s", record.Host, decryptedRecord.Host)
	}

	if decryptedRecord.TTL != record.TTL {
		t.Errorf("TTL mismatch: expected %d, got %d", record.TTL, decryptedRecord.TTL)
	}
}

// TestCalypsoMessageSerialization tests Message serialization/deserialization
func TestCalypsoMessageSerialization(t *testing.T) {
	// Setup
	maxDepth := 5
	domain := "alice.example.com"
	auth := calypso.NewAuthority(maxDepth)
	writerKey, err := auth.IssueKey(domain, true)
	if err != nil {
		t.Fatalf("IssueKey failed: %v", err)
	}

	// Encrypt a message
	plaintext := []byte("test message")
	message, err := writerKey.EncryptAndSign(domain, plaintext)
	if err != nil {
		t.Fatalf("EncryptAndSign failed: %v", err)
	}

	// Serialize
	serialized, err := SerializeMessage(message)
	if err != nil {
		t.Fatalf("SerializeMessage failed: %v", err)
	}

	// Deserialize
	deserialized, err := DeserializeMessage(serialized)
	if err != nil {
		t.Fatalf("DeserializeMessage failed: %v", err)
	}

	// Verify components match
	if deserialized.SearchTag != message.SearchTag {
		t.Errorf("SearchTag mismatch: expected %s, got %s", message.SearchTag, deserialized.SearchTag)
	}

	if len(deserialized.IV) != len(message.IV) {
		t.Errorf("IV length mismatch: expected %d, got %d", len(message.IV), len(deserialized.IV))
	}

	if len(deserialized.Ciphertext) != len(message.Ciphertext) {
		t.Errorf("Ciphertext length mismatch: expected %d, got %d", len(message.Ciphertext), len(deserialized.Ciphertext))
	}
}

// TestCalypsoWriterKeyEnforcement tests that reader keys cannot be used for encryption
func TestCalypsoWriterKeyEnforcement(t *testing.T) {
	// Setup
	maxDepth := 5
	domain := "alice.example.com"
	auth := calypso.NewAuthority(maxDepth)

	// Issue reader key
	readerKey, err := auth.IssueKey(domain, false)
	if err != nil {
		t.Fatalf("IssueKey failed: %v", err)
	}

	// Create temporary files
	tmpDir := t.TempDir()
	paramsFile := tmpDir + "/params.bin"
	readerKeyFile := tmpDir + "/reader.key"

	// Save params and reader key
	paramsData, _ := SerializePublicParams(auth.PublicParams)
	os.WriteFile(paramsFile, paramsData, 0644)

	keyData, _ := SerializeCalypsoPrivateKey(readerKey)
	os.WriteFile(readerKeyFile, keyData, 0600)

	// Try to create encrypter with reader key (should fail)
	_, err = NewCalypsoEncrypter(paramsFile, readerKeyFile, domain)
	if err == nil {
		t.Error("Expected error when creating encrypter with reader key, but got none")
	}
}