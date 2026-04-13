package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestEncryptRecord_NoEncryption(t *testing.T) {
	// Test basic JSON marshaling without encryption
	record := &DNSRecord{
		Host: "192.168.1.100",
		TTL:  300,
	}

	// Test with NoOpCrypto encrypter
	encrypter := &NoOpCrypto{}
	data, err := EncryptRecord(record, encrypter)
	if err != nil {
		t.Fatalf("EncryptRecord failed: %v", err)
	}

	if data == nil {
		t.Fatal("EncryptRecord returned nil data")
	}

	// Verify it's valid JSON by unmarshaling
	var testRecord DNSRecord
	err = json.Unmarshal(data, &testRecord)
	if err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	// Check the data matches
	if testRecord.Host != record.Host {
		t.Errorf("Host mismatch: expected %s, got %s", record.Host, testRecord.Host)
	}
	if testRecord.TTL != record.TTL {
		t.Errorf("TTL mismatch: expected %d, got %d", record.TTL, testRecord.TTL)
	}
}

func TestDecryptRecord_NoDecryption(t *testing.T) {
	// Test basic JSON unmarshaling without decryption
	originalRecord := &DNSRecord{
		Host: "192.168.1.100",
		TTL:  300,
	}

	// Convert to JSON manually for test
	jsonData, err := json.Marshal(originalRecord)
	if err != nil {
		t.Fatalf("Failed to create test data: %v", err)
	}

	// Test with NoOpCrypto decrypter
	decrypter := &NoOpCrypto{}
	record, err := DecryptRecord(jsonData, decrypter)
	if err != nil {
		t.Fatalf("DecryptRecord failed: %v", err)
	}

	if record == nil {
		t.Fatal("DecryptRecord returned nil record")
	}

	// Check the data matches
	if record.Host != originalRecord.Host {
		t.Errorf("Host mismatch: expected %s, got %s", originalRecord.Host, record.Host)
	}

	if record.TTL != originalRecord.TTL {
		t.Errorf("TTL mismatch: expected %d, got %d", originalRecord.TTL, record.TTL)
	}
}

func TestCryptoRoundTrip(t *testing.T) {
	// Test encrypt then decrypt (without actual encryption)
	original := &DNSRecord{
		Host: "10.0.0.5",
		TTL:  600,
	}

	crypto := &NoOpCrypto{}

	// Encrypt (should just return JSON)
	encrypted, err := EncryptRecord(original, crypto)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt (should parse JSON back)
	decrypted, err := DecryptRecord(encrypted, crypto)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Compare
	if decrypted.Host != original.Host ||
		decrypted.TTL != original.TTL {
		t.Errorf("Round trip failed:\nOriginal:  %+v\nDecrypted: %+v", original, decrypted)
	}
}

// Helper test to verify JSON structure
func TestDNSRecordJSON(t *testing.T) {
	record := DNSRecord{
		Host: "127.0.0.1",
		TTL:  300,
	}

	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Failed to marshal DNSRecord: %v", err)
	}

	expectedFields := []string{"host", "ttl"}
	jsonStr := string(data)

	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("JSON missing field '%s': %s", field, jsonStr)
		}
	}
}

// Test that DNSRecord JSON format exactly matches CoreDNS/SkyDNS expectations
func TestDNSRecordJSON_CoreDNSFormat(t *testing.T) {
	record := DNSRecord{
		Host: "127.0.0.1",
		TTL:  300,
	}

	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Failed to marshal DNSRecord: %v", err)
	}

	// Verify exact format matches CoreDNS expectation
	expected := `{"host":"127.0.0.1","ttl":300}`
	actual := string(data)
	if actual != expected {
		t.Errorf("JSON format mismatch:\nExpected: %s\nGot:      %s", expected, actual)
	}

	// Verify no extra fields are present
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if len(parsed) != 2 {
		t.Errorf("Expected exactly 2 fields, got %d: %v", len(parsed), parsed)
	}

	// Verify CoreDNS can parse it (no "domain" field)
	if _, hasOldField := parsed["domain"]; hasOldField {
		t.Error("JSON contains old 'domain' field - incompatible with CoreDNS")
	}
	if _, hasOldField := parsed["ip"]; hasOldField {
		t.Error("JSON contains old 'ip' field - incompatible with CoreDNS")
	}
}

// Simple helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsInner(s, substr)))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestAESCrypto_RoundTrip verifies AES-256-GCM encryption/decryption
func TestAESCrypto_RoundTrip(t *testing.T) {
	// Generate 32-byte AES key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	crypto := &AESCrypto{key: key}

	original := &DNSRecord{
		Host: "10.0.0.42",
		TTL:  300,
	}

	// Encrypt
	encrypted, err := EncryptRecord(original, crypto)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptRecord(encrypted, crypto)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify
	if decrypted.Host != original.Host {
		t.Errorf("Host mismatch: expected %s, got %s", original.Host, decrypted.Host)
	}
	if decrypted.TTL != original.TTL {
		t.Errorf("TTL mismatch: expected %d, got %d", original.TTL, decrypted.TTL)
	}
}

// TestAESCrypto_WrongKey verifies wrong key produces decryption error
func TestAESCrypto_WrongKey(t *testing.T) {
	// Generate two different keys
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	crypto1 := &AESCrypto{key: key1}
	crypto2 := &AESCrypto{key: key2}

	original := &DNSRecord{
		Host: "10.0.0.50",
		TTL:  300,
	}

	// Encrypt with key1
	encrypted, err := EncryptRecord(original, crypto1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with key2 (should fail)
	_, err = DecryptRecord(encrypted, crypto2)
	if err == nil {
		t.Error("Expected decryption error with wrong key, but got nil")
	}
}

// TestAESCrypto_CiphertextFormat verifies type marker and base64 encoding
func TestAESCrypto_CiphertextFormat(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	crypto := &AESCrypto{key: key}

	record := &DNSRecord{
		Host: "10.0.0.60",
		TTL:  300,
	}

	// EncryptRecord returns raw bytes, need to wrap in TXT format like RegisterDNS does
	encryptedBytes, err := EncryptRecord(record, crypto)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify raw bytes are non-empty
	if len(encryptedBytes) == 0 {
		t.Fatal("Encrypted bytes are empty")
	}

	// Wrap in TXT record format like RegisterDNS does
	encodedPayload := base64.StdEncoding.EncodeToString(encryptedBytes)
	textValue := "01:" + encodedPayload
	txtRecord := map[string]interface{}{
		"text": textValue,
		"ttl":  300,
	}

	// Marshal to JSON
	valueBytes, err := json.Marshal(txtRecord)
	if err != nil {
		t.Fatalf("Failed to marshal TXT record: %v", err)
	}

	// Parse back to verify format
	var parsedRecord struct {
		Text string `json:"text"`
		TTL  int    `json:"ttl"`
	}
	if err := json.Unmarshal(valueBytes, &parsedRecord); err != nil {
		t.Fatalf("Failed to parse TXT record JSON: %v", err)
	}

	// Verify type marker "01:"
	if !strings.HasPrefix(parsedRecord.Text, "01:") {
		t.Errorf("Expected type marker '01:', got: %s", parsedRecord.Text[:10])
	}

	// Verify base64 payload (no whitespace, valid characters)
	payload := parsedRecord.Text[3:] // Skip "01:"
	if len(payload) == 0 {
		t.Error("Empty base64 payload")
	}

	// Verify can decode base64
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Errorf("Failed to decode base64 payload: %v", err)
	}
	if len(decoded) == 0 {
		t.Error("Decoded payload is empty")
	}
}

// TestAESCrypto_DifferentKeysDifferentCiphertexts verifies non-deterministic encryption
func TestAESCrypto_DifferentKeysDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	crypto := &AESCrypto{key: key}

	record := &DNSRecord{
		Host: "10.0.0.70",
		TTL:  300,
	}

	// Encrypt same record twice
	ct1, err := EncryptRecord(record, crypto)
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	ct2, err := EncryptRecord(record, crypto)
	if err != nil {
		t.Fatalf("Second encrypt failed: %v", err)
	}

	// Ciphertexts should differ (random IV/nonce)
	if bytes.Equal(ct1, ct2) {
		t.Error("Two encryptions of same plaintext produced identical ciphertexts (IV not randomized)")
	}
}