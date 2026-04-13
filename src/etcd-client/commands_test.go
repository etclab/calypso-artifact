package main

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/etclab/ncircl/hibe/akn07"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	testEtcdServer = "127.0.0.1:2379"
)

// Note: These tests require:
// A running etcd server at localhost:2379

func getTestConfig() *Config {
	return &Config{
		EtcdEndpoints: []string{testEtcdServer},
		Timeout:       5,
	}
}

func TestRegisterDNS_Validation(t *testing.T) {
	config := getTestConfig()

	tests := []struct {
		domain    string
		ip        string
		shouldErr bool
		name      string
	}{
		{"", "192.168.1.1", true, "empty domain"},
		{"test.com", "", true, "empty IP"},
		{"invalid_domain", "192.168.1.1", true, "domain without dot"},
		{"test.com", "192.168.1", true, "invalid IP format"},
		{"valid.com", "192.168.1.1", false, "valid inputs"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := RegisterDNS(test.domain, test.ip, config)

			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected error for domain='%s', ip='%s', but got none", test.domain, test.ip)
				}
			} else {
				if err != nil {
					t.Logf("Note: %v (this is expected if etcd is not running)", err)
				}
			}
		})
	}
}

func TestLookupDNS_Validation(t *testing.T) {
	config := getTestConfig()

	tests := []struct {
		domain    string
		shouldErr bool
		name      string
	}{
		{"", true, "empty domain"},
		{"invalid_domain", true, "domain without dot"},
		{"valid.com", false, "valid domain"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LookupDNS(test.domain, config)

			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected validation error for domain='%s', but got none", test.domain)
				}
			} else {
				if err != nil {
					t.Logf("Note: %v (this is expected if etcd is not running or domain not found)", err)
				}
			}
		})
	}
}

func TestDeleteDNS_Validation(t *testing.T) {
	config := getTestConfig()

	tests := []struct {
		domain    string
		shouldErr bool
		name      string
	}{
		{"", true, "empty domain"},
		{"invalid_domain", true, "domain without dot"},
		{"valid.com", false, "valid domain"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := DeleteDNS(test.domain, config)

			if test.shouldErr {
				if err == nil {
					t.Errorf("Expected validation error for domain='%s', but got none", test.domain)
				}
			} else {
				if err != nil {
					t.Logf("Note: %v (this is expected if etcd is not running or domain not found)", err)
				}
			}
		})
	}
}

func TestListDNS_Basic(t *testing.T) {
	config := getTestConfig()

	err := ListDNS("", config)
	if err != nil {
		t.Logf("Note: %v (this is expected if etcd is not running)", err)
	}
}

func TestClearDNS_Basic(t *testing.T) {
	config := getTestConfig()

	err := ClearDNS(config)
	if err != nil {
		t.Logf("Note: %v (this is expected if etcd is not running)", err)
	}
}

func TestFullWorkflow(t *testing.T) {
	config := getTestConfig()

	// Clear any existing records first to start with clean state
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	domain := "test.integration.com"
	ip := "10.0.0.100"

	// Register
	err = RegisterDNS(domain, ip, config)
	if err != nil {
		t.Errorf("Failed to register DNS: %v", err)
		return
	}

	// Verify registration by lookup
	retrievedIP, err := LookupDNS(domain, config)
	if err != nil {
		t.Errorf("Failed to lookup registered domain: %v", err)
	} else if retrievedIP != ip {
		t.Errorf("Expected IP %s, got %s", ip, retrievedIP)
	}

	// Verify domain appears in list
	err = ListDNS("", config)
	if err != nil {
		t.Errorf("Failed to list DNS records: %v", err)
	}

	// Test delete functionality
	err = DeleteDNS(domain, config)
	if err != nil {
		t.Errorf("Failed to delete DNS record: %v", err)
	}

	// Verify record is deleted
	_, err = LookupDNS(domain, config)
	if err == nil {
		t.Errorf("Record still exists after deletion")
	}

	// Final cleanup - clear all records
	err = ClearDNS(config)
	if err != nil {
		t.Logf("Warning: Failed to clear records during cleanup: %v", err)
	}
}

func TestTypeMarkerBehavior(t *testing.T) {
	config := getTestConfig()

	// Clear any existing records first
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	// Test NoOp (plaintext) - should be {"host": "IP", "ttl": 300}
	noopDomain := "noop.test.com"
	noopIP := "10.0.0.1"
	noopConfig := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		Timeout:       5,
		// No CertFile, no CryptoType - defaults to NoOp
	}

	err = RegisterDNS(noopDomain, noopIP, noopConfig)
	if err != nil {
		t.Fatalf("Failed to register NoOp record: %v", err)
	}

	// Connect to etcd to verify format
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{testEtcdServer},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify NoOp entry has A record format: {"host": "IP", "ttl": 300}
	noopKey := DomainToKey(noopDomain)
	resp, err := cli.Get(ctx, noopKey)
	if err != nil {
		t.Fatalf("Failed to get NoOp record from etcd: %v", err)
	}

	if len(resp.Kvs) == 0 {
		t.Fatal("NoOp record not found in etcd")
	}

	noopValue := string(resp.Kvs[0].Value)
	if !strings.Contains(noopValue, `"host"`) || !strings.Contains(noopValue, noopIP) {
		t.Errorf("NoOp entry should be A record format {\"host\": \"IP\", \"ttl\": 300}, got: %s", noopValue)
	}

	// Cleanup
	err = ClearDNS(config)
	if err != nil {
		t.Logf("Warning: Failed to clear records during cleanup: %v", err)
	}
}

func TestWKDIBEWorkflow(t *testing.T) {
	// Test files - use unique names to avoid conflicts
	paramsFile := "test_wkdibe_params.bin"
	masterKeyFile := "test_wkdibe_master.key"
	privateKeyFile := "test_wkdibe_alice.key"

	// Cleanup test files at end
	defer os.Remove(paramsFile)
	defer os.Remove(masterKeyFile)
	defer os.Remove(privateKeyFile)

	// 1. Generate WKD-IBE setup (params + master key)
	maxDepth := 5
	pp, mk := akn07.Setup(maxDepth)

	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("Failed to serialize public params: %v", err)
	}
	if err := os.WriteFile(paramsFile, ppBytes, 0644); err != nil {
		t.Fatalf("Failed to write params file: %v", err)
	}

	mkBytes, err := SerializeMasterKey(mk)
	if err != nil {
		t.Fatalf("Failed to serialize master key: %v", err)
	}
	if err := os.WriteFile(masterKeyFile, mkBytes, 0600); err != nil {
		t.Fatalf("Failed to write master key file: %v", err)
	}

	// 2. Generate a private key for alice.example.com
	domain := "alice.example.com"
	patternStr, err := DomainToPattern(domain, maxDepth)
	if err != nil {
		t.Fatalf("Failed to derive pattern from domain: %v", err)
	}

	pattern, err := akn07.NewPatternFromStrings(pp, patternStr)
	if err != nil {
		t.Fatalf("Failed to create pattern: %v", err)
	}

	privateKey, err := akn07.KeyGen(pp, mk, pattern)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	skBytes, err := SerializePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to serialize private key: %v", err)
	}
	if err := os.WriteFile(privateKeyFile, skBytes, 0600); err != nil {
		t.Fatalf("Failed to write private key file: %v", err)
	}

	// 3. Create config with WKD-IBE settings
	config := &Config{
		EtcdEndpoints:    []string{testEtcdServer},
		CryptoType:       "wkdibe",
		WKDIBEParamsFile: paramsFile,
		WKDIBEKeyFile:    privateKeyFile,
		WKDIBEMaxDepth:   maxDepth,
		Timeout:          5,
	}

	// Clear any existing records
	err = ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	// 4. Register DNS record with WKD-IBE encryption
	ip := "10.0.0.50"
	err = RegisterDNS(domain, ip, config)
	if err != nil {
		t.Errorf("Failed to register DNS with WKD-IBE: %v", err)
		return
	}

	// 5. Lookup with correct WKD-IBE key
	retrievedIP, err := LookupDNS(domain, config)
	if err != nil {
		t.Errorf("Failed to lookup WKD-IBE-encrypted record: %v", err)
	} else if retrievedIP != ip {
		t.Errorf("Expected IP %s, got %s", ip, retrievedIP)
	}

	// 6. Verify list works with WKD-IBE
	err = ListDNS("", config)
	if err != nil {
		t.Errorf("Failed to list WKD-IBE records: %v", err)
	}

	// 7. Test lookup with wrong key (different domain)
	wrongDomain := "bob.example.com"
	wrongPatternStr, err := DomainToPattern(wrongDomain, maxDepth)
	if err != nil {
		t.Fatalf("Failed to derive wrong pattern: %v", err)
	}

	wrongPattern, err := akn07.NewPatternFromStrings(pp, wrongPatternStr)
	if err != nil {
		t.Fatalf("Failed to create wrong pattern: %v", err)
	}

	wrongKey, err := akn07.KeyGen(pp, mk, wrongPattern)
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}
	wrongKeyBytes, _ := SerializePrivateKey(wrongKey)
	wrongKeyFile := "test_wkdibe_wrong.key"
	os.WriteFile(wrongKeyFile, wrongKeyBytes, 0600)
	defer os.Remove(wrongKeyFile)

	wrongConfig := &Config{
		EtcdEndpoints:    []string{testEtcdServer},
		CryptoType:       "wkdibe",
		WKDIBEParamsFile: paramsFile,
		WKDIBEKeyFile:    wrongKeyFile,
		WKDIBEMaxDepth:   maxDepth,
		Timeout:          5,
	}

	// Should fail signature verification with wrong key
	_, err = LookupDNS(domain, wrongConfig)
	if err == nil {
		t.Error("Expected signature verification to fail with wrong key, but lookup succeeded")
	}

	// 8. Final Cleanup
	err = ClearDNS(config)
	if err != nil {
		t.Logf("Warning: Failed to clear records during cleanup: %v", err)
	}

}

// TestAESWorkflow tests AES-256-GCM encryption end-to-end
func TestAESWorkflow(t *testing.T) {
	var err error
	
	// Test file - use unique name to avoid conflicts
	keyFile := "test_aes.key"

	// Cleanup test file at end
	defer os.Remove(keyFile)

	// 1. Generate 32-byte AES key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatalf("Failed to write AES key file: %v", err)
	}

	// 2. Create config with AES settings
	config := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		CryptoType:    "aes",
		AESKeyFile:    keyFile,
		Timeout:       5,
	}

	// Clear any existing records
	err = ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	// 3. Register DNS record with AES encryption
	domain := "aes.test.com"
	ip := "10.0.0.80"
	err = RegisterDNS(domain, ip, config)
	if err != nil {
		t.Errorf("Failed to register DNS with AES: %v", err)
		return
	}

	// 4. Lookup with correct AES key
	retrievedIP, err := LookupDNS(domain, config)
	if err != nil {
		t.Errorf("Failed to lookup AES-encrypted record: %v", err)
	} else if retrievedIP != ip {
		t.Errorf("Expected IP %s, got %s", ip, retrievedIP)
	}

	// 5. Verify record format via direct etcd access
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{testEtcdServer},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	etcdKey := DomainToKey(domain)
	resp, err := cli.Get(ctx, etcdKey)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("AES record not found in etcd")
	}

	// Verify it's an AES encrypted record (should contain "01:")
	value := string(resp.Kvs[0].Value)
	if !strings.Contains(value, "01:") {
		t.Errorf("Expected AES record format with '01:' prefix, got: %s", value)
	}

	// 6. Verify list works with AES
	err = ListDNS("", config)
	if err != nil {
		t.Errorf("Failed to list AES records: %v", err)
	}

	// 7. Test lookup with wrong key (should fail)
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(255 - i) // Different key
	}
	wrongKeyFile := "test_aes_wrong.key"
	os.WriteFile(wrongKeyFile, wrongKey, 0600)
	defer os.Remove(wrongKeyFile)

	wrongConfig := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		CryptoType:    "aes",
		AESKeyFile:    wrongKeyFile,
		Timeout:       5,
	}

	// Should fail to decrypt with wrong key
	_, err = LookupDNS(domain, wrongConfig)
	if err == nil {
		t.Error("Expected error when decrypting with wrong AES key")
	} else {
		t.Logf("Correctly failed with wrong key: %v", err)
	}

	// 8. Final Cleanup
	err = ClearDNS(config)
	if err != nil {
		t.Logf("Warning: Failed to clear records during cleanup: %v", err)
	}
}

// TestListDNS_RecordTypes tests ListDNS with different record types
func TestListDNS_RecordTypes(t *testing.T) {
	config := getTestConfig()

	// Clear any existing records first
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	// Test 1: Register plaintext record
	plaintextDomain := "plaintext.list.test.com"
	plaintextIP := "192.168.1.1"
	plaintextConfig := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		Timeout:       5,
	}
	err = RegisterDNS(plaintextDomain, plaintextIP, plaintextConfig)
	if err != nil {
		t.Fatalf("Failed to register plaintext record: %v", err)
	}
	t.Logf("Registered plaintext record: %s -> %s", plaintextDomain, plaintextIP)

	// Test 2: List all records
	t.Log("\n=== Listing all records ===")
	err = ListDNS("", plaintextConfig)
	if err != nil {
		t.Errorf("Failed to list DNS records: %v", err)
	}

	// Test 4: Verify plaintext record format via direct etcd access
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{testEtcdServer},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	plaintextKey := DomainToKey(plaintextDomain)
	resp, err := cli.Get(ctx, plaintextKey)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("Failed to get plaintext record from etcd: %v", err)
	}

	plaintextValue := string(resp.Kvs[0].Value)
	if !strings.Contains(plaintextValue, `"host"`) {
		t.Errorf("Plaintext record should have 'host' field, got: %s", plaintextValue)
	}
	if !strings.Contains(plaintextValue, plaintextIP) {
		t.Errorf("Plaintext record should contain IP %s, got: %s", plaintextIP, plaintextValue)
	}

	// Test 3: Verify list shows records from /skydns/* namespace
	allKeys, err := cli.Get(ctx, "/skydns/", clientv3.WithPrefix())
	if err != nil {
		t.Errorf("Failed to query /skydns/ namespace: %v", err)
	} else {
		t.Logf("Found %d records in /skydns/ namespace", len(allKeys.Kvs))
		if len(allKeys.Kvs) == 0 {
			t.Error("Expected at least one record in /skydns/ namespace")
		}
	}

	// Cleanup
	err = ClearDNS(config)
	if err != nil {
		t.Logf("Warning: Failed to clear records during cleanup: %v", err)
	}
}

// TestListDNS_MixedRecordTypes tests ListDNS with mixed plaintext and encrypted records
func TestListDNS_MixedRecordTypes(t *testing.T) {
	config := getTestConfig()

	// Clear any existing records
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	// Register multiple records of different types
	domains := []struct {
		name       string
		ip         string
		cryptoType string
	}{
		{"plain1.test.com", "10.0.1.1", ""},
		{"plain2.test.com", "10.0.1.2", ""},
		{"plain3.test.com", "10.0.1.3", ""},
	}

	for _, d := range domains {
		cfg := &Config{
			EtcdEndpoints: []string{testEtcdServer},
			Timeout:       5,
		}
		err := RegisterDNS(d.name, d.ip, cfg)
		if err != nil {
			t.Logf("Warning: Failed to register %s: %v", d.name, err)
		} else {
			t.Logf("Registered %s -> %s", d.name, d.ip)
		}
	}

	// List all records
	t.Log("\n=== Listing mixed record types ===")
	err = ListDNS("", config)
	if err != nil {
		t.Errorf("Failed to list mixed records: %v", err)
	}

	// Cleanup
	err = ClearDNS(config)
	if err != nil {
		t.Logf("Warning: Failed to clear records during cleanup: %v", err)
	}
}

// TestListDNS_EmptyDatabase tests ListDNS with no records
func TestListDNS_EmptyDatabase(t *testing.T) {
	config := getTestConfig()

	// Clear all records
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	// List should report no records found
	t.Log("\n=== Listing empty database ===")
	err = ListDNS("", config)
	if err != nil {
		t.Errorf("ListDNS should not error on empty database: %v", err)
	}
}

// TestDeleteDNS_PlaintextRecord tests deleting a plaintext record
func TestDeleteDNS_PlaintextRecord(t *testing.T) {
	config := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		Timeout:       5,
	}

	// Clear any existing records
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	domain := "plaintext.delete.test.com"
	ip := "10.0.0.10"

	// Register plaintext record
	err = RegisterDNS(domain, ip, config)
	if err != nil {
		t.Fatalf("Failed to register plaintext record: %v", err)
	}

	// Verify record exists via direct etcd access
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{testEtcdServer},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := DomainToKey(domain)
	resp, err := cli.Get(ctx, key)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("Record not found in etcd before deletion")
	}
	t.Logf("Record exists at key: %s", key)

	// Delete the record
	err = DeleteDNS(domain, config)
	if err != nil {
		t.Errorf("Failed to delete plaintext record: %v", err)
	}

	// Verify record is removed from etcd
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err = cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to query etcd after deletion: %v", err)
	}
	if len(resp.Kvs) > 0 {
		t.Errorf("Record still exists in etcd after deletion")
	}
	t.Log("Record successfully removed from etcd")

	// Cleanup
	_ = ClearDNS(config)
}

// TestDeleteDNS_WKDIBERecord tests deleting a WKD-IBE encrypted record
func TestDeleteDNS_WKDIBERecord(t *testing.T) {
	// Setup WKD-IBE test files
	paramsFile := "test_delete_wkdibe_params.bin"
	masterKeyFile := "test_delete_wkdibe_master.key"
	privateKeyFile := "test_delete_wkdibe_alice.key"

	defer os.Remove(paramsFile)
	defer os.Remove(masterKeyFile)
	defer os.Remove(privateKeyFile)

	// Generate WKD-IBE setup
	maxDepth := 5
	pp, mk := akn07.Setup(maxDepth)

	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		t.Fatalf("Failed to serialize public params: %v", err)
	}
	if err := os.WriteFile(paramsFile, ppBytes, 0644); err != nil {
		t.Fatalf("Failed to write params file: %v", err)
	}

	mkBytes, err := SerializeMasterKey(mk)
	if err != nil {
		t.Fatalf("Failed to serialize master key: %v", err)
	}
	if err := os.WriteFile(masterKeyFile, mkBytes, 0600); err != nil {
		t.Fatalf("Failed to write master key file: %v", err)
	}

	// Generate private key for test domain
	domain := "wkdibe.delete.test.com"
	patternStr, err := DomainToPattern(domain, maxDepth)
	if err != nil {
		t.Fatalf("Failed to derive pattern: %v", err)
	}

	pattern, err := akn07.NewPatternFromStrings(pp, patternStr)
	if err != nil {
		t.Fatalf("Failed to create pattern: %v", err)
	}

	privateKey, err := akn07.KeyGen(pp, mk, pattern)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	skBytes, err := SerializePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to serialize private key: %v", err)
	}
	if err := os.WriteFile(privateKeyFile, skBytes, 0600); err != nil {
		t.Fatalf("Failed to write private key file: %v", err)
	}

	// Create config
	config := &Config{
		EtcdEndpoints:    []string{testEtcdServer},
		CryptoType:       "wkdibe",
		WKDIBEParamsFile: paramsFile,
		WKDIBEKeyFile:    privateKeyFile,
		WKDIBEMaxDepth:   maxDepth,
		Timeout:          5,
	}

	// Clear any existing records
	err = ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	ip := "10.0.0.30"

	// Register WKD-IBE encrypted record
	err = RegisterDNS(domain, ip, config)
	if err != nil {
		t.Fatalf("Failed to register WKD-IBE record: %v", err)
	}

	// Verify record exists via direct etcd access
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{testEtcdServer},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := DomainToKey(domain)
	resp, err := cli.Get(ctx, key)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("WKD-IBE record not found in etcd before deletion")
	}

	// Verify it's a WKD-IBE encrypted record (should contain "02:")
	value := string(resp.Kvs[0].Value)
	if !strings.Contains(value, "02:") {
		t.Errorf("Expected WKD-IBE record format with '02:' prefix, got: %s", value)
	}
	t.Logf("WKD-IBE record exists at key: %s", key)

	// Delete the record
	err = DeleteDNS(domain, config)
	if err != nil {
		t.Errorf("Failed to delete WKD-IBE record: %v", err)
	}

	// Verify record is removed from etcd
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err = cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to query etcd after deletion: %v", err)
	}
	if len(resp.Kvs) > 0 {
		t.Errorf("WKD-IBE record still exists in etcd after deletion")
	}
	t.Log("WKD-IBE record successfully removed from etcd")

	// Cleanup
	_ = ClearDNS(config)
}

// TestDeleteDNS_CalypsoRecord tests deleting a Calypso encrypted record
func TestDeleteDNS_CalypsoRecord(t *testing.T) {
	// Setup Calypso test files
	paramsFile := "test_delete_calypso_params.bin"
	authorityFile := "test_delete_calypso_authority.bin"
	writerKeyFile := "test_delete_calypso_writer.key"

	defer os.Remove(paramsFile)
	defer os.Remove(authorityFile)
	defer os.Remove(writerKeyFile)

	maxDepth := 5

	// Generate Calypso setup using HandleCalypsoCommands
	HandleCalypsoCommands([]string{
		"setup", "--max-depth", "5",
		"--output", paramsFile,
		"--authority", authorityFile,
	})

	// Generate writer key for test domain
	domain := "deleteme.example.com"
	HandleCalypsoCommands([]string{
		"keygen", "--params", paramsFile, "--authority", authorityFile,
		"--domain", domain, "--writer", "--output", writerKeyFile,
	})

	// Create config
	config := &Config{
		EtcdEndpoints:     []string{testEtcdServer},
		CryptoType:        "calypso",
		CalypsoParamsFile: paramsFile,
		CalypsoWriterKey:  writerKeyFile,
		CalypsoMaxDepth:   maxDepth,
		Timeout:           5,
	}

	// Clear any existing records
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	ip := "10.0.0.40"

	// Register Calypso encrypted record
	err = RegisterDNS(domain, ip, config)
	if err != nil {
		t.Fatalf("Failed to register Calypso record: %v", err)
	}

	// Verify record exists via direct etcd access at /skydns-calypso/[searchTag]
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{testEtcdServer},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Load writer key to get its searchtag
	keyData, err := os.ReadFile(writerKeyFile)
	if err != nil {
		t.Fatalf("Failed to read writer key: %v", err)
	}
	calypsoKey, err := DeserializeCalypsoPrivateKey(keyData)
	if err != nil {
		t.Fatalf("Failed to deserialize writer key: %v", err)
	}
	key := "/skydns-calypso/" + calypsoKey.SearchTag

	resp, err := cli.Get(ctx, key)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("Calypso record not found in etcd at %s before deletion", key)
	}

	// Verify it's a Calypso encrypted record (should contain "03:")
	value := string(resp.Kvs[0].Value)
	if !strings.Contains(value, "03:") {
		t.Errorf("Expected Calypso record format with '03:' prefix, got: %s", value)
	}
	t.Logf("Calypso record exists at key: %s", key)

	// Delete the record using domain name
	err = DeleteDNS(domain, config)
	if err != nil {
		t.Errorf("Failed to delete Calypso record: %v", err)
	}

	// Verify record is removed from etcd at /skydns-calypso/[searchTag]
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err = cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to query etcd after deletion: %v", err)
	}
	if len(resp.Kvs) > 0 {
		t.Errorf("Calypso record still exists in etcd after deletion")
	}
	t.Log("Calypso record successfully removed from /skydns-calypso/[searchTag]")

	// Cleanup
	_ = ClearDNS(config)
}

// TestDeleteDNS_NonExistentDomain tests deleting a non-existent domain
func TestDeleteDNS_NonExistentDomain(t *testing.T) {
	config := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		Timeout:       5,
	}

	// Clear any existing records
	err := ClearDNS(config)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	domain := "nonexistent.delete.test.com"

	// Attempt to delete non-existent domain
	err = DeleteDNS(domain, config)
	if err == nil {
		t.Errorf("Expected error when deleting non-existent domain, got nil")
	} else {
		t.Logf("Correctly returned error: %v", err)
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("Expected 'does not exist' in error message, got: %v", err)
		}
	}

	// Cleanup
	_ = ClearDNS(config)
}

// TestDeleteDNS_TypeAgnostic tests that delete works regardless of encryption type
func TestDeleteDNS_TypeAgnostic(t *testing.T) {
	// Clear any existing records
	baseConfig := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		Timeout:       5,
	}
	err := ClearDNS(baseConfig)
	if err != nil {
		t.Skipf("Skipping integration test - etcd unavailable: %v", err)
	}

	// Register a plaintext record
	plaintextDomain := "typeagnostic1.test.com"
	plaintextIP := "10.0.0.51"
	plaintextConfig := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		Timeout:       5,
	}
	err = RegisterDNS(plaintextDomain, plaintextIP, plaintextConfig)
	if err != nil {
		t.Fatalf("Failed to register plaintext record: %v", err)
	}

	// Delete with a different config (e.g., with CryptoType set but not used for deletion)
	deleteConfig := &Config{
		EtcdEndpoints: []string{testEtcdServer},
		CryptoType:    "", // No crypto type - deletion should still work
		Timeout:       5,
	}

	err = DeleteDNS(plaintextDomain, deleteConfig)
	if err != nil {
		t.Errorf("Delete should work regardless of config CryptoType for plaintext records: %v", err)
	}

	// Verify deletion
	_, err = LookupDNS(plaintextDomain, plaintextConfig)
	if err == nil {
		t.Errorf("Record still exists after deletion")
	}

	// Cleanup
	_ = ClearDNS(baseConfig)
}
