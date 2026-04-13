package main

import (
	"testing"
)

func TestDNSRecord(t *testing.T) {
	// Test creating a DNS record
	record := DNSRecord{
		Host: "192.168.1.10",
		TTL:  300,
	}

	if record.Host != "192.168.1.10" {
		t.Errorf("Expected host '192.168.1.10', got %s", record.Host)
	}
}

func TestDomainToKey(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"api.example.com", "/skydns/com/example/api"},
		{"www.google.com", "/skydns/com/google/www"},
		{"service.local", "/skydns/local/service"},
	}

	for _, test := range tests {
		t.Run(test.domain, func(t *testing.T) {
			result := DomainToKey(test.domain)
			if result != test.expected {
				t.Errorf("DomainToKey(%s) = %s, expected %s", test.domain, result, test.expected)
			}
		})
	}
}

func TestKeyToDomain(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"/skydns/com/example/api", "api.example.com"},
		{"/skydns/com/google/www", "www.google.com"},
		{"/skydns/local/service", "service.local"},
	}

	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			result := KeyToDomain(test.key)
			if result != test.expected {
				t.Errorf("KeyToDomain(%s) = %s, expected %s", test.key, result, test.expected)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		domain    string
		shouldErr bool
		name      string
	}{
		{"api.example.com", false, "valid domain"},
		{"", true, "empty domain"},
		{"localhost", true, "no dot"},
		{"test.local", false, "valid short domain"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateDomain(test.domain)
			if test.shouldErr && err == nil {
				t.Errorf("Expected error for domain '%s', but got none", test.domain)
			}
			if !test.shouldErr && err != nil {
				t.Errorf("Expected no error for domain '%s', but got: %v", test.domain, err)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		ip        string
		shouldErr bool
		name      string
	}{
		{"192.168.1.10", false, "valid IP"},
		{"", true, "empty IP"},
		{"192.168.1", true, "incomplete IP"},
		{"10.0.0.1", false, "valid private IP"},
		{"192.168.1.1.1", true, "too many parts"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateIP(test.ip)
			if test.shouldErr && err == nil {
				t.Errorf("Expected error for IP '%s', but got none", test.ip)
			}
			if !test.shouldErr && err != nil {
				t.Errorf("Expected no error for IP '%s', but got: %v", test.ip, err)
			}
		})
	}
}

// Test the round-trip conversion: domain -> key -> domain
func TestDomainKeyRoundTrip(t *testing.T) {
	domains := []string{
		"api.example.com",
		"www.google.com",
		"service.local",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			key := DomainToKey(domain)
			result := KeyToDomain(key)
			if result != domain {
				t.Errorf("Round trip failed: %s -> %s -> %s", domain, key, result)
			}
		})
	}
}