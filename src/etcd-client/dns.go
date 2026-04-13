package main

import (
	"errors"
	"strings"
)

// DNSRecord represents a DNS A record
type DNSRecord struct {
	Host string `json:"host"`
	TTL  int    `json:"ttl"`
}

// DomainToKey converts a domain name to etcd key format
// Example: "api.example.com" -> "/skydns/com/example/api"
func DomainToKey(domain string) string {
	// Reverse to: ["com", "example", "api"]
	// Join with "/" and add "/skydns/" prefix

	var domainSlice []string = strings.Split(domain, ".")
	var key string = "/skydns/"

	for i := len(domainSlice) - 1; i >= 0; i-- {
		key = key + domainSlice[i]
		if i != 0 {
			key = key + "/"
		}
	}

	return key
}

// KeyToDomain converts etcd key back to domain name
// Example: "/skydns/com/example/api" -> "api.example.com"
func KeyToDomain(key string) string {
	// Split into slice by "/"
	var keySlice []string = strings.Split(key, "/")

	// Remove "skydns" prefix
	keySlice = keySlice[2:]

	// Reverse and put into domain format
	var domain string
	for i := len(keySlice) - 1; i >= 0; i-- {
		domain = domain + keySlice[i]
		if i != 0 {
			domain = domain + "."
		}
	}

	return domain
}

// ValidateDomain performs basic domain validation and returns appropriate error messages
func ValidateDomain(domain string) error {
	// Check if domain is empty
	if domain == "" {
		return errors.New("Domain cannot be empty")
	}

	// Check if domain contains at least one "."
	if !strings.Contains(domain, ".") {
		return errors.New("Domain must contain at least one \".\"")
	}

	return nil
}

// ValidateIP performs basic IP validation (IPv4) and returns appropriate error messages
func ValidateIP(ip string) error {
	// Check if IP is empty
	if ip == "" {
		return errors.New("IP cannot be empty")
	}

	// Check if IP has 4 parts separated by "."
	var splitIP []string = strings.Split(ip, ".")
	var dotCount int = strings.Count(ip, ".")
	if len(splitIP) != 4 || dotCount != 3 {
		return errors.New("IP must have four parts separated by \".\"")
	}

	return nil
}
