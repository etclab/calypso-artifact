package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/bytesx"
)

// Serialization helpers for WKD-IBE structures

func SerializePublicParams(pp *akn07.PublicParams) ([]byte, error) {
	return pp.MarshalBinary()
}

func DeserializePublicParams(data []byte) (*akn07.PublicParams, error) {
	pp := &akn07.PublicParams{}
	if err := pp.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return pp, nil
}

func SerializeMasterKey(mk *akn07.MasterKey) ([]byte, error) {
	return mk.MarshalBinary()
}

func DeserializeMasterKey(data []byte) (*akn07.MasterKey, error) {
	mk := &akn07.MasterKey{}
	if err := mk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return mk, nil
}

func SerializePrivateKey(sk *akn07.PrivateKey) ([]byte, error) {
	return sk.MarshalBinary()
}

func DeserializePrivateKey(data []byte) (*akn07.PrivateKey, error) {
	sk := &akn07.PrivateKey{}
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return sk, nil
}

// Pattern conversion helpers

// DomainToPattern converts a DNS domain to a WKD-IBE pattern
// Example: "alice.example.com" with maxDepth=5 → ["com", "example", "alice", "", ""]
// Wildcard example: "*.example.com" → ["com", "example", "", "", ""]
// Remaining slots padded with empty strings (wildcards use empty strings, not slots for signatures)
func DomainToPattern(domain string, maxDepth int) ([]string, error) {
	if maxDepth < 2 {
		return nil, errors.New("maxDepth must be at least 2")
	}

	parts := strings.Split(domain, ".")
	if len(parts) > maxDepth-1 {
		return nil, errors.New("domain exceeds maxDepth capacity")
	}

	pattern := make([]string, maxDepth)

	// Reverse domain parts and handle wildcards (alice.example.com → com, example, alice)
	wildcardSeen := false
	for i := 0; i < len(parts); i++ {
		reversedIdx := len(parts) - 1 - i
		part := parts[reversedIdx]

		// Check for wildcard marker
		if part == "*" {
			wildcardSeen = true
			pattern[i] = "" // Wildcard represented as empty string
		} else {
			// Validate: concrete labels cannot follow wildcards
			if wildcardSeen {
				return nil, errors.New("invalid pattern: concrete labels cannot follow wildcards")
			}
			if part == "" {
				return nil, errors.New("invalid pattern: empty labels not allowed (use * for wildcards)")
			}
			pattern[i] = part
		}
	}

	// Remaining slots are padding (empty strings for unused positions)

	return pattern, nil
}

// PatternToDomain converts a WKD-IBE pattern back to a DNS domain
// Example: ["com", "example", "alice", "", ""] → "alice.example.com"
func PatternToDomain(pattern []string) (string, error) {
	if len(pattern) == 0 {
		return "", errors.New("empty pattern")
	}

	// Find the first empty slot (wildcards at the end)
	endIdx := len(pattern)
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == "" {
			endIdx = i
			break
		}
	}

	if endIdx == 0 {
		return "", errors.New("pattern has no fixed components")
	}

	// Reverse back to domain format
	parts := make([]string, endIdx)
	for i := 0; i < endIdx; i++ {
		parts[i] = pattern[endIdx-1-i]
	}

	return strings.Join(parts, "."), nil
}


// WKDIBECrypto implements WKD-IBE encryption/decryption using akn07 scheme
type WKDIBECrypto struct {
	pp      *akn07.PublicParams
	pattern *akn07.Pattern
	key     *akn07.PrivateKey // nil for encryption-only
}

// NewWKDIBEEncrypter creates a WKDIBECrypto instance for encryption
// Requires a key for signing (same key used for encrypt/decrypt/sign/verify)
func NewWKDIBEEncrypter(paramsFile, keyFile string) (*WKDIBECrypto, error) {
	// Load params
	paramsData, err := os.ReadFile(paramsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read params file: %w", err)
	}

	pp, err := DeserializePublicParams(paramsData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize public params: %w", err)
	}

	// Load key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	key, err := DeserializePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	// Pattern comes from key, not parameter
	return &WKDIBECrypto{
		pp:      pp,
		pattern: key.Pattern,
		key:     key,
	}, nil
}

// NewWKDIBEDecrypter creates a WKDIBECrypto instance for decryption
func NewWKDIBEDecrypter(paramsFile, keyFile string) (*WKDIBECrypto, error) {
	paramsData, err := os.ReadFile(paramsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read params file: %w", err)
	}

	pp, err := DeserializePublicParams(paramsData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize public params: %w", err)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	key, err := DeserializePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	return &WKDIBECrypto{
		pp:      pp,
		pattern: key.Pattern, // Use pattern from key
		key:     key,
	}, nil
}

// Encrypt implements hybrid WKD-IBE encryption:
// 1. Generate random Gt element
// 2. WKD-IBE encrypt Gt → ciphertext
// 3. KDF(Gt) → AES-256 key
// 4. AES-CTR encrypt plaintext
// 5. Sign plaintext
// 6. Pack: [IV_len|IV|AES_ct_len|AES_ct|WKDIBE_ct_len|WKDIBE_ct|Sig_len|Sig]
func (h *WKDIBECrypto) Encrypt(plaintext []byte) ([]byte, error) {
	if h.pattern == nil {
		return nil, fmt.Errorf("pattern not set for encryption")
	}
	if h.key == nil {
		return nil, fmt.Errorf("private key not set for signing")
	}

	// 1. Generate random Gt element
	m := blspairing.NewRandomGt()

	// 2. WKD-IBE encrypt the Gt
	hibeCt, err := akn07.Encrypt(h.pp, h.pattern, m)
	if err != nil {
		return nil, fmt.Errorf("WKD-IBE encryption failed: %w", err)
	}

	// 3. Derive AES key from Gt
	aesKey := blspairing.KdfGtToAes256(m)

	// 4. Generate IV and encrypt plaintext with AES-CTR
	// Note: EncryptCTR modifies the input buffer in-place, so we must make a copy
	iv := bytesx.Random(16)
	plaintextCopy := make([]byte, len(plaintext))
	copy(plaintextCopy, plaintext)
	aesCt, err := aesx.EncryptCTR(aesKey, iv, plaintextCopy)
	if err != nil {
		return nil, fmt.Errorf("AES encryption failed: %w", err)
	}

	// 5. Serialize WKD-IBE ciphertext
	hibeCtBytes, err := hibeCt.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("WKD-IBE ciphertext serialization failed: %w", err)
	}

	// 6. Sign plaintext
	plaintextHash := blspairing.HashBytesToScalar(plaintext)
	sig := akn07.Sign(h.pp, h.key, plaintextHash)
	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("signature serialization failed: %w", err)
	}

	// 7. Pack everything together
	// Format: [IV_len(2)|IV(16)|AES_ct_len(4)|AES_ct(N)|WKDIBE_ct_len(4)|WKDIBE_ct(M)|Sig_len(4)|Sig(S)]
	ivLen := uint16(len(iv))
	aesCtLen := uint32(len(aesCt))
	hibeCtLen := uint32(len(hibeCtBytes))
	sigLen := uint32(len(sigBytes))

	// Calculate total size
	totalSize := 2 + len(iv) + 4 + len(aesCt) + 4 + len(hibeCtBytes) + 4 + len(sigBytes)
	result := make([]byte, totalSize)

	offset := 0

	binary.BigEndian.PutUint16(result[offset:], ivLen)
	offset += 2

	copy(result[offset:], iv)
	offset += len(iv)

	binary.BigEndian.PutUint32(result[offset:], aesCtLen)
	offset += 4

	copy(result[offset:], aesCt)
	offset += len(aesCt)

	binary.BigEndian.PutUint32(result[offset:], hibeCtLen)
	offset += 4

	copy(result[offset:], hibeCtBytes)
	offset += len(hibeCtBytes)

	binary.BigEndian.PutUint32(result[offset:], sigLen)
	offset += 4

	copy(result[offset:], sigBytes)

	return result, nil
}

// Decrypt implements hybrid WKD-IBE decryption:
// 1. Unpack ciphertext
// 2. WKD-IBE decrypt → Gt
// 3. KDF(Gt) → AES-256 key
// 4. AES-CTR decrypt → plaintext
// 5. Verify signature
func (h *WKDIBECrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	if h.key == nil {
		return nil, fmt.Errorf("private key not set for decryption")
	}

	// Minimum size check: IV_len(2) + IV(16) + AES_ct_len(4) + WKDIBE_ct_len(4) + Sig_len(4) + data
	if len(ciphertext) < 2+16+4+4+4+1 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	offset := 0

	// 1. Parse IV length and IV
	ivLen := binary.BigEndian.Uint16(ciphertext[offset:])
	offset += 2
	if offset+int(ivLen) > len(ciphertext) {
		return nil, fmt.Errorf("invalid IV length")
	}
	iv := ciphertext[offset : offset+int(ivLen)]
	offset += int(ivLen)

	// 2. Parse AES ciphertext length and AES ciphertext
	if offset+4 > len(ciphertext) {
		return nil, fmt.Errorf("ciphertext too short for AES length")
	}
	aesCtLen := binary.BigEndian.Uint32(ciphertext[offset:])
	offset += 4
	if offset+int(aesCtLen) > len(ciphertext) {
		return nil, fmt.Errorf("invalid AES ciphertext length")
	}
	aesCt := ciphertext[offset : offset+int(aesCtLen)]
	offset += int(aesCtLen)

	// 3. Parse WKDIBE ciphertext with explicit length
	if offset+4 > len(ciphertext) {
		return nil, fmt.Errorf("ciphertext too short for WKDIBE length")
	}
	hibeCtLen := binary.BigEndian.Uint32(ciphertext[offset:])
	offset += 4
	if offset+int(hibeCtLen) > len(ciphertext) {
		return nil, fmt.Errorf("invalid WKDIBE ciphertext length")
	}
	hibeCtBytes := ciphertext[offset : offset+int(hibeCtLen)]
	offset += int(hibeCtLen)

	// 4. Parse signature
	if offset+4 > len(ciphertext) {
		return nil, fmt.Errorf("ciphertext too short for signature length")
	}
	sigLen := binary.BigEndian.Uint32(ciphertext[offset:])
	offset += 4
	if offset+int(sigLen) > len(ciphertext) {
		return nil, fmt.Errorf("invalid signature length")
	}
	sigBytes := ciphertext[offset : offset+int(sigLen)]
	sig := &akn07.Signature{}
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		return nil, fmt.Errorf("signature deserialization failed: %w", err)
	}

	// 5. Deserialize and decrypt WKD-IBE ciphertext
	hibeCt := &akn07.Ciphertext{}
	if err := hibeCt.UnmarshalBinary(hibeCtBytes); err != nil {
		return nil, fmt.Errorf("WKD-IBE ciphertext deserialization failed: %w", err)
	}

	// 6. WKD-IBE decrypt to get Gt
	m := akn07.Decrypt(h.pp, h.key, hibeCt)

	// 7. Derive AES key from Gt
	aesKey := blspairing.KdfGtToAes256(m)

	// 8. AES-CTR decrypt
	plaintext, err := aesx.DecryptCTR(aesKey, iv, aesCt)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	// 9. Verify signature
	plaintextHash := blspairing.HashBytesToScalar(plaintext)
	if !akn07.Verify(h.pp, h.key.Pattern, sig, plaintextHash) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return plaintext, nil
}