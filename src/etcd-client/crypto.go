package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type Encrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
}

type Decrypter interface {
	Decrypt(ciphertext []byte) ([]byte, error)
}

// NoOpCrypto implements both Encrypter and Decrypter with no encryption
type NoOpCrypto struct{}

func (n *NoOpCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (n *NoOpCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

// AESCrypto implements AES-256-GCM encryption/decryption
type AESCrypto struct {
	key []byte // 32-byte AES-256 key
}

func NewAESCrypto(keyFile string) (*AESCrypto, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read AES key file: %w", err)
	}

	if len(keyData) != 32 {
		return nil, fmt.Errorf("AES key must be exactly 32 bytes (256 bits), got %d bytes", len(keyData))
	}

	return &AESCrypto{key: keyData}, nil
}

func (a *AESCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (a *AESCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptRecord encrypts a DNS record using the provided Encrypter
func EncryptRecord(record *DNSRecord, encrypter Encrypter) ([]byte, error) {
	jsonRecord, err := json.Marshal(record)
	if err != nil {
		return nil, errors.New("Error converting record to JSON")
	}

	encrypted, err := encrypter.Encrypt(jsonRecord)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// DecryptRecord decrypts encrypted data back to DNS record using the provided Decrypter
func DecryptRecord(encryptedData []byte, decrypter Decrypter) (*DNSRecord, error) {
	var record DNSRecord

	jsonRecord, err := decrypter.Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonRecord, &record)
	if err != nil {
		return nil, errors.New("Error converting record from JSON")
	}

	return &record, nil
}

// DecryptWithType parses JSON wrapper and auto-detects encryption type
func DecryptWithType(data []byte, decrypters map[CryptoType]Decrypter) (*DNSRecord, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	// Parse JSON wrapper
	var wrapper map[string]interface{}
	err := json.Unmarshal(data, &wrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON wrapper: %v", err)
	}

	// Check if it's a plaintext A record: {"host": "IP", "ttl": 300}
	if _, hasHost := wrapper["host"]; hasHost {
		var record DNSRecord
		err := json.Unmarshal(data, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to parse plaintext A record: %v", err)
		}
		return &record, nil
	}

	// Check if it's an encrypted TXT record: {"text": "TYPE:BASE64", "ttl": 300}
	textVal, hasText := wrapper["text"]
	if !hasText {
		return nil, errors.New("JSON wrapper missing both 'host' and 'text' fields")
	}

	textStr, ok := textVal.(string)
	if !ok {
		return nil, errors.New("'text' field is not a string")
	}

	// Parse TYPE:BASE64 format
	if len(textStr) < 3 || textStr[2] != ':' {
		return nil, fmt.Errorf("invalid TYPE:BASE64 format: expected colon at position 2, got: %s", textStr)
	}

	typeCode := textStr[:2]
	base64Payload := textStr[3:]

	// Map type code to CryptoType
	var cryptoType CryptoType
	switch typeCode {
	case "01":
		cryptoType = AES
	case "02":
		cryptoType = WKDIBE
	case "03":
		cryptoType = Calypso
	default:
		return nil, fmt.Errorf("unknown type code: %s", typeCode)
	}

	// Get appropriate decrypter
	decrypter, exists := decrypters[cryptoType]
	if !exists {
		return nil, fmt.Errorf("no decrypter available for type %s", cryptoType)
	}

	// Base64 decode the payload
	encryptedBytes, err := base64.StdEncoding.DecodeString(base64Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode payload: %v", err)
	}

	// Decrypt using appropriate decrypter
	jsonRecord, err := decrypter.Decrypt(encryptedBytes)
	if err != nil {
		return nil, fmt.Errorf("decryption failed for type %s: %v", cryptoType, err)
	}

	// Parse decrypted JSON into DNSRecord
	var record DNSRecord
	err = json.Unmarshal(jsonRecord, &record)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted JSON: %v", err)
	}

	return &record, nil
}
