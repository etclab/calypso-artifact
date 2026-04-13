package main

import (
	"fmt"
	"os"

	"github.com/etclab/calypso"
	"github.com/etclab/ncircl/hibe/akn07"
)

// Calypso-specific serialization helpers

// SerializeAuthority serializes a Calypso Authority using upstream MarshalBinary
func SerializeAuthority(auth *calypso.Authority) ([]byte, error) {
	return auth.MarshalBinary()
}

// DeserializeAuthority deserializes a Calypso Authority using upstream UnmarshalBinary
func DeserializeAuthority(data []byte) (*calypso.Authority, error) {
	auth := &calypso.Authority{}
	if err := auth.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return auth, nil
}

// SerializeCalypsoPrivateKey serializes a Calypso PrivateKey using upstream MarshalBinary
func SerializeCalypsoPrivateKey(key *calypso.PrivateKey) ([]byte, error) {
	return key.MarshalBinary()
}

// DeserializeCalypsoPrivateKey deserializes a Calypso PrivateKey using upstream UnmarshalBinary
func DeserializeCalypsoPrivateKey(data []byte) (*calypso.PrivateKey, error) {
	key := &calypso.PrivateKey{}
	if err := key.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return key, nil
}

// SerializeMessage serializes a Calypso Message using upstream MarshalBinary
func SerializeMessage(msg *calypso.Message) ([]byte, error) {
	return msg.MarshalBinary()
}

// DeserializeMessage deserializes a Calypso Message using upstream UnmarshalBinary
func DeserializeMessage(data []byte) (*calypso.Message, error) {
	msg := &calypso.Message{}
	if err := msg.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return msg, nil
}

// CalypsoCrypto implements Encrypter/Decrypter interfaces using Calypso
type CalypsoCrypto struct {
	pp     *akn07.PublicParams
	key    *calypso.PrivateKey
	domain string
}

// NewCalypsoEncrypter creates a CalypsoCrypto instance for encryption
// Requires a writer key (reader keys cannot sign)
func NewCalypsoEncrypter(paramsFile, writerKeyFile, domain string) (*CalypsoCrypto, error) {
	// Load public params using existing helper from wkdibe.go
	paramsData, err := os.ReadFile(paramsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read params file: %w", err)
	}

	pp, err := DeserializePublicParams(paramsData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize public params: %w", err)
	}

	// Load writer key
	keyData, err := os.ReadFile(writerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read writer key file: %w", err)
	}

	key, err := DeserializeCalypsoPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	// Validate it's a writer key
	if !key.IsWriter() {
		return nil, fmt.Errorf("registration requires a writer key (reader keys cannot sign)")
	}

	return &CalypsoCrypto{
		pp:     pp,
		key:    key,
		domain: domain,
	}, nil
}

// NewCalypsoDecrypter creates a CalypsoCrypto instance for decryption
// Accepts either writer or reader keys
// Note: domain parameter is ignored - uses key.DomainName for signature verification
func NewCalypsoDecrypter(paramsFile, keyFile, domain string) (*CalypsoCrypto, error) {
	// Load public params using existing helper from wkdibe.go
	paramsData, err := os.ReadFile(paramsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read params file: %w", err)
	}

	pp, err := DeserializePublicParams(paramsData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize public params: %w", err)
	}

	// Load key (writer or reader)
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	key, err := DeserializeCalypsoPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	// CRITICAL: Use key's embedded domain for signature verification
	// This ensures Bob's key (bob.example.com) cannot decrypt Alice's messages (alice.example.com)
	return &CalypsoCrypto{
		pp:     pp,
		key:    key,
		domain: key.DomainName, // Use key's domain, not lookup domain
	}, nil
}

// Encrypt implements the Encrypter interface
// Wraps key.EncryptAndSign and serializes the Message
func (c *CalypsoCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	// Encrypt and sign using Calypso
	message, err := c.key.EncryptAndSign(c.domain, plaintext)
	if err != nil {
		return nil, fmt.Errorf("EncryptAndSign failed: %w", err)
	}

	// Serialize Message to bytes
	serialized, err := SerializeMessage(message)
	if err != nil {
		return nil, fmt.Errorf("message serialization failed: %w", err)
	}

	return serialized, nil
}

// Decrypt implements the Decrypter interface
// Deserializes the Message and wraps key.DecryptAndVerify
func (c *CalypsoCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	// Deserialize bytes to Message
	message, err := DeserializeMessage(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("message deserialization failed: %w", err)
	}

	// Decrypt and verify using Calypso
	plaintext, err := c.key.DecryptAndVerify(c.domain, message)
	if err != nil {
		return nil, fmt.Errorf("DecryptAndVerify failed (signature verification may have failed): %w", err)
	}

	return plaintext, nil
}