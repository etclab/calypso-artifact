package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type KeyPair struct {
	Algorithm  string
	PrivateKey interface{}
	PublicKey  interface{}
}

func generateKeyPair(algorithm string) (*KeyPair, error) {
	switch algorithm {
	case "RS256":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
		}
		return &KeyPair{
			Algorithm:  algorithm,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}, nil

	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
		}
		return &KeyPair{
			Algorithm:  algorithm,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}, nil

	case "EdDSA":
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate EdDSA private key: %w", err)
		}
		return &KeyPair{
			Algorithm:  algorithm,
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func savePrivateKey(keyPair *KeyPair, filename string) error {
	var privateKeyBytes []byte
	var pemType string
	var err error

	switch keyPair.Algorithm {
	case "RS256":
		rsaKey := keyPair.PrivateKey.(*rsa.PrivateKey)
		privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			return fmt.Errorf("failed to marshal RSA private key: %w", err)
		}
		pemType = "PRIVATE KEY"
	case "ES256":
		ecdsaKey := keyPair.PrivateKey.(*ecdsa.PrivateKey)
		privateKeyBytes, err = x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		pemType = "EC PRIVATE KEY"
	case "EdDSA":
		ed25519Key := keyPair.PrivateKey.(ed25519.PrivateKey)
		privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(ed25519Key)
		if err != nil {
			return fmt.Errorf("failed to marshal EdDSA private key: %w", err)
		}
		pemType = "PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported algorithm: %s", keyPair.Algorithm)
	}

	privateKeyPEM := pem.Block{
		Type:  pemType,
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &privateKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}

func savePublicKey(keyPair *KeyPair, filename string) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(keyPair.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &publicKeyPEM); err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	return nil
}

func loadPrivateKey(filename string) (interface{}, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		return privateKey, nil

	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		return privateKey, nil

	default:
		return nil, fmt.Errorf("unsupported private key type %s (use PKCS#8 format for RSA keys)", block.Type)
	}
}

func loadPublicKeyFromFile(filename string) (interface{}, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return publicKeyInterface, nil
}