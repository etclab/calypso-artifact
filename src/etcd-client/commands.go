package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// getCalypsoSearchTagKey derives the etcd key path for a Calypso-encrypted domain
// by loading the private key and extracting/deriving the SearchTag
func getCalypsoSearchTagKey(domain string, config *Config) (string, error) {
	// Load the Calypso key (prefer reader, fallback to writer)
	keyFile := config.CalypsoReaderKey
	if keyFile == "" {
		keyFile = config.CalypsoWriterKey
	}
	if keyFile == "" {
		return "", fmt.Errorf("CALYPSO_READER_KEY or CALYPSO_WRITER_KEY required for Calypso operations")
	}

	// Load the private key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("Error reading Calypso key file: %v", err)
	}

	calypsoKey, err := DeserializeCalypsoPrivateKey(keyData)
	if err != nil {
		return "", fmt.Errorf("Error deserializing Calypso key: %v", err)
	}

	// Use the key's SearchTag directly if domain matches
	if calypsoKey.DomainName == domain {
		return "/skydns-calypso/" + calypsoKey.SearchTag, nil
	}

	// Derive a key for the specific domain to get its SearchTag
	derivedKey, err := calypsoKey.DeriveKey(domain, false)
	if err != nil {
		return "", fmt.Errorf("Failed to derive key for domain %s: %v", domain, err)
	}

	return "/skydns-calypso/" + derivedKey.SearchTag, nil
}

// RegisterDNS registers a DNS A record in etcd
func RegisterDNS(domain, ip string, config *Config) error {
	var err error

	err = ValidateDomain(domain)
	if err != nil {
		return fmt.Errorf("Error validating domain: %v", err)
	}

	err = ValidateIP(ip)
	if err != nil {
		return fmt.Errorf("Error validating ip: %v", err)
	}

	// Create DNSRecord struct with host (ip) and TTL=300
	var record DNSRecord = DNSRecord{ip, 300}

	var encrypter Encrypter
	var cryptoType CryptoType
	var encryptedBytes []byte // For Calypso searchtag extraction

	// Determine crypto type based on config
	if config.CryptoType == "calypso" {
		// Calypso encryption
		if config.CalypsoParamsFile == "" {
			return fmt.Errorf("CALYPSO_PARAMS_FILE must be specified for Calypso encryption")
		}
		if config.CalypsoWriterKey == "" {
			return fmt.Errorf("CALYPSO_WRITER_KEY must be specified for Calypso encryption (reader keys cannot sign)")
		}

		encrypter, err = NewCalypsoEncrypter(config.CalypsoParamsFile, config.CalypsoWriterKey, domain)
		if err != nil {
			return fmt.Errorf("Error creating Calypso encrypter: %v", err)
		}
		cryptoType = Calypso
	} else if config.CryptoType == "aes" {
		// AES encryption
		if config.AESKeyFile == "" {
			return fmt.Errorf("AES_KEY_FILE must be specified for AES encryption")
		}

		encrypter, err = NewAESCrypto(config.AESKeyFile)
		if err != nil {
			return fmt.Errorf("Error creating AES encrypter: %v", err)
		}
		cryptoType = AES
	} else if config.CryptoType == "wkdibe" {
		// WKD-IBE encryption
		if config.WKDIBEParamsFile == "" {
			return fmt.Errorf("WKDIBE_PARAMS_FILE must be specified for WKD-IBE encryption")
		}
		if config.WKDIBEKeyFile == "" {
			return fmt.Errorf("WKDIBE_KEY_FILE must be specified for WKD-IBE encryption")
		}

		encrypter, err = NewWKDIBEEncrypter(config.WKDIBEParamsFile, config.WKDIBEKeyFile)
		if err != nil {
			return fmt.Errorf("Error creating WKD-IBE encrypter: %v", err)
		}
		cryptoType = WKDIBE
	} else {
		// No encryption
		encrypter = &NoOpCrypto{}
		cryptoType = NoOp
	}

	var valueBytes []byte
	if cryptoType == NoOp {
		// Store as standard CoreDNS A record: {"host": "IP", "ttl": 300}
		valueBytes, err = json.Marshal(&record)
		if err != nil {
			return fmt.Errorf("Error marshaling record: %v", err)
		}
	} else {
		// Encrypt the record (returns raw encrypted bytes without type marker)
		encryptedBytes, err = EncryptRecord(&record, encrypter)
		if err != nil {
			return fmt.Errorf("Error encrypting record: %v", err)
		}

		// Base64 encode the encrypted bytes
		encodedPayload := base64.StdEncoding.EncodeToString(encryptedBytes)

		// Prepend hex type code with colon separator
		var typeCode string
		switch cryptoType {
		case AES:
			typeCode = "01"
		case WKDIBE:
			typeCode = "02"
		case Calypso:
			typeCode = "03"
		default:
			return fmt.Errorf("Unknown crypto type: %v", cryptoType)
		}

		textValue := typeCode + ":" + encodedPayload

		// Create TXT record JSON wrapper: {"text": "TYPE:BASE64", "ttl": 300}
		txtRecord := map[string]interface{}{
			"text": textValue,
			"ttl":  300,
		}

		valueBytes, err = json.Marshal(txtRecord)
		if err != nil {
			return fmt.Errorf("Error marshaling TXT record: %v", err)
		}
	}

	// etcd client connection
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   config.EtcdEndpoints,
		DialTimeout: time.Duration(config.Timeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("etcd connection failed: %v", err)
	}
	defer cli.Close()

	// Use SearchTag-based key for Calypso (privacy-preserving storage)
	var key string
	if cryptoType == Calypso {
		// Extract searchtag from the encrypted Calypso Message
		// The encryptedBytes contain the serialized Message which includes SearchTag
		message, err := DeserializeMessage(encryptedBytes)
		if err != nil {
			return fmt.Errorf("Error deserializing Calypso message to extract SearchTag: %v", err)
		}
		key = "/skydns-calypso/" + message.SearchTag
	} else {
		key = DomainToKey(domain)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.Put(ctx, key, string(valueBytes))
	if err != nil {
		return fmt.Errorf("etcd put failed: %v", err)
	}

	fmt.Printf("Registered %s -> %s\n", domain, ip)
	return nil
}

// LookupDNS retrieves a DNS A record from etcd
func LookupDNS(domain string, config *Config) (string, error) {
	var err error

	// Validate domain
	err = ValidateDomain(domain)
	if err != nil {
		return "", fmt.Errorf("Error validating domain: %v", err)
	}

	// Connect to etcd
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   config.EtcdEndpoints,
		DialTimeout: time.Duration(config.Timeout) * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("etcd connection failed: %v", err)
	}
	defer cli.Close()

	// Determine key path based on crypto type
	var key string
	if config.CryptoType == "calypso" {
		key, err = getCalypsoSearchTagKey(domain, config)
		if err != nil {
			return "", err
		}
	} else {
		key = DomainToKey(domain)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("Error getting from etcd: %v", err)
	}

	// Check if record exists
	if len(resp.Kvs) == 0 {
		return "", fmt.Errorf("Record does not exist")
	}

	// Create decrypters map
	decrypters := make(map[CryptoType]Decrypter)
	decrypters[NoOp] = &NoOpCrypto{}

	if config.WKDIBEParamsFile != "" && config.WKDIBEKeyFile != "" {
		wkdibeDecrypter, err := NewWKDIBEDecrypter(config.WKDIBEParamsFile, config.WKDIBEKeyFile)
		if err != nil {
			return "", fmt.Errorf("Error creating WKD-IBE decrypter: %v", err)
		}
		decrypters[WKDIBE] = wkdibeDecrypter
	}

	if config.CalypsoParamsFile != "" {
		// Prefer reader key, fallback to writer key (writer can decrypt too)
		keyFile := config.CalypsoReaderKey
		if keyFile == "" {
			keyFile = config.CalypsoWriterKey
		}
		if keyFile != "" {
			calypsoDecrypter, err := NewCalypsoDecrypter(config.CalypsoParamsFile, keyFile, domain)
			if err != nil {
				return "", fmt.Errorf("Error creating Calypso decrypter: %v", err)
			}
			decrypters[Calypso] = calypsoDecrypter
		}
	}

	if config.AESKeyFile != "" {
		aesDecrypter, err := NewAESCrypto(config.AESKeyFile)
		if err != nil {
			return "", fmt.Errorf("Error creating AES decrypter: %v", err)
		}
		decrypters[AES] = aesDecrypter
	}

	decryptedRecord, err := DecryptWithType(resp.Kvs[0].Value, decrypters)
	if err != nil {
		return "", fmt.Errorf("Error decrypting record: %v", err)
	}

	// Display domain (user-provided for Calypso, extracted from key otherwise)
	displayDomain := domain
	if config.CryptoType != "calypso" {
		displayDomain = KeyToDomain(string(resp.Kvs[0].Key))
	}
	fmt.Printf("Domain: %v\nHost: %v\nTTL: %v\n", displayDomain, decryptedRecord.Host, decryptedRecord.TTL)

	return decryptedRecord.Host, nil
}

// ListDNS lists all DNS records with optional prefix
func ListDNS(prefix string, config *Config) error {
	// Connect to etcd
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   config.EtcdEndpoints,
		DialTimeout: time.Duration(config.Timeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("etcd connection failed: %v", err)
	}
	defer cli.Close()

	// Get all records with empty prefix (all keys)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "", clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("Error getting from etcd: %v", err)
	}

	if len(resp.Kvs) == 0 {
		fmt.Printf("No records found\n")
		return nil
	}

	// Loop through all records and display them
	recordCount := 0
	for _, kv := range resp.Kvs {
		key := string(kv.Key)
		value := kv.Value

		// Parse JSON value
		var record map[string]interface{}
		err := json.Unmarshal(value, &record)
		if err != nil {
			fmt.Printf("Warning: Failed to parse JSON for key %s: %v\n", key, err)
			continue
		}

		recordCount++

		// Check if it's a text record (encrypted)
		if text, ok := record["text"].(string); ok {
			// Check if it's TYPE:BASE64 format (colon at position 2)
			if len(text) > 3 && text[2] == ':' {
				typeCode := text[:2]

				// Map type code to crypto type name
				var cryptoName string
				switch typeCode {
				case "01":
					cryptoName = "AES"
				case "02":
					cryptoName = "WKD-IBE"
				case "03":
					cryptoName = "Calypso"
				default:
					cryptoName = "Unknown"
				}

				// Extract domain from key path
				var displayKey string
				if len(key) > 16 && key[:16] == "/skydns-calypso/" {
					// Calypso record - show SearchTag (cannot reverse to domain)
					displayKey = key
				} else {
					// Standard /skydns/ path - convert to domain
					displayKey = KeyToDomain(key)
				}

				fmt.Printf("Record %d:\nKey: %s\nType: [ENCRYPTED:%s]\nTTL: %v\n\n",
					recordCount, displayKey, cryptoName, record["ttl"])
			} else {
				// Non-encrypted text record
				displayKey := KeyToDomain(key)
				fmt.Printf("Record %d:\nDomain: %s\nType: TXT\nText: %s\nTTL: %v\n\n",
					recordCount, displayKey, text, record["ttl"])
			}
		} else if host, ok := record["host"].(string); ok {
			// Plaintext A record
			displayKey := KeyToDomain(key)
			fmt.Printf("Record %d:\nDomain: %s\nType: A\nHost: %s\nTTL: %v\n\n",
				recordCount, displayKey, host, record["ttl"])
		} else {
			fmt.Printf("Warning: Unknown record format for key %s\n", key)
		}
	}

	fmt.Printf("Total records: %d\n", recordCount)
	return nil
}

// DeleteDNS removes a DNS A record from etcd
func DeleteDNS(domain string, config *Config) error {
	var err error

	// Validate domain
	err = ValidateDomain(domain)
	if err != nil {
		return fmt.Errorf("Error validating domain: %v", err)
	}

	// Connect to etcd
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   config.EtcdEndpoints,
		DialTimeout: time.Duration(config.Timeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("etcd connection failed: %v", err)
	}
	defer cli.Close()

	// Determine key path based on crypto type
	var key string
	if config.CryptoType == "calypso" {
		key, err = getCalypsoSearchTagKey(domain, config)
		if err != nil {
			return err
		}
	} else {
		key = DomainToKey(domain)
	}

	// Check if record exists first
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("Error checking record existence: %v", err)
	}

	if len(resp.Kvs) == 0 {
		return fmt.Errorf("Record does not exist")
	}

	// Delete from etcd
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("etcd delete failed: %v", err)
	}

	fmt.Printf("Deleted %s\n", domain)
	return nil
}

// ClearDNS removes all DNS records from etcd
func ClearDNS(config *Config) error {
	// Connect to etcd
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   config.EtcdEndpoints,
		DialTimeout: time.Duration(config.Timeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("etcd connection failed: %v", err)
	}
	defer cli.Close()

	// Get all keys
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "", clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("Error getting records from etcd: %v", err)
	}

	if len(resp.Kvs) == 0 {
		fmt.Printf("No records to clear\n")
		return nil
	}

	// Delete all records
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.Delete(ctx, "", clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("etcd clear failed: %v", err)
	}

	fmt.Printf("Cleared %d records\n", len(resp.Kvs))
	return nil
}
