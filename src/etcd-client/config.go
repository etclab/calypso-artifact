package main

import (
	"os"
	"strconv"
	"strings"
)

// Config holds application configuration
type Config struct {
	EtcdEndpoints []string
	Timeout       int    // seconds
	CryptoType    string // "", "aes", "wkdibe", "calypso"

	// WKD-IBE fields
	WKDIBEParamsFile string // PublicParams (required for all operations)
	WKDIBEMasterKey  string // MasterKey (for keygen operations)
	WKDIBEKeyFile    string // PrivateKey (for encrypt/decrypt/sign/verify operations)
	WKDIBEMaxDepth   int    // default 5

	// Calypso fields
	CalypsoParamsFile string // PublicParams (required for all operations)
	CalypsoAuthority  string // Authority file (keygen only)
	CalypsoWriterKey  string // Writer key (encryption)
	CalypsoReaderKey  string // Reader key (decryption)
	CalypsoMaxDepth   int    // default 5, min 2

	// AES fields
	AESKeyFile string // 32-byte AES-256 key file
}

// LoadConfig loads configuration from environment variables and defaults
func LoadConfig() *Config {
	// Config struct with default values
	// Default etcd endpoint: "localhost:2379"
	// Default timeout: 5 seconds
	// Default WKD-IBE max depth: 5
	var config = Config{
		EtcdEndpoints:   []string{"localhost:2379"},
		Timeout:         5,
		WKDIBEMaxDepth:  5,
		CalypsoMaxDepth: 5,
	}

	// Read these environment variables and override defaults:
	// - ETCD_ENDPOINTS
	// - CRYPTO_TYPE
	// - WKDIBE_PARAMS_FILE
	// - WKDIBE_MASTER_KEY
	// - WKDIBE_KEY_FILE
	// - WKDIBE_MAX_DEPTH
	// - CALYPSO_PARAMS_FILE
	// - CALYPSO_AUTHORITY
	// - CALYPSO_WRITER_KEY
	// - CALYPSO_READER_KEY
	// - CALYPSO_MAX_DEPTH
	// - AES_KEY_FILE
	var os_etcd_endpoints string = os.Getenv("ETCD_ENDPOINTS")
	var os_crypto_type string = os.Getenv("CRYPTO_TYPE")
	var os_wkdibe_params_file string = os.Getenv("WKDIBE_PARAMS_FILE")
	var os_wkdibe_master_key string = os.Getenv("WKDIBE_MASTER_KEY")
	var os_wkdibe_key_file string = os.Getenv("WKDIBE_KEY_FILE")
	var os_wkdibe_max_depth string = os.Getenv("WKDIBE_MAX_DEPTH")
	var os_calypso_params_file string = os.Getenv("CALYPSO_PARAMS_FILE")
	var os_calypso_authority string = os.Getenv("CALYPSO_AUTHORITY")
	var os_calypso_writer_key string = os.Getenv("CALYPSO_WRITER_KEY")
	var os_calypso_reader_key string = os.Getenv("CALYPSO_READER_KEY")
	var os_calypso_max_depth string = os.Getenv("CALYPSO_MAX_DEPTH")
	var os_aes_key_file string = os.Getenv("AES_KEY_FILE")

	if os_etcd_endpoints != "" {
		var endpoints []string = strings.Split(os_etcd_endpoints, ",")
		config.EtcdEndpoints = endpoints
	}

	if os_crypto_type != "" {
		config.CryptoType = os_crypto_type
	}

	if os_wkdibe_params_file != "" {
		config.WKDIBEParamsFile = os_wkdibe_params_file
	}

	if os_wkdibe_master_key != "" {
		config.WKDIBEMasterKey = os_wkdibe_master_key
	}

	if os_wkdibe_key_file != "" {
		config.WKDIBEKeyFile = os_wkdibe_key_file
	}

	if os_wkdibe_max_depth != "" {
		if depth, err := strconv.Atoi(os_wkdibe_max_depth); err == nil && depth >= 2 {
			config.WKDIBEMaxDepth = depth
		}
	}

	if os_calypso_params_file != "" {
		config.CalypsoParamsFile = os_calypso_params_file
	}

	if os_calypso_authority != "" {
		config.CalypsoAuthority = os_calypso_authority
	}

	if os_calypso_writer_key != "" {
		config.CalypsoWriterKey = os_calypso_writer_key
	}

	if os_calypso_reader_key != "" {
		config.CalypsoReaderKey = os_calypso_reader_key
	}

	if os_calypso_max_depth != "" {
		if depth, err := strconv.Atoi(os_calypso_max_depth); err == nil && depth >= 2 {
			config.CalypsoMaxDepth = depth
		}
	}

	if os_aes_key_file != "" {
		config.AESKeyFile = os_aes_key_file
	}

	return &config
}
