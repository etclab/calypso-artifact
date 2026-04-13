package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Check for wkdibe subcommands before flag parsing
	if len(os.Args) > 1 && os.Args[1] == "wkdibe" {
		HandleWKDIBECommands(os.Args[2:])
		return
	}

	// Check for calypso subcommands before flag parsing
	if len(os.Args) > 1 && os.Args[1] == "calypso" {
		HandleCalypsoCommands(os.Args[2:])
		return
	}

	config := LoadConfig()

	var register = flag.String("register", "", "Register DNS A record using etcd client API, given in the form domain=ip")
	var lookup = flag.String("lookup", "", "Lookup DNS A record from etcd, given a domain")
	var list = flag.Bool("list", false, "List all DNS records from etcd")
	var delete = flag.String("delete", "", "Delete DNS A record from etcd, given a domain")
	var clear = flag.Bool("clear", false, "Clear all DNS records from etcd")
	var help = flag.Bool("help", false, "Show help")

	flag.Parse()

	if *help || (*register == "" && *lookup == "" && !*list && *delete == "" && !*clear) {
		showHelp()
		return
	}

	if *register != "" {
		registerVals := strings.Split(*register, "=")
		if len(registerVals) != 2 {
			fmt.Fprintf(os.Stderr, "Error: Invalid register format. Use: domain=ip\n")
			os.Exit(1)
		}
		domain := registerVals[0]
		ip := registerVals[1]

		err := RegisterDNS(domain, ip, config)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error registering DNS: %v\n", err)
			os.Exit(1)
		}
	}

	if *lookup != "" {
		_, err := LookupDNS(*lookup, config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error looking up DNS: %v\n", err)
			os.Exit(1)
		}
	}

	if *list {
		err := ListDNS("", config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing DNS: %v\n", err)
			os.Exit(1)
		}
	}

	if *delete != "" {
		err := DeleteDNS(*delete, config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting DNS: %v\n", err)
			os.Exit(1)
		}
	}

	if *clear {
		err := ClearDNS(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error clearing DNS: %v\n", err)
			os.Exit(1)
		}
	}

	if !*help && *register == "" && *lookup == "" && !*list && *delete == "" && !*clear {
		fmt.Printf("etcd-client: No command specified. Use -help for usage.\n")
	}
}

func showHelp() {
	fmt.Printf(`etcd-client - A command-line etcd client with support for AES, WKD-IBE, and Calypso encryption schemes.

USAGE:
    etcd-client [OPTIONS]
    etcd-client wkdibe <subcommand> [OPTIONS]
    etcd-client calypso <subcommand> [OPTIONS]

OPTIONS:
    -register domain=ip    Register DNS A record using etcd client API
    -lookup domain         Lookup DNS A record from etcd
    -list                  List all DNS records from etcd (excludes Calypso namespace)
    -delete domain         Delete DNS A record from etcd
    -clear                 Clear all DNS records from etcd
    -help                  Show this help

WKD-IBE SUBCOMMANDS:
    wkdibe setup           Generate WKD-IBE public parameters and master key
    wkdibe keygen          Generate identity key from master key
    wkdibe keyder          Derive child key from parent key

CALYPSO SUBCOMMANDS:
    calypso setup          Generate Calypso authority and public parameters
    calypso keygen         Generate identity key from authority (writer or reader)
    calypso reader         Derive reader key from writer key
    calypso keyder         Derive child key from parent key (requires wildcard)

EXAMPLES:
    # Basic operations
    etcd-client -register api.example.com=192.168.1.10
    etcd-client -lookup api.example.com
    etcd-client -list
    etcd-client -delete api.example.com
    etcd-client -clear
	
	# AES encryption
	openssl rand -out aes.key 32
	AES_KEY_FILE=aes.key CRYPTO_TYPE=aes \
		etcd-client -register api.example.com=10.0.0.1
	AES_KEY_FILE=aes.key CRYPTO_TYPE=aes \
		etcd-client -lookup api.example.com

    # WKD-IBE setup and usage
    etcd-client wkdibe setup --max-depth 5
    etcd-client wkdibe keygen --params params.bin --master-key master.key \
        --pattern "com,example,alice" --output alice.key
    CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice.key \
        etcd-client -lookup alice.example.com

    # Calypso setup and usage
    etcd-client calypso setup --max-depth 5
    etcd-client calypso keygen --params params.bin --authority auth.bin \
        --domain "alice.example.com" --writer --output alice-writer.key
    CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=params.bin CALYPSO_WRITER_KEY=alice-writer.key \
        etcd-client -register alice.example.com=10.0.0.1


ENVIRONMENT VARIABLES:
    General:
        ETCD_ENDPOINTS           etcd server endpoints (default: localhost:2379)
        CRYPTO_TYPE              Encryption scheme: "", "aes", "wkdibe", "calypso"
		
	AES (CRYPTO_TYPE=aes):
		AES_KEY_FILE             32-byte AES-256 key file
		
    WKD-IBE (CRYPTO_TYPE=wkdibe):
        WKDIBE_PARAMS_FILE       Public parameters file
        WKDIBE_MASTER_KEY        Master key file (for keygen)
        WKDIBE_KEY_FILE          Identity key file (for decryption)
        WKDIBE_MAX_DEPTH         Maximum hierarchy depth (default: 5, min: 2)

    Calypso (CRYPTO_TYPE=calypso):
        CALYPSO_PARAMS_FILE      Public parameters file
        CALYPSO_AUTHORITY        Authority file (for keygen)
        CALYPSO_WRITER_KEY       Writer key file (for encryption/signing)
        CALYPSO_READER_KEY       Reader key file (for decryption)
        CALYPSO_MAX_DEPTH        Maximum hierarchy depth (default: 5, min: 2)

Use 'etcd-client wkdibe help' or 'etcd-client calypso help' for detailed subcommand help.
`)
}
