package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/etclab/ncircl/hibe/akn07"
)

// HandleWKDIBECommands handles all WKD-IBE-related subcommands
func HandleWKDIBECommands(args []string) {
	if len(args) < 1 {
		showWKDIBEHelp()
		os.Exit(1)
	}

	subcommand := args[0]

	switch subcommand {
	case "setup":
		handleWKDIBESetup(args[1:])
	case "keygen":
		handleWKDIBEKeyGen(args[1:])
	case "keyder":
		handleWKDIBEKeyDerive(args[1:])
	case "help", "-h", "--help":
		showWKDIBEHelp()
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown wkdibe subcommand: %s\n", subcommand)
		showWKDIBEHelp()
		os.Exit(1)
	}
}

func handleWKDIBESetup(args []string) {
	fs := flag.NewFlagSet("wkdibe setup", flag.ExitOnError)
	maxDepth := fs.Int("max-depth", 5, "Maximum depth for WKD-IBE hierarchy")
	output := fs.String("output", "params.bin", "Output file for public parameters")
	masterKey := fs.String("master-key", "master.key", "Output file for master key")

	fs.Parse(args)

	// Validate maxDepth
	if *maxDepth < 2 {
		fmt.Fprintf(os.Stderr, "Error: max-depth must be at least 2\n")
		os.Exit(1)
	}

	fmt.Printf("Generating WKD-IBE setup with max-depth=%d...\n", *maxDepth)

	// Generate public params and master key
	pp, mk := akn07.Setup(*maxDepth)

	// Serialize and save public params
	ppBytes, err := SerializePublicParams(pp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing public params: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, ppBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public params to %s: %v\n", *output, err)
		os.Exit(1)
	}

	// Serialize and save master key
	mkBytes, err := SerializeMasterKey(mk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing master key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*masterKey, mkBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing master key to %s: %v\n", *masterKey, err)
		os.Exit(1)
	}

	fmt.Printf("Public parameters saved to: %s\n", *output)
	fmt.Printf("Master key saved to: %s\n", *masterKey)
	fmt.Printf("MaxDepth: %d\n", *maxDepth)
}

func handleWKDIBEKeyGen(args []string) {
	fs := flag.NewFlagSet("wkdibe keygen", flag.ExitOnError)
	paramsFile := fs.String("params", "params.bin", "Public parameters file")
	masterKeyFile := fs.String("master-key", "master.key", "Master key file")
	domain := fs.String("domain", "", "Domain name (e.g. 'alice.example.com' or '*.example.com')")
	output := fs.String("output", "identity.key", "Output file for private key")

	fs.Parse(args)

	// Validate required flags
	if *domain == "" {
		fmt.Fprintf(os.Stderr, "Error: --domain is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load public params
	ppBytes, err := os.ReadFile(*paramsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading params file %s: %v\n", *paramsFile, err)
		os.Exit(1)
	}

	pp, err := DeserializePublicParams(ppBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public params: %v\n", err)
		os.Exit(1)
	}

	// Load master key
	mkBytes, err := os.ReadFile(*masterKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading master key file %s: %v\n", *masterKeyFile, err)
		os.Exit(1)
	}

	mk, err := DeserializeMasterKey(mkBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing master key: %v\n", err)
		os.Exit(1)
	}

	// Convert domain to pattern (akn07.NewPatternFromStrings handles validation)
	patternStr, err := DomainToPattern(*domain, pp.MaxDepth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting domain to pattern: %v\n", err)
		os.Exit(1)
	}

	pattern, err := akn07.NewPatternFromStrings(pp, patternStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating pattern: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generating private key for domain: %s\n", *domain)

	// Generate private key
	sk, err := akn07.KeyGen(pp, mk, pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
		os.Exit(1)
	}

	// Serialize and save private key
	skBytes, err := SerializePrivateKey(sk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing private key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, skBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing private key to %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("Private key saved to: %s\n", *output)
}

func handleWKDIBEKeyDerive(args []string) {
	fs := flag.NewFlagSet("wkdibe keyder", flag.ExitOnError)
	paramsFile := fs.String("params", "params.bin", "Public parameters file")
	parentKeyFile := fs.String("parent-key", "", "Parent private key file")
	domain := fs.String("domain", "", "Child domain name (e.g. 'alice.example.com')")
	output := fs.String("output", "child.key", "Output file for child private key")

	fs.Parse(args)

	// Validate required flags
	if *parentKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --parent-key is required\n")
		fs.Usage()
		os.Exit(1)
	}
	if *domain == "" {
		fmt.Fprintf(os.Stderr, "Error: --domain is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load public params
	ppBytes, err := os.ReadFile(*paramsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading params file %s: %v\n", *paramsFile, err)
		os.Exit(1)
	}

	pp, err := DeserializePublicParams(ppBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public params: %v\n", err)
		os.Exit(1)
	}

	// Load parent key
	parentKeyBytes, err := os.ReadFile(*parentKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading parent key file %s: %v\n", *parentKeyFile, err)
		os.Exit(1)
	}

	parentKey, err := DeserializePrivateKey(parentKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing parent key: %v\n", err)
		os.Exit(1)
	}

	// Convert domain to pattern (akn07.NewPatternFromStrings handles validation)
	patternStr, err := DomainToPattern(*domain, pp.MaxDepth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting domain to pattern: %v\n", err)
		os.Exit(1)
	}

	pattern, err := akn07.NewPatternFromStrings(pp, patternStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating pattern: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deriving child key for domain: %s\n", *domain)

	// Derive child key
	childKey, err := akn07.KeyDer(pp, parentKey, pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving child key: %v\n", err)
		os.Exit(1)
	}

	// Serialize and save child key
	childKeyBytes, err := SerializePrivateKey(childKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing child key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, childKeyBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing child key to %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("Child key saved to: %s\n", *output)
}

func showWKDIBEHelp() {
	fmt.Printf(`etcd-client wkdibe - WKD-IBE key management commands

USAGE:
    etcd-client wkdibe <subcommand> [OPTIONS]

SUBCOMMANDS:
    setup        Generate WKD-IBE public parameters and master key
    keygen       Generate identity key from master key
    keyder       Derive child key from parent key
    help         Show this help

EXAMPLES:
    # Generate WKD-IBE setup with default max-depth=5
    etcd-client wkdibe setup

    # Generate identity key for alice.example.com
    etcd-client wkdibe keygen --params params.bin --master-key master.key \
        --domain "alice.example.com" --output alice.key

    # Generate wildcard key for *.example.com (use * for wildcards)
    etcd-client wkdibe keygen --params params.bin --master-key master.key \
        --domain "*.example.com" --output wildcard.key

    # Derive child key from parent key
    etcd-client wkdibe keyder --params params.bin --parent-key example.key \
        --domain "alice.subdomain.example.com" --output subdomain.key

    # Derive specific key from wildcard parent
    etcd-client wkdibe keyder --params params.bin --parent-key wildcard.key \
        --domain "alice.example.com" --output alice.key

Use 'etcd-client wkdibe <subcommand> -h' for more information about a subcommand.
`)
}
