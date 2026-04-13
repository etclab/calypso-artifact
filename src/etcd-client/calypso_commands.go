package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/etclab/calypso"
)

// HandleCalypsoCommands handles all Calypso-related subcommands
func HandleCalypsoCommands(args []string) {
	if len(args) < 1 {
		showCalypsoHelp()
		os.Exit(1)
	}

	subcommand := args[0]

	switch subcommand {
	case "setup":
		handleCalypsoSetup(args[1:])
	case "keygen":
		handleCalypsoKeyGen(args[1:])
	case "reader":
		handleCalypsoReader(args[1:])
	case "keyder":
		handleCalypsoKeyDerive(args[1:])
	case "help", "-h", "--help":
		showCalypsoHelp()
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown calypso subcommand: %s\n", subcommand)
		showCalypsoHelp()
		os.Exit(1)
	}
}

func handleCalypsoSetup(args []string) {
	fs := flag.NewFlagSet("calypso setup", flag.ExitOnError)
	maxDepth := fs.Int("max-depth", 5, "Maximum depth for Calypso hierarchy")
	output := fs.String("output", "params.bin", "Output file for public parameters")
	authority := fs.String("authority", "authority.bin", "Output file for authority (contains master key)")

	fs.Parse(args)

	// Validate maxDepth
	if *maxDepth < 2 {
		fmt.Fprintf(os.Stderr, "Error: max-depth must be at least 2\n")
		os.Exit(1)
	}

	fmt.Printf("Generating Calypso setup with max-depth=%d...\n", *maxDepth)

	// Generate authority (includes PublicParams and MasterKey)
	auth := calypso.NewAuthority(*maxDepth)

	// Serialize and save public params
	ppBytes, err := SerializePublicParams(auth.PublicParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing public params: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, ppBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public params to %s: %v\n", *output, err)
		os.Exit(1)
	}

	// Serialize and save authority
	authBytes, err := SerializeAuthority(auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing authority: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*authority, authBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing authority to %s: %v\n", *authority, err)
		os.Exit(1)
	}

	fmt.Printf("Public parameters saved to: %s\n", *output)
	fmt.Printf("Authority saved to: %s\n", *authority)
	fmt.Printf("MaxDepth: %d\n", *maxDepth)
}

func handleCalypsoKeyGen(args []string) {
	fs := flag.NewFlagSet("calypso keygen", flag.ExitOnError)
	paramsFile := fs.String("params", "params.bin", "Public parameters file")
	authorityFile := fs.String("authority", "authority.bin", "Authority file")
	domain := fs.String("domain", "", "Domain name (e.g. 'alice.example.com' or '*.example.com')")
	writer := fs.Bool("writer", false, "Generate writer key (default: reader key)")
	output := fs.String("output", "identity.key", "Output file for private key")

	fs.Parse(args)

	// Validate required flags
	if *domain == "" {
		fmt.Fprintf(os.Stderr, "Error: --domain is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load public params (not strictly needed but validates file)
	ppBytes, err := os.ReadFile(*paramsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading params file %s: %v\n", *paramsFile, err)
		os.Exit(1)
	}

	_, err = DeserializePublicParams(ppBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing public params: %v\n", err)
		os.Exit(1)
	}

	// Load authority
	authBytes, err := os.ReadFile(*authorityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading authority file %s: %v\n", *authorityFile, err)
		os.Exit(1)
	}

	auth, err := DeserializeAuthority(authBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing authority: %v\n", err)
		os.Exit(1)
	}

	keyType := "reader"
	if *writer {
		keyType = "writer"
	}

	fmt.Printf("Generating %s key for domain: %s\n", keyType, *domain)

	// Issue private key
	key, err := auth.IssueKey(*domain, *writer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error issuing key: %v\n", err)
		os.Exit(1)
	}

	// Serialize and save private key
	keyBytes, err := SerializeCalypsoPrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing private key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, keyBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing private key to %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("%s key saved to: %s\n", keyType, *output)
}

func handleCalypsoReader(args []string) {
	fs := flag.NewFlagSet("calypso reader", flag.ExitOnError)
	writerKeyFile := fs.String("writer", "", "Writer key file")
	output := fs.String("output", "reader.key", "Output file for reader key")

	fs.Parse(args)

	// Validate required flags
	if *writerKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --writer is required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load writer key
	writerKeyBytes, err := os.ReadFile(*writerKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading writer key file %s: %v\n", *writerKeyFile, err)
		os.Exit(1)
	}

	writerKey, err := DeserializeCalypsoPrivateKey(writerKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing writer key: %v\n", err)
		os.Exit(1)
	}

	// Validate it's a writer key
	if !writerKey.IsWriter() {
		fmt.Fprintf(os.Stderr, "Error: input key must be a writer key\n")
		os.Exit(1)
	}

	fmt.Printf("Deriving reader key from writer key for domain: %s\n", writerKey.DomainName)

	// Derive reader key
	readerKey, err := writerKey.DeriveReader()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving reader key: %v\n", err)
		os.Exit(1)
	}

	// Serialize and save reader key
	readerKeyBytes, err := SerializeCalypsoPrivateKey(readerKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing reader key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, readerKeyBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing reader key to %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("Reader key saved to: %s\n", *output)
}

func handleCalypsoKeyDerive(args []string) {
	fs := flag.NewFlagSet("calypso keyder", flag.ExitOnError)
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

	// Load public params (not strictly needed but validates file)
	ppBytes, err := os.ReadFile(*paramsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading params file %s: %v\n", *paramsFile, err)
		os.Exit(1)
	}

	_, err = DeserializePublicParams(ppBytes)
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

	parentKey, err := DeserializeCalypsoPrivateKey(parentKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deserializing parent key: %v\n", err)
		os.Exit(1)
	}

	// Validate parent can derive
	if !parentKey.CanDerive() {
		fmt.Fprintf(os.Stderr, "Error: parent key must have wildcard for derivation\n")
		os.Exit(1)
	}

	// Child inherits writer/reader type from parent
	isWriter := parentKey.IsWriter()
	keyType := "reader"
	if isWriter {
		keyType = "writer"
	}

	fmt.Printf("Deriving %s key for domain: %s (from parent: %s)\n", keyType, *domain, parentKey.DomainName)

	// Derive child key
	childKey, err := parentKey.DeriveKey(*domain, isWriter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving child key: %v\n", err)
		os.Exit(1)
	}

	// Serialize and save child key
	childKeyBytes, err := SerializeCalypsoPrivateKey(childKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing child key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, childKeyBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing child key to %s: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("Child %s key saved to: %s\n", keyType, *output)
}

func showCalypsoHelp() {
	fmt.Printf(`etcd-client calypso - Calypso key management commands

USAGE:
    etcd-client calypso <subcommand> [OPTIONS]

SUBCOMMANDS:
    setup        Generate Calypso authority and public parameters
    keygen       Generate identity key from authority
    reader       Derive reader key from writer key
    keyder       Derive child key from parent key (requires wildcard)
    help         Show this help

EXAMPLES:
    # Generate Calypso setup with default max-depth=5
    etcd-client calypso setup

    # Generate writer key for alice.example.com
    etcd-client calypso keygen --params params.bin --authority authority.bin \
        --domain "alice.example.com" --writer --output alice-writer.key

    # Generate reader key for alice.example.com
    etcd-client calypso keygen --params params.bin --authority authority.bin \
        --domain "alice.example.com" --output alice-reader.key

    # Derive reader key from writer key
    etcd-client calypso reader --writer alice-writer.key --output alice-reader.key

    # Generate wildcard writer key for *.example.com
    etcd-client calypso keygen --params params.bin --authority authority.bin \
        --domain "*.example.com" --writer --output wildcard-writer.key

    # Derive specific key from wildcard parent
    etcd-client calypso keyder --params params.bin --parent-key wildcard-writer.key \
        --domain "alice.example.com" --output alice-writer.key

Use 'etcd-client calypso <subcommand> -h' for more information about a subcommand.
`)
}