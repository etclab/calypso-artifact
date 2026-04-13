package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	privateKeyFile string
	publicKeyFile  string
	clientID       string
	permissions    []string
	allowedZones   []string
	expiry         time.Duration
	algorithm      string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "jwt-tools",
		Short: "JWT token generator for CoreDNS authentication",
		Long:  "A minimal Go tool to generate JWT tokens for CoreDNS service client authentication",
	}

	var generateKeysCmd = &cobra.Command{
		Use:   "generate-keys",
		Short: "Generate cryptographic key pair",
		Long:  "Generate private and public key pair for JWT signing and verification (supports RS256, ES256, EdDSA)",
		Run: func(cmd *cobra.Command, args []string) {
			keyPair, err := generateKeyPair(algorithm)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
				os.Exit(1)
			}

			if err := savePrivateKey(keyPair, privateKeyFile); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
				os.Exit(1)
			}

			if err := savePublicKey(keyPair, publicKeyFile); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving public key: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("%s key pair generated successfully:\n", algorithm)
			fmt.Printf("Private key: %s\n", privateKeyFile)
			fmt.Printf("Public key: %s\n", publicKeyFile)
		},
	}

	var generateTokenCmd = &cobra.Command{
		Use:   "generate-token",
		Short: "Generate JWT token",
		Long:  "Generate a JWT token for a CoreDNS client with specified permissions",
		Run: func(cmd *cobra.Command, args []string) {
			if clientID == "" {
				fmt.Fprintf(os.Stderr, "Error: client-id is required\n")
				os.Exit(1)
			}

			privateKey, err := loadPrivateKey(privateKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
				os.Exit(1)
			}

			token, err := generateJWT(privateKey, algorithm, clientID, permissions, allowedZones, expiry)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("JWT Token for client '%s':\n%s\n", clientID, token)
		},
	}

	var verifyTokenCmd = &cobra.Command{
		Use:   "verify-token [token]",
		Short: "Verify JWT token",
		Long:  "Verify a JWT token using the public key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tokenString := args[0]

			publicKey, err := loadPublicKeyFromFile(publicKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
				os.Exit(1)
			}

			claims, err := verifyJWT(publicKey, tokenString)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Token verification failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Token is valid!\n")
			fmt.Printf("Client ID: %s\n", claims.ClientID)
			fmt.Printf("Permissions: %s\n", strings.Join(claims.Permissions, ", "))
			if len(claims.AllowedZones) > 0 {
				fmt.Printf("Allowed Zones: %s\n", strings.Join(claims.AllowedZones, ", "))
			}
			fmt.Printf("Expires At: %s\n", claims.ExpiresAt.Time.Format(time.RFC3339))
		},
	}

	generateKeysCmd.Flags().StringVar(&privateKeyFile, "private-key", "private.pem", "Private key file path")
	generateKeysCmd.Flags().StringVar(&publicKeyFile, "public-key", "public.pem", "Public key file path")
	generateKeysCmd.Flags().StringVar(&algorithm, "algorithm", "EdDSA", "Signing algorithm (RS256, ES256, EdDSA)")

	generateTokenCmd.Flags().StringVar(&privateKeyFile, "private-key", "private.pem", "Private key file path")
	generateTokenCmd.Flags().StringVar(&clientID, "client-id", "", "Client identifier (required)")
	generateTokenCmd.Flags().StringSliceVar(&permissions, "permissions", []string{"query"}, "Client permissions")
	generateTokenCmd.Flags().StringSliceVar(&allowedZones, "allowed-zones", []string{}, "Allowed DNS zones")
	generateTokenCmd.Flags().DurationVar(&expiry, "expiry", 24*time.Hour, "Token expiry duration")
	generateTokenCmd.Flags().StringVar(&algorithm, "algorithm", "EdDSA", "Signing algorithm (RS256, ES256, EdDSA)")
	generateTokenCmd.MarkFlagRequired("client-id")

	verifyTokenCmd.Flags().StringVar(&publicKeyFile, "public-key", "public.pem", "Public key file path")

	rootCmd.AddCommand(generateKeysCmd)
	rootCmd.AddCommand(generateTokenCmd)
	rootCmd.AddCommand(verifyTokenCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}