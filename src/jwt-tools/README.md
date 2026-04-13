# JWT Tools for CoreDNS

A minimal Go tool for generating JWT tokens for CoreDNS service client authentication with support for multiple cryptographic algorithms.

- Generate cryptographic key pairs (RSA, ECDSA P-256, EdDSA Ed25519)
- Create JWT tokens with CoreDNS-specific claims
- Verify JWT tokens with automatic algorithm detection
- CLI interface with algorithm selection

## Supported Algorithms

- **EdDSA**: Ed25519 signature algorithm (default, fastest, most secure)
- **ES256**: ECDSA with P-256 curve and SHA-256 (smaller keys, faster)
- **RS256**: RSA with SHA-256 (legacy compatibility, 2048-bit keys)

## Usage

### Basic Usage (EdDSA - Default)
```bash
# Generate EdDSA key pair (default)
./jwt-tools generate-keys

# Generate token for a client
./jwt-tools generate-token --client-id "dns-client-1" --permissions "query" --allowed-zones "example.com" --expiry "1h"

# Verify token
./jwt-tools verify-token [token-string]
```

### ES256 (ECDSA) Usage
```bash
# Generate ES256 key pair
./jwt-tools generate-keys --algorithm ES256

# Generate ES256 token
./jwt-tools generate-token --algorithm ES256 --client-id "dns-client-1" --permissions "query" --expiry "1h"
```

### RS256 (RSA) Usage
```bash
# Generate RSA key pair
./jwt-tools generate-keys --algorithm RS256

# Generate RSA token
./jwt-tools generate-token --algorithm RS256 --client-id "dns-client-1" --permissions "query" --expiry "1h"
```

### Make Targets
```bash
# Default EdDSA usage
make keys          # Generate EdDSA keys
make token         # Generate EdDSA token

# Unified algorithm support (ALG=RS256|ES256|EdDSA)
make keys-algo ALG=ES256     # Generate ES256 keys
make token ALG=ES256         # Generate ES256 token
make token ALG=RS256         # Generate RS256 token

# Complete demo workflow
make demo ALG=ES256          # Generate ES256 keys + token
make demo ALG=EdDSA          # Generate EdDSA keys + token
make demo ALG=RS256          # Generate RS256 keys + token
```

## JWT Claims

- `client_id`: Client identifier
- `permissions`: Array of permissions (query, update, etc.)
- `allowed_zones`: Optional DNS zones restriction
- Standard JWT claims (iss, sub, exp, nbf, iat)

## Build

```bash
go build -o jwt-tools
```

## Algorithm Comparison

| Algorithm | Key Size | Performance | Security | Use Case |
|-----------|----------|-------------|----------|----------|
| **EdDSA** | 256-bit | Fastest | Strongest | Modern applications (default) |
| **ES256** | 256-bit | Fast | Strong | Balanced performance/size |
| **RS256** | 2048-bit | Slowest | Strong | Legacy compatibility |

## Architecture

- **Private key**: Used by this tool to sign JWT tokens
- **Public key**: Used by CoreDNS to verify JWT tokens
- **Algorithm detection**: Verification automatically detects signing algorithm from token header
- **Key formats**: All keys stored in standard PEM format for compatibility