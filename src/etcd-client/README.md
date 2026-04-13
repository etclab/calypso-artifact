# etcd-client

Tool for populating etcd with DNS records using different encryption schemes to evaluate multiple Zero Trust DNS security approaches.

## Research Context

This tool populates etcd with different encryption schemes to evaluate a **security progression** for Zero Trust DNS service discovery: application-layer → hardware-based → cryptographic enforcement.

### Security Approaches

- **Approach 0**: Plain DoH - no encryption, plaintext etcd entries (performance baseline)
- **Approach 1**: JWT-authorized DoH - application-layer access control via JWT tokens
- **Approach 2**: Enclave DoH - AES-256-GCM encrypted etcd entries, CoreDNS runs in secure enclave with decryption key (hardware-based confidentiality)
- **Approach 3**: WKD-IBE (akn07) + DoH - IBE encrypted entries with pattern-based hierarchical access control (cryptographic enforcement)
- **Approach 4**: Calypso + DoH - enhanced IBE with mandatory signatures, privacy-preserving storage, and reader/writer separation

### Implementation Status

- ✅ **Approach 0**: Plaintext A records (standard CoreDNS)
- ✅ **Approach 1**: JWT validation (CoreDNS jwt_edns plugin, not implemented in this tool)
- ✅ **Approach 2**: AES-256-GCM encrypted entries (type code `01`)
  - Symmetric encryption with single shared key
  - CoreDNS in enclave decrypts for clients
  - Protects etcd storage at rest
- ✅ **Approach 3**: WKD-IBE encrypted TXT records (type code `02`)
  - Pattern-based hierarchical access control
  - Wildcard support via `*` syntax
  - End-to-end encryption (client-side decryption)
- ✅ **Approach 4**: Calypso encrypted TXT records (type code `03`)
  - Mandatory signatures and authenticated encryption
  - Privacy-preserving storage (SearchTag hashing)
  - Writer/reader key separation
  - End-to-end encryption (client-side decryption)

**Zero Trust Architecture:** Approaches 3 and 4 use end-to-end encryption where CoreDNS serves encrypted TXT records without decryption keys. Clients receive `TYPE:BASE64` formatted responses and decrypt locally.

## Structure

```
├── main.go          # CLI entry point
├── config.go        # Configuration management
├── dns.go           # DNS record types and validation
├── crypto.go        # Encryption/decryption layer
├── commands.go      # etcd client v3 operations: register, lookup, list, delete, clear
└── *_test.go        # Unit tests for each module
```

## Build

```bash
go build -o etcd-client
```

## Usage

```bash
# Help
./etcd-client -help

# Register DNS record
./etcd-client -register api.example.com=192.168.1.10

# Lookup domain
./etcd-client -lookup api.example.com

# List all records
./etcd-client -list

# Delete specific record
./etcd-client -delete api.example.com

# Clear all records
./etcd-client -clear
```

## Environment Variables

### General
- `ETCD_ENDPOINTS`: etcd server endpoints
    - Default: `localhost:2379`
    - Multiple endpoints must be separated by commas, e.g.`1.2.3.4:2379,4.5.6.7:2379`

### Encryption Settings

- `CRYPTO_TYPE`: Encryption scheme (`aes` | `wkdibe` | `calypso` | empty for plaintext)

### AES Encryption
- `AES_KEY_FILE`: AES key file (32-byte key for AES-256-GCM)

### WKD-IBE Encryption
- `WKDIBE_PARAMS_FILE`: Public parameters file (default: `params.bin`)
- `WKDIBE_MASTER_KEY`: Master key file for key generation (default: `master.key`)
- `WKDIBE_KEY_FILE`: Private key file for WKD-IBE encrypt/decrypt/sign/verify operations
- `WKDIBE_MAX_DEPTH`: Maximum hierarchy depth (default: `5`)

### Calypso Encryption

- `CALYPSO_PARAMS_FILE`: Public parameters file (default: `params.bin`)
- `CALYPSO_AUTHORITY`: Authority file for key generation (default: `authority.bin`)
- `CALYPSO_WRITER_KEY`: Writer key file for encryption (can also decrypt)
- `CALYPSO_READER_KEY`: Reader key file for decryption only
- `CALYPSO_MAX_DEPTH`: Maximum hierarchy depth (default: `5`)

## Development

### Testing with AES Encryption

AES-256-GCM encryption represents Approach 2 (Enclave DoH) - symmetric encryption for protecting etcd storage at rest, designed for deployment with CoreDNS inside secure enclaves.

#### Prerequisites

**1. Start etcd server:**
```bash
etcd
```

**2. Generate AES key:**
```bash
# Generate 32-byte (256-bit) AES key
openssl rand -out aes.key 32
```

#### Test Commands

**Register with AES encryption (stores as TXT record):**
```bash
CRYPTO_TYPE=aes AES_KEY_FILE=./aes.key ./etcd-client -register secure.test.com=172.16.0.10
# Stored in etcd as: {"text":"01:BASE64...","ttl":300}
```

**Lookup with AES decryption:**
```bash
CRYPTO_TYPE=aes AES_KEY_FILE=./aes.key ./etcd-client -lookup secure.test.com
# Fetches TXT record, decodes base64, decrypts with AES-256-GCM, returns IP
```

**Register without encryption (stores as A record):**
```bash
./etcd-client -register plain.test.com=10.0.0.1
# Stored in etcd as: {"host":"10.0.0.1","ttl":300}
```

**List all records:**
```bash
./etcd-client -list
```

#### Full Workflow Example

```bash
# Build
go build

# Generate AES key
openssl rand -out aes.key 32

# Clear existing records
./etcd-client -clear

# Register with AES encryption (TXT record with TYPE:BASE64)
CRYPTO_TYPE=aes AES_KEY_FILE=./aes.key ./etcd-client -register secure.test.com=172.16.0.10

# Register without encryption (A record)
./etcd-client -register plain.test.com=172.16.0.20

# Lookup AES-encrypted record (requires key)
CRYPTO_TYPE=aes AES_KEY_FILE=./aes.key ./etcd-client -lookup secure.test.com

# Lookup plain record (no key needed)
./etcd-client -lookup plain.test.com

# List all records
./etcd-client -list

# Delete a record
./etcd-client -delete secure.test.com

# Clear all
./etcd-client -clear
```

### Testing with WKD-IBE Encryption

WKD-IBE (Wildcard Key Derivation Identity-Based Encryption) enables hierarchical access control where parent keys can derive child keys but cannot decrypt child-specific ciphertexts. The implementation uses the akn07 scheme with wildcard pattern support.


#### Prerequisites

**1. Start etcd server:**
```bash
etcd
```

**2. Generate WKD-IBE setup (public params + master key):**
```bash
./etcd-client wkdibe setup --max-depth 5 --output params.bin --master-key master.key
```

**3. Generate identity keys:**
```bash
# Generate key for example.com domain
./etcd-client wkdibe keygen --params params.bin --master-key master.key \
    --domain "example.com" --output example.key

# Generate key for alice.example.com
./etcd-client wkdibe keygen --params params.bin --master-key master.key \
    --domain "alice.example.com" --output alice.key
```

#### WKD-IBE Commands

**Key management:**
```bash
# Setup: Generate public params and master key
./etcd-client wkdibe setup --max-depth 5 --output params.bin --master-key master.key

# KeyGen: Generate identity key from master key
./etcd-client wkdibe keygen --params params.bin --master-key master.key \
    --domain "alice.example.com" --output alice.key

# KeyDerive: Derive child key from parent key (delegation)
./etcd-client wkdibe keyder --params params.bin --parent-key example.key \
    --domain "subdomain.alice.example.com" --output subdomain.key
```

**Register with WKD-IBE encryption (requires key for signing, stores as TXT record):**
```bash
CRYPTO_TYPE=wkdibe \
WKDIBE_PARAMS_FILE=params.bin \
WKDIBE_KEY_FILE=alice.key \
./etcd-client -register alice.example.com=10.0.0.1
# Stored in etcd as: {"text":"02:BASE64...","ttl":300}
```

**Lookup with WKD-IBE decryption:**
```bash
CRYPTO_TYPE=wkdibe \
WKDIBE_PARAMS_FILE=params.bin \
WKDIBE_KEY_FILE=alice.key \
./etcd-client -lookup alice.example.com
# Fetches TXT record, parses TYPE:BASE64, decrypts, returns IP
```

**List all records (shows metadata only, does not decrypt):**
```bash
./etcd-client -list
```

#### Full WKD-IBE Workflow Example

```bash
# 1. Setup WKD-IBE system
./etcd-client wkdibe setup --max-depth 5 --output params.bin --master-key master.key

# 2. Generate parent key for alice.example.com
./etcd-client wkdibe keygen --params params.bin --master-key master.key \
    --domain "alice.example.com" --output alice.key

# 3. Derive child key for subdomain.alice.example.com
./etcd-client wkdibe keyder --params params.bin --parent-key alice.key \
    --domain "subdomain.alice.example.com" --output alice-subdomain.key

# 4. Register DNS records with WKD-IBE encryption (requires keys for signing)
CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice.key \
./etcd-client -register alice.example.com=10.0.0.1

CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice-subdomain.key \
./etcd-client -register subdomain.alice.example.com=10.0.0.3

# 5. Lookup with parent key (alice.key)
CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice.key \
./etcd-client -lookup alice.example.com

# 6. Lookup with child key (alice-subdomain.key)
CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice-subdomain.key \
./etcd-client -lookup subdomain.alice.example.com

# 7. List records (shows metadata only, does not decrypt)
./etcd-client -list
# Output: Shows encryption type and domain for all records

# 8. Verify access control: parent cannot decrypt child records
CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice.key \
./etcd-client -lookup subdomain.alice.example.com || echo "Failed as expected - parent cannot decrypt child"

# 9. Verify child key decrypts its own records
CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice-subdomain.key \
./etcd-client -lookup subdomain.alice.example.com

# 10. Cleanup
./etcd-client -clear
```

#### WKD-IBE Wildcard Patterns

WKD-IBE supports wildcard patterns using `*` syntax, enabling parent keys to match multiple subdomains. Wildcards must be contiguous at the end of the pattern.

**Wildcard workflow:**
```bash
# 1. Generate wildcard key for *.example.com
./etcd-client wkdibe keygen --params params.bin --master-key master.key \
    --domain "*.example.com" --output wildcard-example.key

# 2. Derive specific keys from wildcard parent
./etcd-client wkdibe keyder --params params.bin --parent-key wildcard-example.key \
    --domain "alice.example.com" --output alice.key

./etcd-client wkdibe keyder --params params.bin --parent-key wildcard-example.key \
    --domain "bob.example.com" --output bob.key

# 3. Register DNS records (encrypted to specific patterns, requires keys for signing)
CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice.key \
./etcd-client -register alice.example.com=10.0.0.1

CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=bob.key \
./etcd-client -register bob.example.com=10.0.0.2

# 4. Lookup with derived keys
CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=alice.key \
./etcd-client -lookup alice.example.com

CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=params.bin WKDIBE_KEY_FILE=bob.key \
./etcd-client -lookup bob.example.com
```

**Wildcard validation:**
```bash
# Valid wildcard domain patterns
*.example.com          # Wildcard subdomain
*.*.com               # Multi-level wildcard
*.com                 # Top-level wildcard

# Invalid patterns (wildcards must be at the beginning)
alice.*.com           # Error: wildcard in middle not supported
example.com.*         # Error: wildcard at end not supported
```

#### WKD-IBE Key Hierarchy

WKD-IBE supports **downward delegation**: parent keys can derive child keys, but each key only decrypts ciphertexts for its exact pattern.

```
master.key (com,example)
    ├─> alice.key (com,example,alice)      # Can decrypt alice.example.com
    └─> bob.key (com,example,bob)          # Can decrypt bob.example.com
            └─> subdomain.key (com,example,bob,subdomain)  # Can decrypt subdomain.bob.example.com
```

**Example:**
- `example.key` can derive `alice.key`
- `alice.key` can decrypt records for `alice.example.com`
- `example.key` **cannot** decrypt records for `alice.example.com` (no upward decryption)

### Testing with Calypso Encryption

Calypso provides mandatory signatures and writer/reader key separation for enhanced security. Writer keys can encrypt and sign, while reader keys can only decrypt.

#### Prerequisites

**1. Start etcd server:**
```bash
etcd
```

**2. Generate Calypso setup (public params + authority):**
```bash
./etcd-client calypso setup --max-depth 5 --output params.bin --authority auth.bin
```

**3. Generate writer key:**
```bash
# Writer key (can encrypt, sign, and decrypt)
./etcd-client calypso keygen --params params.bin --authority auth.bin \
    --domain "alice.example.com" --writer --output alice-writer.key

# Derive reader key from writer
./etcd-client calypso reader --writer alice-writer.key --output alice-reader.key
```

#### Calypso Commands

**Key management:**
```bash
# Setup: Generate authority and public params
./etcd-client calypso setup --max-depth 5 --output params.bin --authority auth.bin

# KeyGen: Issue writer key from authority
./etcd-client calypso keygen --params params.bin --authority auth.bin \
    --domain "alice.example.com" --writer --output alice-writer.key

# Reader: Derive reader key from writer key
./etcd-client calypso reader --writer alice-writer.key --output alice-reader.key

# KeyDerive: Derive child key from wildcard parent
./etcd-client calypso keyder --params params.bin --parent-key wildcard.key \
    --domain "alice.example.com" --output alice.key
```

**Register with Calypso encryption (requires writer key, stores as TXT record):**
```bash
CRYPTO_TYPE=calypso \
CALYPSO_PARAMS_FILE=params.bin \
CALYPSO_WRITER_KEY=alice-writer.key \
./etcd-client -register alice.example.com=10.0.0.1
# Stored at /skydns-calypso/<SearchTag> as: {"text":"03:BASE64...","ttl":300}
```

**Lookup with Calypso decryption (reader or writer key):**
```bash
CRYPTO_TYPE=calypso \
CALYPSO_PARAMS_FILE=params.bin \
CALYPSO_READER_KEY=alice-reader.key \
./etcd-client -lookup alice.example.com
# Computes SearchTag, fetches TXT record, parses TYPE:BASE64, verifies signature, decrypts, returns IP
```

#### Calypso Wildcard Workflow

```bash
# 1. Generate wildcard writer key for *.example.com
./etcd-client calypso keygen --params params.bin --authority auth.bin \
    --domain "*.example.com" --writer --output wildcard.key

# 2. Derive concrete keys from wildcard parent
./etcd-client calypso keyder --params params.bin --parent-key wildcard.key \
    --domain "alice.example.com" --output alice.key

# 3. Register with concrete key (encryption requires concrete domain)
CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=params.bin CALYPSO_WRITER_KEY=alice.key \
./etcd-client -register alice.example.com=10.0.0.1

# 4. Lookup with derived key
CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=params.bin CALYPSO_READER_KEY=alice.key \
./etcd-client -lookup alice.example.com
```

**Access control:** Parent wildcard key can derive child keys but **cannot** decrypt child ciphertexts (downward delegation only).

## Storage Format

etcd-client stores DNS records in formats compatible with CoreDNS's standard etcd plugin.

### Plaintext Records (A Records)

**Approaches 0, 1:** Standard A records for plaintext or JWT-protected entries:
```json
etcd key:   /skydns/com/example/www
etcd value: {"host":"10.0.0.1","ttl":300}
```

CoreDNS serves as A record: `www.example.com. 300 IN A 10.0.0.1`

### Encrypted Records (TXT Records)

**Approaches 2, 3, 4:** TXT records with `TYPE:BASE64` format for encrypted entries:
```json
etcd key:   /skydns/com/example/alice
etcd value: {"text":"02:V0tESUJFZW5jcnlwdGVkZGF0YQ==","ttl":300}
                    ↑ TYPE:BASE64 format
```

CoreDNS serves as TXT record: `alice.example.com. 300 IN TXT "02:V0tESUJFZW5jcnlwdGVkZGF0YQ=="`

**TYPE codes:**
- `01` = AES-256-GCM (Approach 2 - Enclave DoH)
- `02` = WKD-IBE/akn07 (Approach 3)
- `03` = Calypso (Approach 4)

**Format structure:** `TYPE:BASE64_PAYLOAD`
- `TYPE`: Two-digit hex code
- `BASE64_PAYLOAD`: Standard base64 encoding of encrypted bytes
- Separator: Single colon (`:`)

### Client-Side Decryption

Clients (e.g., q tool) receive TXT responses, parse the `TYPE:BASE64` format, base64 decode, and decrypt using appropriate keys. This enables **end-to-end encryption** with zero trust on DNS servers.

**Workflow:**
1. Client queries DNS for TXT record
2. CoreDNS returns TXT record with `TYPE:BASE64` format
3. Client parses type code and base64 payload
4. Client selects appropriate decrypter based on type code
5. Client decrypts payload to obtain IP address

**Note:** All encryption schemes coexist in the same etcd instance. The `etcd-client` tool automatically detects and handles both plaintext A records and encrypted TXT records.


## Dependencies

- **etcd client v3 API**: Native etcd client for key-value operations
- **WKD-IBE library**: AKN07 WKD-IBE implementation (via vendored dependency)
- **Calypso package**: Calypso encryption with RSA accumulator wildcards (`src/calypso/`)
- **Go 1.25+**: Required Go version

**Key Integration Points:**
- `commands.go` uses `clientv3.New()` for etcd connections
- `clientv3.Put()`, `clientv3.Get()`, and `clientv3.Delete()` for DNS record operations
- `wkdibe_commands.go` implements WKD-IBE key management subcommands
- `calypso_commands.go` implements Calypso key management subcommands
- TXT record storage with `TYPE:BASE64` format for encrypted entries
- Native API calls replace shell execution of `etcdctl` commands

## Encryption Schemes

### AES-256-GCM
- **Use case:** Symmetric encryption for Approach 2 (Enclave DoH)
- **Key management:** Single shared 32-byte key
- **Deployment:** CoreDNS runs in secure enclave with decryption key
- **Properties:** Authenticated encryption, minimal overhead baseline

### WKD-IBE (Wildcard Key Derivation Identity-Based Encryption)
- **Use case:** Hierarchical access control with pattern-based delegation
- **Key management:** Master key → identity keys → child keys
- **Scheme:** AKN07 (Abdalla-Kiltz-Neven 2007) on BLS12-381
- **Wildcard support:** Fully implemented using `*` syntax (e.g., `*.example.com`)
- **Signatures:** Mandatory - every ciphertext signed during encryption, verified on decryption
- **Access control:** Parent keys derive child keys, cannot decrypt child ciphertexts

**Pattern Mapping:**
```
alice.example.com → ["com", "example", "alice", "", ""]
*.example.com     → ["com", "example", "", "", ""]
                                                 ↑
                                    signature slot (last position)
```

### Calypso
- **Use case:** Hierarchical access control with mandatory signatures and writer/reader separation
- **Key management:** Centralized authority issues writer/reader keys, supports wildcard delegation
- **Wildcard mechanism:** RSA accumulator-based (salts updated during key derivation)
- **Signatures:** Mandatory - every message signed by writer key, verified on decryption
- **Key types:** Writer keys (sign + encrypt), Reader keys (decrypt only)
- **Encryption:** Requires concrete domain (no encryption to wildcards directly)
- **Privacy-preserving storage:** Records stored at `/skydns-calypso/<SearchTag>` using SHA256 hash instead of plaintext domain paths
- **Access control:** Parent keys derive child keys, cannot decrypt child ciphertexts

**SearchTag-Based Storage:**
Calypso records use hashed etcd keys to prevent domain enumeration:
- **Other approaches:** `/skydns/com/example/alice` (domain visible to etcd observers)
- **Calypso:** `/skydns-calypso/a3f5b2...` (SHA256 hash, domain hidden)
- **Privacy property:** Observers cannot enumerate which domains exist
- **Trade-off:** Lookup-only model (must know domain name to query, no ListDNS enumeration)

**Key differences from WKD-IBE:**
- Both have mandatory signatures (WKD-IBE signs plaintext, Calypso signs entire message)
- Writer/reader key separation (vs single key type)
- RSA accumulator wildcards (vs nil pattern values)
- Privacy-preserving etcd storage (hashed keys vs plaintext paths)
- Not enumerable via ListDNS (lookup-only by design)