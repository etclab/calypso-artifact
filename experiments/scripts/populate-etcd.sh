#!/bin/bash
set -e

# Load common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Default values
APPROACH="plain"
SERVICE_COUNT=1000
NAMESPACE_COUNT=10
ETCD_ENDPOINT="http://localhost:2379"
CLEAR_FIRST=false
VERBOSE=false

# Usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Populate etcd with DNS entries for benchmarking Calypso approaches"
    echo ""
    echo "Options:"
    echo "  -a, --approach <name>      Approach to use (plain|jwt|enclave|wkdibe|calypso) [default: plain]"
    echo "  -s, --services <count>     Number of services to create [default: 1000]"
    echo "  -n, --namespaces <count>   Number of namespaces to distribute services across [default: 10]"
    echo "  -e, --endpoint <url>       etcd endpoint [default: http://localhost:2379]"
    echo "  -c, --clear                Clear existing entries first"
    echo "  -v, --verbose              Verbose output"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Populate 100 services for plain approach"
    echo "  $0 -a plain -s 100"
    echo ""
    echo "  # Populate 1000 services across 50 namespaces for calypso"
    echo "  $0 -a calypso -s 1000 -n 50 -c"
    echo ""
    echo "  # Clear and populate 10K services for benchmarking"
    echo "  $0 -a wkdibe -s 10000 -n 100 -c"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--approach)
            APPROACH="$2"
            shift 2
            ;;
        -s|--services)
            SERVICE_COUNT="$2"
            shift 2
            ;;
        -n|--namespaces)
            NAMESPACE_COUNT="$2"
            shift 2
            ;;
        -e|--endpoint)
            ETCD_ENDPOINT="$2"
            shift 2
            ;;
        -c|--clear)
            CLEAR_FIRST=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Strip -udp suffix if present (used for UDP benchmarking)
BASE_APPROACH="$APPROACH"
if [[ "$APPROACH" == *-udp ]]; then
    BASE_APPROACH="${APPROACH%-udp}"
fi

# Validate base approach
case "$BASE_APPROACH" in
    plain|jwt|enclave|enclave-jwt|wkdibe|calypso)
        ;;
    *)
        echo "ERROR: Invalid approach: $BASE_APPROACH"
        echo "Valid approaches: plain, jwt, enclave, enclave-jwt, wkdibe, calypso (with optional -udp suffix)"
        exit 1
        ;;
esac

# Check dependencies
ETCDCTL="$WORKSPACE/build/etcdctl"
ETCD_CLIENT="$WORKSPACE/build/etcd-client"

if [ ! -f "$ETCDCTL" ]; then
    echo "ERROR: etcdctl not found at $ETCDCTL"
    echo "Run ./scripts/build-components.sh first"
    exit 1
fi

# For encrypted approaches, we need etcd-client
if [ "$BASE_APPROACH" != "plain" ] && [ "$BASE_APPROACH" != "jwt" ]; then
    if [ ! -f "$ETCD_CLIENT" ]; then
        echo "ERROR: etcd-client not found at $ETCD_CLIENT"
        echo "Run ./scripts/build-components.sh first"
        exit 1
    fi
fi

# For enclave approach, verify AES key exists
if [ "$BASE_APPROACH" = "enclave" ]; then
    KEY_FILE="$WORKSPACE/approaches/enclave/aes.key"
    if [ ! -f "$KEY_FILE" ]; then
        echo "ERROR: AES key not found at $KEY_FILE"
        echo "The enclave approach requires an AES key for encryption."
        echo "Run './scripts/start.sh enclave' first to generate the key and start services."
        exit 1
    fi
fi

# For enclave-jwt approach, verify AES key exists
if [ "$BASE_APPROACH" = "enclave-jwt" ]; then
    KEY_FILE="$WORKSPACE/approaches/enclave-jwt/aes.key"
    if [ ! -f "$KEY_FILE" ]; then
        echo "ERROR: AES key not found at $KEY_FILE"
        echo "The enclave-jwt approach requires an AES key for encryption."
        echo "Run './scripts/start.sh enclave-jwt' first to generate the key and start services."
        exit 1
    fi
fi

echo "=== Populating etcd for $APPROACH approach ==="
echo ""
echo "Configuration:"
echo "  • Services:    $SERVICE_COUNT"
echo "  • Namespaces:  $NAMESPACE_COUNT"
echo "  • Endpoint:    $ETCD_ENDPOINT"
echo "  • Clear first: $CLEAR_FIRST"
echo ""

# Test etcd connection
if ! $ETCDCTL --endpoints="$ETCD_ENDPOINT" endpoint health &>/dev/null; then
    echo "ERROR: Cannot connect to etcd at $ETCD_ENDPOINT"
    echo "Make sure etcd is running (./scripts/start.sh $APPROACH)"
    exit 1
fi

# Clear existing entries if requested
if [ "$CLEAR_FIRST" = true ]; then
    echo "Clearing existing entries..."
    $ETCDCTL --endpoints="$ETCD_ENDPOINT" del --prefix /skydns/ 2>/dev/null || true

    # For Calypso, also clear the searchtag namespace
    if [ "$BASE_APPROACH" = "calypso" ]; then
        $ETCDCTL --endpoints="$ETCD_ENDPOINT" del --prefix /skydns-calypso/ 2>/dev/null || true
    fi
    echo "  ✓ Cleared"
    echo ""
fi

# Create keys directory for WKD-IBE approach
if [ "$BASE_APPROACH" = "wkdibe" ]; then
    KEYS_DIR="$WORKSPACE/approaches/wkdibe/keys"
    mkdir -p "$KEYS_DIR"
    echo "Keys will be stored in: $KEYS_DIR"
    echo ""
fi

# Create keys directory for Calypso approach
if [ "$BASE_APPROACH" = "calypso" ]; then
    KEYS_DIR="$WORKSPACE/approaches/calypso/keys"
    mkdir -p "$KEYS_DIR"
    echo "Keys will be stored in: $KEYS_DIR"
    echo ""
fi

# Function to create DNS entry in etcd
create_dns_entry() {
    local service="$1"
    local namespace="$2"
    local ip="$3"
    local approach="$4"

    # Full domain: service.namespace.svc.cluster.local
    local domain="${service}.${namespace}.svc.cluster.local"

    # Reverse domain for etcd path: /skydns/local/cluster/svc/namespace/service
    local etcd_path="/skydns/local/cluster/svc/${namespace}/${service}"

    # DNS record data
    local record_data='{"host":"'$ip'"}'

    case "$approach" in
        plain|jwt)
            # No encryption, store directly
            if [ "$VERBOSE" = true ]; then
                echo "  Storing: $domain → $ip"
            fi
            $ETCDCTL --endpoints="$ETCD_ENDPOINT" put "$etcd_path" "$record_data" &>/dev/null
            ;;

        enclave)
            # AES-256-GCM encryption (type code 01)
            # etcd-client will handle the encryption with the enclave key
            if [ "$VERBOSE" = true ]; then
                echo "  Storing (AES): $domain → $ip"
            fi
            # Use environment variables for AES key configuration
            CRYPTO_TYPE=aes AES_KEY_FILE="$WORKSPACE/approaches/enclave/aes.key" \
            ETCD_ENDPOINTS="$ETCD_ENDPOINT" \
                $ETCD_CLIENT -register "${domain}=${ip}" &>/dev/null
            ;;

        enclave-jwt)
            # AES-256-GCM encryption + JWT authorization
            # Same encryption as enclave, but with JWT authorization layer
            if [ "$VERBOSE" = true ]; then
                echo "  Storing (AES+JWT): $domain → $ip"
            fi
            # Use environment variables for AES key configuration
            CRYPTO_TYPE=aes AES_KEY_FILE="$WORKSPACE/approaches/enclave-jwt/aes.key" \
            ETCD_ENDPOINTS="$ETCD_ENDPOINT" \
                $ETCD_CLIENT -register "${domain}=${ip}" &>/dev/null
            ;;

        wkdibe)
            # WKD-IBE encryption (type code 02)
            # Generate domain-specific identity key
            KEY_FILE="$WORKSPACE/approaches/wkdibe/keys/${domain}.key"

            if [ ! -f "$KEY_FILE" ]; then
                "$ETCD_CLIENT" wkdibe keygen \
                    --params "$WORKSPACE/approaches/wkdibe/params.bin" \
                    --master-key "$WORKSPACE/approaches/wkdibe/master.key" \
                    --domain "$domain" \
                    --output "$KEY_FILE" &>/dev/null
            fi

            if [ "$VERBOSE" = true ]; then
                echo "  Storing (WKD-IBE): $domain → $ip"
            fi
            CRYPTO_TYPE=wkdibe \
                WKDIBE_PARAMS_FILE="$WORKSPACE/approaches/wkdibe/params.bin" \
                WKDIBE_KEY_FILE="$KEY_FILE" \
                WKDIBE_MAX_DEPTH=6 \
                ETCD_ENDPOINTS="$ETCD_ENDPOINT" \
                $ETCD_CLIENT -register "${domain}=${ip}" &>/dev/null
            ;;

        calypso)
            # Calypso encryption (type code 03)
            # Use per-namespace wildcard writer key
            NS_KEY_FILE="$WORKSPACE/approaches/calypso/keys/${namespace}.key"

            if [ ! -f "$NS_KEY_FILE" ]; then
                # Generate namespace wildcard key: *.namespace-X.svc.cluster.local
                "$ETCD_CLIENT" calypso keygen \
                    --params "$WORKSPACE/approaches/calypso/params.bin" \
                    --authority "$WORKSPACE/approaches/calypso/authority.bin" \
                    --domain "*.${namespace}.svc.cluster.local" \
                    --writer \
                    --output "$NS_KEY_FILE" &>/dev/null
            fi

            if [ "$VERBOSE" = true ]; then
                echo "  Storing (Calypso): $domain → $ip"
            fi
            CRYPTO_TYPE=calypso \
                CALYPSO_PARAMS_FILE="$WORKSPACE/approaches/calypso/params.bin" \
                CALYPSO_WRITER_KEY="$NS_KEY_FILE" \
                CALYPSO_MAX_DEPTH=7 \
                ETCD_ENDPOINTS="$ETCD_ENDPOINT" \
                $ETCD_CLIENT -register "${domain}=${ip}" &>/dev/null
            ;;
    esac
}

# Function to generate IP from service/namespace indices
generate_ip() {
    local service_idx="$1"
    local namespace_idx="$2"

    # Generate IP in 10.x.y.z range
    # 10.namespace.(service/256).(service%256)
    local octet3=$((service_idx / 256))
    local octet4=$((service_idx % 256))

    echo "10.${namespace_idx}.${octet3}.${octet4}"
}

# Create services distributed across namespaces
echo "Creating DNS entries..."

# Calculate services per namespace
SERVICES_PER_NS=$((SERVICE_COUNT / NAMESPACE_COUNT))
REMAINING=$((SERVICE_COUNT % NAMESPACE_COUNT))

service_counter=1

for ((ns=1; ns<=NAMESPACE_COUNT; ns++)); do
    namespace="namespace-${ns}"

    # Determine how many services in this namespace
    services_in_ns=$SERVICES_PER_NS
    if [ $ns -le $REMAINING ]; then
        services_in_ns=$((services_in_ns + 1))
    fi

    if [ "$VERBOSE" = true ]; then
        echo ""
        echo "Namespace: $namespace (${services_in_ns} services)"
    fi

    for ((s=1; s<=services_in_ns; s++)); do
        service="service-${service_counter}"
        ip=$(generate_ip $service_counter $ns)

        create_dns_entry "$service" "$namespace" "$ip" "$BASE_APPROACH"

        # Show progress
        if [ $((service_counter % 100)) -eq 0 ]; then
            echo "  Progress: ${service_counter}/${SERVICE_COUNT}"
        fi

        service_counter=$((service_counter + 1))
    done
done

echo ""
echo "✓ Created ${SERVICE_COUNT} DNS entries across ${NAMESPACE_COUNT} namespaces"
echo ""

# Verify entries (sample check using actual service distribution)
echo "Verification (sampling 3 random entries):"
for i in 1 2 3; do
    # Pick a random service index (1 to SERVICE_COUNT)
    rand_service=$((RANDOM % SERVICE_COUNT + 1))

    # Calculate which namespace this service belongs to
    services_per_ns=$((SERVICE_COUNT / NAMESPACE_COUNT))
    remaining=$((SERVICE_COUNT % NAMESPACE_COUNT))

    # Determine namespace based on service distribution
    cumulative=0
    for ((ns=1; ns<=NAMESPACE_COUNT; ns++)); do
        services_in_ns=$services_per_ns
        if [ $ns -le $remaining ]; then
            services_in_ns=$((services_in_ns + 1))
        fi
        cumulative=$((cumulative + services_in_ns))
        if [ $rand_service -le $cumulative ]; then
            rand_ns=$ns
            break
        fi
    done

    service="service-${rand_service}"
    namespace="namespace-${rand_ns}"
    domain="${service}.${namespace}.svc.cluster.local"

    # Set etcd path based on approach (calypso uses different prefix)
    if [ "$BASE_APPROACH" = "calypso" ]; then
        etcd_path_prefix="/skydns-calypso"
    else
        etcd_path_prefix="/skydns"
    fi
    etcd_path="${etcd_path_prefix}/local/cluster/svc/${namespace}/${service}"

    case "$BASE_APPROACH" in
        plain|jwt)
            # Check etcd directly
            result=$($ETCDCTL --endpoints="$ETCD_ENDPOINT" get "$etcd_path" 2>/dev/null)
            if [ -n "$result" ]; then
                echo "  • $domain: ✓ Present in etcd"
            else
                echo "  • $domain: ✗ Not found"
            fi
            ;;

        enclave)
            # For enclave: verify with etcd-client decryption
            echo "  • Testing: $domain"
            result=$(CRYPTO_TYPE=aes AES_KEY_FILE="$WORKSPACE/approaches/enclave/aes.key" \
                ETCD_ENDPOINTS="$ETCD_ENDPOINT" \
                $ETCD_CLIENT -lookup "$domain" 2>&1)
            if echo "$result" | grep -q "10\." &>/dev/null; then
                echo "    ✓ Encrypted and retrievable"
            else
                echo "    ✗ Failed to decrypt"
            fi
            ;;

        enclave-jwt)
            # For enclave-jwt: verify with etcd-client decryption
            echo "  • Testing: $domain"
            result=$(CRYPTO_TYPE=aes AES_KEY_FILE="$WORKSPACE/approaches/enclave-jwt/aes.key" \
                ETCD_ENDPOINTS="$ETCD_ENDPOINT" \
                $ETCD_CLIENT -lookup "$domain" 2>&1)
            if echo "$result" | grep -q "10\." &>/dev/null; then
                echo "    ✓ Encrypted and retrievable"
            else
                echo "    ✗ Failed to decrypt"
            fi
            ;;

        wkdibe|calypso)
            # For wkdibe/calypso: verify entry exists in etcd (can't decrypt without keys)
            result=$($ETCDCTL --endpoints="$ETCD_ENDPOINT" get "$etcd_path" 2>/dev/null)
            if [ -n "$result" ]; then
                echo "  • $domain: ✓ Present in etcd (encrypted)"
            else
                echo "  • $domain: ✗ Not found"
            fi
            ;;
    esac
done

echo ""
echo "DNS entries ready for benchmarking!"
echo ""
echo "Example queries (from repository root):"

case "$APPROACH" in
    plain|enclave)
        echo "  ./build/q -i A service-1.namespace-1.svc.cluster.local @https://localhost:8443"
        ;;
    jwt|enclave-jwt)
        echo "  # First generate a JWT token:"
        echo "  JWT_TOKEN=\$(cd ./approaches/$BASE_APPROACH && ../../build/jwt-tools generate-token --algorithm EdDSA --client-id test --permissions query --expiry 1h | tail -1)"
        echo ""
        echo "  # Then query with the token:"
        echo "  ./build/q -i --jwt --token \"\$JWT_TOKEN\" A service-1.namespace-1.svc.cluster.local @https://localhost:8443"
        ;;
    wkdibe)
        echo "  ./build/q -i A service-1.namespace-1.svc.cluster.local @https://localhost:8443 --wkdibe --params=./approaches/wkdibe/params.bin --key=./approaches/wkdibe/keys/service-1.namespace-1.svc.cluster.local.key"
        ;;
    calypso)
        echo "  # First derive reader key from namespace writer key:"
        echo "  ./build/etcd-client calypso keyder --params=./approaches/calypso/params.bin --parent-key=./approaches/calypso/keys/namespace-1.key --domain=service-1.namespace-1.svc.cluster.local --output=./approaches/calypso/keys/service-1.namespace-1.svc.cluster.local-writer.key"
        echo ""
        echo "  ./build/etcd-client calypso reader --writer=./approaches/calypso/keys/service-1.namespace-1.svc.cluster.local-writer.key --output=./approaches/calypso/keys/service-1.namespace-1.svc.cluster.local-reader.key"
        echo ""
        echo "  # Then query with the reader key:"
        echo "  ./build/q -i A service-1.namespace-1.svc.cluster.local @https://localhost:8443 --calypso --params=./approaches/calypso/params.bin --key=./approaches/calypso/keys/service-1.namespace-1.svc.cluster.local-reader.key"
        ;;
esac

echo ""
echo "To run benchmarks, use the appropriate benchmark script for your approach."