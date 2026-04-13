#!/bin/bash
set -e

# Load common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Usage
usage() {
    echo "Usage: $0 <approach>"
    echo ""
    echo "Available approaches:"
    echo "  plain       - Plain DoH (Baseline)"
    echo "  enclave     - Enclave-Protected CoreDNS"
    echo "  jwt         - JWT-Authorized DoH"
    echo "  enclave-jwt - Enclave + JWT (AES encryption + JWT authorization) + DoH"
    echo "  wkdibe     - WKD-IBE + DoH/UDP"
    echo "  calypso     - Calypso + DoH/UDP"
    exit 1
}

# Check arguments
if [ $# -ne 1 ]; then
    usage
fi

APPROACH="$1"

# Strip -udp suffix if present (used for UDP benchmarking)
BASE_APPROACH="$APPROACH"
if [[ "$APPROACH" == *-udp ]]; then
    BASE_APPROACH="${APPROACH%-udp}"
fi

# Use approaches directory directly (templates are version controlled, runtime files are gitignored)
APPROACH_DIR="$WORKSPACE/approaches/${BASE_APPROACH}"

# Check workspace exists
if [ ! -d "$WORKSPACE/repos/coredns" ]; then
    echo "ERROR: CoreDNS repository not found at $WORKSPACE/repos/coredns"
    echo "Run setup-vm.sh and use-vendored.sh first"
    exit 1
fi

echo "=== Starting ${APPROACH} approach ==="
echo ""

# Check for and stop any running services
RUNNING_SERVICES=false
for approach_dir in "$WORKSPACE/approaches"/*; do
    if [ -d "$approach_dir" ]; then
        if [ -f "$approach_dir/coredns.pid" ] || [ -f "$approach_dir/etcd.pid" ]; then
            RUNNING_SERVICES=true
            break
        fi
    fi
done

if [ "$RUNNING_SERVICES" = true ]; then
    echo "Detected running services, stopping them first..."
    "$SCRIPT_DIR/stop.sh"
    echo ""
fi

# Approach-specific configurations
case "$BASE_APPROACH" in
    plain)
        PLUGINS="etcd:etcd"
        ;;

    enclave)
        PLUGINS="etcd_crypto:etcd_crypto"
        ;;

    jwt)
        PLUGINS="etcd:etcd,jwt_edns:jwt_edns"
        ;;

    wkdibe)
        PLUGINS="etcd_calypso:etcd_calypso"
        ;;

    calypso)
        PLUGINS="etcd_calypso:etcd_calypso"
        ;;

    enclave-jwt)
        PLUGINS="jwt_edns:jwt_edns,etcd_crypto:etcd_crypto"
        ;;

    *)
        echo "ERROR: Unknown approach: $BASE_APPROACH"
        usage
        ;;
esac

# For enclave approach, ensure AES key exists
if [ "$BASE_APPROACH" = "enclave" ]; then
    KEY_FILE="$APPROACH_DIR/aes.key"
    if [ ! -f "$KEY_FILE" ]; then
        echo "Generating AES-256 key for enclave approach..."
        openssl rand -out "$KEY_FILE" 32
        echo "  ✓ Key saved to $KEY_FILE"
        echo ""
    fi
fi

# For enclave-jwt approach, ensure AES key and JWT keys exist
if [ "$BASE_APPROACH" = "enclave-jwt" ]; then
    AES_KEY="$APPROACH_DIR/aes.key"
    if [ ! -f "$AES_KEY" ]; then
        echo "Generating AES-256 key for enclave-jwt approach..."
        openssl rand -out "$AES_KEY" 32
        echo "  ✓ AES key saved to $AES_KEY"
    fi

    if [ ! -f "$APPROACH_DIR/private.pem" ] || [ ! -f "$APPROACH_DIR/public.pem" ]; then
        echo "ERROR: JWT keys not found in $APPROACH_DIR"
        echo "Generate JWT keys with: cd $APPROACH_DIR && ../../build/jwt-tools generate-keys --algorithm EdDSA"
        exit 1
    fi
fi

# For wkdibe approach, ensure params and keys exist
if [ "$BASE_APPROACH" = "wkdibe" ]; then
    PARAMS_FILE="$APPROACH_DIR/params.bin"
    MASTER_KEY="$APPROACH_DIR/master.key"
    TEST_KEY="$APPROACH_DIR/test.key"

    if [ ! -f "$PARAMS_FILE" ] || [ ! -f "$MASTER_KEY" ]; then
        echo "Generating WKD-IBE parameters and master key..."
        # max-depth=6: 5 domain labels + 1 signature slot
        "$WORKSPACE/build/etcd-client" wkdibe setup --max-depth 6 \
            --output "$PARAMS_FILE" --master-key "$MASTER_KEY"
        echo "  ✓ Parameters saved to $PARAMS_FILE"
        echo "  ✓ Master key saved to $MASTER_KEY"
        echo ""
    fi

    # Generate test key for exact test domain (testservice.test.svc.cluster.local)
    if [ ! -f "$TEST_KEY" ]; then
        echo "Generating WKD-IBE identity key for test domain..."
        "$WORKSPACE/build/etcd-client" wkdibe keygen \
            --params "$PARAMS_FILE" --master-key "$MASTER_KEY" \
            --pattern "local,cluster,svc,test,testservice" --output "$TEST_KEY"
        echo "  ✓ Test key saved to $TEST_KEY"
        echo ""
    fi

    # Generate wildcard query key for *.*.svc.cluster.local (covers all namespaces/services)
    WILDCARD_KEY="$APPROACH_DIR/wildcard.key"
    if [ ! -f "$WILDCARD_KEY" ]; then
        echo "Generating WKD-IBE wildcard identity key for queries..."
        "$WORKSPACE/build/etcd-client" wkdibe keygen \
            --params "$PARAMS_FILE" --master-key "$MASTER_KEY" \
            --pattern "local,cluster,svc,*,*" --output "$WILDCARD_KEY"
        echo "  ✓ Wildcard key saved to $WILDCARD_KEY"
        echo ""
    fi
fi

# For calypso approach, ensure params and keys exist
if [ "$BASE_APPROACH" = "calypso" ]; then
    PARAMS_FILE="$APPROACH_DIR/params.bin"
    AUTHORITY_FILE="$APPROACH_DIR/authority.bin"
    WILDCARD_KEY="$APPROACH_DIR/wildcard.key"
    WRITER_KEY="$APPROACH_DIR/writer.key"

    if [ ! -f "$PARAMS_FILE" ] || [ ! -f "$AUTHORITY_FILE" ]; then
        echo "Generating Calypso parameters and authority..."
        # max-depth=7: 5 domain labels + 1 wildcard + 1 signature slot
        "$WORKSPACE/build/etcd-client" calypso setup --max-depth 7 \
            --output "$PARAMS_FILE" --authority "$AUTHORITY_FILE"
        echo "  ✓ Parameters saved to $PARAMS_FILE"
        echo "  ✓ Authority saved to $AUTHORITY_FILE"
        echo ""
    fi

    # Generate wildcard writer key for *.test.svc.cluster.local
    if [ ! -f "$WILDCARD_KEY" ]; then
        echo "Generating Calypso wildcard writer key..."
        "$WORKSPACE/build/etcd-client" calypso keygen \
            --params "$PARAMS_FILE" --authority "$AUTHORITY_FILE" \
            --domain "*.test.svc.cluster.local" --writer --output "$WILDCARD_KEY"
        echo "  ✓ Wildcard key saved to $WILDCARD_KEY"
        echo ""
    fi

    # Derive concrete writer key for testservice.test.svc.cluster.local
    if [ ! -f "$WRITER_KEY" ]; then
        echo "Deriving Calypso writer key for test domain..."
        "$WORKSPACE/build/etcd-client" calypso keyder \
            --params "$PARAMS_FILE" --parent-key "$WILDCARD_KEY" \
            --domain "testservice.test.svc.cluster.local" --output "$WRITER_KEY"
        echo "  ✓ Writer key saved to $WRITER_KEY"
        echo ""
    fi
fi

# Verify approach configuration exists
if [ ! -d "$APPROACH_DIR" ]; then
    echo "ERROR: Approach directory not found: $APPROACH_DIR"
    exit 1
fi
if [ ! -f "$APPROACH_DIR/Corefile" ]; then
    echo "ERROR: Corefile not found: $APPROACH_DIR/Corefile"
    exit 1
fi
if [ ! -f "$APPROACH_DIR/etcd.conf.yml" ]; then
    echo "ERROR: etcd.conf.yml not found: $APPROACH_DIR/etcd.conf.yml"
    exit 1
fi

# Step 1: Configure CoreDNS plugins
echo "Step 1: Configuring CoreDNS plugins"
configure_coredns_plugins "$PLUGINS"

echo ""
echo "Step 2: Building CoreDNS"
build_coredns "$BASE_APPROACH"

echo ""
echo "Step 3: Setting up TLS certificates"
# Generate shared CA if it doesn't exist
generate_shared_ca
# Generate server certificate for this approach if it doesn't exist
if ! generate_server_cert "$APPROACH_DIR"; then
    echo "  ✗ Failed to generate server certificate"
    exit 1
fi

echo ""
echo "Step 4: Starting etcd"
if ! start_etcd "$APPROACH_DIR" "$BASE_APPROACH"; then
    exit 1
fi

echo ""
echo "Step 5: Starting CoreDNS"
if ! start_coredns "$APPROACH_DIR" "$BASE_APPROACH"; then
    # Clean up etcd if CoreDNS fails
    stop_services "$APPROACH_DIR" "$BASE_APPROACH"
    exit 1
fi

# Get PIDs for display
ETCD_PID=$(cat "$APPROACH_DIR/etcd.pid")
COREDNS_PID=$(cat "$APPROACH_DIR/coredns.pid")

echo ""
echo "=== ${APPROACH} services running ==="
echo ""
echo "Services:"
echo "  • etcd:     http://localhost:2379 (PID: $ETCD_PID)"
echo "  • CoreDNS:  https://localhost:8443 (PID: $COREDNS_PID)"
echo ""
echo "Logs:"
echo "  • etcd:     $APPROACH_DIR/etcd.log"
echo "  • CoreDNS:  $APPROACH_DIR/coredns.log"
echo ""
echo "To stop services:"
echo "  ./scripts/stop.sh $APPROACH"
echo ""