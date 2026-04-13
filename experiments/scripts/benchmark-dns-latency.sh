#!/bin/bash
set -e

# Load common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# DNS latency benchmarking script for Calypso approaches
# Measures end-to-end DNS resolution time and generates CDF data

# Default values
APPROACH="plain"
QUERY_COUNT=1000
SERVICE_COUNT=1000  # Must match what was populated
NAMESPACE_COUNT=10  # Must match what was populated
OUTPUT_DIR="./results"
DNS_ENDPOINT="https://localhost:8443"
NXDOMAIN_PCT=10     # Percentage of queries that should be nonexistent (0-100)
VERBOSE=false

# Usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Benchmark DNS query latency for different Calypso approaches"
    echo ""
    echo "Options:"
    echo "  -a <approach>    Approach to benchmark (plain|jwt|enclave|wkdibe|calypso) [default: plain]"
    echo "  -q <count>       Number of queries to run [default: 1000]"
    echo "  -s <count>       Number of services populated (must match populate script) [default: 1000]"
    echo "  -n <count>       Number of namespaces populated (must match populate script) [default: 10]"
    echo "  -o <dir>         Output directory for results [default: ./results]"
    echo "  -e <endpoint>    DNS endpoint URL [default: https://localhost:8443]"
    echo "  -x <percent>     Percentage of NXDOMAIN queries (0-100) [default: 10]"
    echo "  -v               Verbose output"
    echo "  -h               Show this help message"
    echo ""
    echo "Output:"
    echo "  Creates CSV file with query latencies for CDF plotting:"
    echo "    results/<approach>-<timestamp>-latencies.csv"
    echo ""
    echo "Example:"
    echo "  # Benchmark plain approach with 1000 queries"
    echo "  $0 -a plain -q 1000"
    echo ""
    echo "  # Benchmark with no NXDOMAIN queries"
    echo "  $0 -a plain -q 1000 -x 0"
    echo ""
    echo "  # Benchmark all approaches"
    echo "  for approach in plain jwt enclave wkdibe calypso; do"
    echo "    $0 -a \$approach -q 1000"
    echo "  done"
    exit 0
}

# Parse arguments
while getopts "a:q:s:n:o:e:x:vh" opt; do
    case $opt in
        a) APPROACH="$OPTARG" ;;
        q) QUERY_COUNT="$OPTARG" ;;
        s) SERVICE_COUNT="$OPTARG" ;;
        n) NAMESPACE_COUNT="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        e) DNS_ENDPOINT="$OPTARG" ;;
        x) NXDOMAIN_PCT="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Detect UDP suffix and set transport
TRANSPORT="https"
BASE_APPROACH="$APPROACH"
if [[ "$APPROACH" == *-udp ]]; then
    TRANSPORT="udp"
    BASE_APPROACH="${APPROACH%-udp}"
    # Override default endpoint for UDP if not explicitly set
    if [ "$DNS_ENDPOINT" = "https://localhost:8443" ]; then
        DNS_ENDPOINT="@localhost:1053"
    fi
else
    # Ensure HTTPS endpoint format
    if [ "$DNS_ENDPOINT" = "https://localhost:8443" ]; then
        DNS_ENDPOINT="@https://localhost:8443"
    fi
fi

# Validate base approach
case "$BASE_APPROACH" in
    plain|jwt|enclave|enclave-jwt|wkdibe|calypso)
        ;;
    *)
        echo "ERROR: Invalid approach: $BASE_APPROACH"
        echo "Valid: plain, jwt, enclave, enclave-jwt, wkdibe, calypso (with optional -udp suffix)"
        exit 1
        ;;
esac

# Validate NXDOMAIN percentage
if ! [[ "$NXDOMAIN_PCT" =~ ^[0-9]+$ ]] || [ "$NXDOMAIN_PCT" -lt 0 ] || [ "$NXDOMAIN_PCT" -gt 100 ]; then
    echo "ERROR: Invalid NXDOMAIN percentage: $NXDOMAIN_PCT (must be 0-100)"
    exit 1
fi

# Find q tool
Q_TOOL="$WORKSPACE/build/q"
if [ ! -f "$Q_TOOL" ]; then
    echo "ERROR: q tool not found at $Q_TOOL"
    echo "Run ./scripts/build-components.sh first"
    exit 1
fi

# Setup approach-specific parameters for q tool
Q_PARAMS=""
if [ "$BASE_APPROACH" = "jwt" ]; then
    JWT_TOOLS="$WORKSPACE/build/jwt-tools"
    if [ ! -f "$JWT_TOOLS" ]; then
        echo "ERROR: jwt-tools not found at $JWT_TOOLS"
        exit 1
    fi
    if [ ! -f "$WORKSPACE/approaches/jwt/private.pem" ]; then
        echo "ERROR: JWT keys not found. Generate with:"
        echo "  cd approaches/jwt && ../../build/jwt-tools generate-keys --algorithm EdDSA"
        exit 1
    fi

    echo "Generating JWT token..."
    JWT_TOKEN=$(cd "$WORKSPACE/approaches/jwt" && "$JWT_TOOLS" generate-token \
        --algorithm EdDSA \
        --client-id "benchmark-client" \
        --permissions "query" \
        --expiry "1h" 2>/dev/null | tail -1)

    if [ -z "$JWT_TOKEN" ]; then
        echo "ERROR: Failed to generate JWT token"
        exit 1
    fi

    Q_PARAMS="--jwt --token $JWT_TOKEN"
    echo "  ✓ JWT token generated"
    echo ""
elif [ "$BASE_APPROACH" = "enclave-jwt" ]; then
    JWT_TOOLS="$WORKSPACE/build/jwt-tools"
    if [ ! -f "$JWT_TOOLS" ]; then
        echo "ERROR: jwt-tools not found at $JWT_TOOLS"
        exit 1
    fi
    if [ ! -f "$WORKSPACE/approaches/enclave-jwt/private.pem" ]; then
        echo "ERROR: JWT keys not found. Generate with:"
        echo "  cd approaches/enclave-jwt && ../../build/jwt-tools generate-keys --algorithm EdDSA"
        exit 1
    fi

    echo "Generating JWT token..."
    JWT_TOKEN=$(cd "$WORKSPACE/approaches/enclave-jwt" && "$JWT_TOOLS" generate-token \
        --algorithm EdDSA \
        --client-id "benchmark-client" \
        --permissions "query" \
        --expiry "1h" 2>/dev/null | tail -1)

    if [ -z "$JWT_TOKEN" ]; then
        echo "ERROR: Failed to generate JWT token"
        exit 1
    fi

    Q_PARAMS="--jwt --token $JWT_TOKEN"
    echo "  ✓ JWT token generated"
    echo ""
elif [ "$BASE_APPROACH" = "wkdibe" ]; then
    WKDIBE_PARAMS="$WORKSPACE/approaches/wkdibe/params.bin"

    if [ ! -f "$WKDIBE_PARAMS" ]; then
        echo "ERROR: WKD-IBE params not found at $WKDIBE_PARAMS"
        exit 1
    fi

    # Note: Key will be determined per-query based on domain
    Q_PARAMS="--wkdibe --params=$WKDIBE_PARAMS"
    echo "WKD-IBE parameters configured"
    echo "  • Params: $WKDIBE_PARAMS"
    echo "  • Keys:   Per-service keys from approaches/wkdibe/"
    echo ""
elif [ "$BASE_APPROACH" = "calypso" ]; then
    CALYPSO_PARAMS="$WORKSPACE/approaches/calypso/params.bin"
    ETCD_CLIENT="$WORKSPACE/build/etcd-client"

    if [ ! -f "$CALYPSO_PARAMS" ]; then
        echo "ERROR: Calypso params not found at $CALYPSO_PARAMS"
        exit 1
    fi
    if [ ! -f "$ETCD_CLIENT" ]; then
        echo "ERROR: etcd-client not found at $ETCD_CLIENT"
        exit 1
    fi

    # Generate reader keys from writer keys if they don't exist
    echo "Checking Calypso reader keys..."
    KEYS_DIR="$WORKSPACE/approaches/calypso/keys"
    reader_keys_generated=0

    for writer_key in "$KEYS_DIR"/namespace-*.key; do
        # Skip reader keys (files ending with -reader.key)
        if [[ "$writer_key" == *-reader.key ]]; then
            continue
        fi

        if [ -f "$writer_key" ]; then
            namespace=$(basename "$writer_key" .key)
            reader_key="$KEYS_DIR/${namespace}-reader.key"

            if [ ! -f "$reader_key" ]; then
                "$ETCD_CLIENT" calypso reader --writer "$writer_key" --output "$reader_key" &>/dev/null
                reader_keys_generated=$((reader_keys_generated + 1))
            fi
        fi
    done

    if [ $reader_keys_generated -gt 0 ]; then
        echo "  ✓ Generated $reader_keys_generated reader key(s)"
    else
        echo "  ✓ All reader keys already exist"
    fi

    # Note: Reader key will be determined per-query based on namespace
    Q_PARAMS="--calypso --params=$CALYPSO_PARAMS"
    echo "  • Params: $CALYPSO_PARAMS"
    echo "  • Keys:   Per-namespace reader keys from approaches/calypso/keys/"
    echo ""
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate timestamp for output file
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}/${APPROACH}-${TIMESTAMP}-latencies.csv"
SUMMARY_FILE="${OUTPUT_DIR}/${APPROACH}-${TIMESTAMP}-summary.txt"

echo "=== DNS Latency Benchmark ==="
echo ""
echo "Configuration:"
echo "  • Approach:    $APPROACH"
echo "  • Queries:     $QUERY_COUNT"
echo "  • Services:    $SERVICE_COUNT"
echo "  • Namespaces:  $NAMESPACE_COUNT"
echo "  • NXDOMAIN:    ${NXDOMAIN_PCT}%"
echo "  • Endpoint:    $DNS_ENDPOINT"
echo "  • Output:      $OUTPUT_FILE"
echo ""

# Test DNS connectivity
echo "Testing DNS connectivity..."
TEST_DOMAIN="service-1.namespace-1.svc.cluster.local"
TEST_Q_PARAMS="$Q_PARAMS"

if [ "$BASE_APPROACH" = "wkdibe" ]; then
    # For wkdibe, use the test domain's key
    TEST_KEY="$WORKSPACE/approaches/wkdibe/keys/${TEST_DOMAIN}.key"
    if [ ! -f "$TEST_KEY" ]; then
        echo "ERROR: Test key not found at $TEST_KEY"
        exit 1
    fi
    TEST_Q_PARAMS="$Q_PARAMS --key=$TEST_KEY"
elif [ "$BASE_APPROACH" = "calypso" ]; then
    # For calypso, derive per-service reader key for test domain
    NS_WRITER_KEY="$WORKSPACE/approaches/calypso/keys/namespace-1.key"
    TEST_WRITER_KEY="$WORKSPACE/approaches/calypso/keys/${TEST_DOMAIN}-writer.key"
    TEST_READER_KEY="$WORKSPACE/approaches/calypso/keys/${TEST_DOMAIN}-reader.key"

    if [ ! -f "$TEST_READER_KEY" ]; then
        # Derive child writer key from namespace wildcard parent
        "$WORKSPACE/build/etcd-client" calypso keyder \
            --params "$CALYPSO_PARAMS" \
            --parent-key "$NS_WRITER_KEY" \
            --domain "$TEST_DOMAIN" \
            --output "$TEST_WRITER_KEY" &>/dev/null

        # Derive reader key from writer key
        "$WORKSPACE/build/etcd-client" calypso reader \
            --writer "$TEST_WRITER_KEY" \
            --output "$TEST_READER_KEY" &>/dev/null
    fi

    TEST_Q_PARAMS="$Q_PARAMS --key=$TEST_READER_KEY"
fi

if ! $Q_TOOL -i A "$TEST_DOMAIN" "${DNS_ENDPOINT}" $TEST_Q_PARAMS &>/dev/null; then
    echo "ERROR: Cannot query DNS at $DNS_ENDPOINT"
    echo "Make sure services are running: ./scripts/start.sh $BASE_APPROACH"
    echo "And DNS entries are populated: ./scripts/populate-etcd.sh"
    exit 1
fi
echo "  ✓ Connected"
echo ""

# Prepare CSV header
echo "query_num,domain,latency_ms,status" > "$OUTPUT_FILE"

# Function to measure query latency
measure_query() {
    local query_num=$1
    local domain=$2
    local q_params_final="$Q_PARAMS"

    # For wkdibe, derive the key file from the domain
    if [ "$BASE_APPROACH" = "wkdibe" ]; then
        # Use the full domain as the key filename
        local key_file="$WORKSPACE/approaches/wkdibe/keys/${domain}.key"

        if [ -f "$key_file" ]; then
            q_params_final="$Q_PARAMS --key=$key_file"
        else
            # For NXDOMAIN or missing keys, skip key parameter (will fail as expected)
            q_params_final="$Q_PARAMS"
        fi
    elif [ "$BASE_APPROACH" = "calypso" ]; then
            # For calypso, derive per-service reader key from namespace writer key
        # Domain format: service-X.namespace-Y.svc.cluster.local
        local namespace=$(echo "$domain" | cut -d. -f2)
        local namespace_writer_key="$WORKSPACE/approaches/calypso/keys/${namespace}.key"
        local service_writer_key="$WORKSPACE/approaches/calypso/keys/${domain}-writer.key"
        local service_reader_key="$WORKSPACE/approaches/calypso/keys/${domain}-reader.key"

        # Check if we need to derive the service keys
        if [ -f "$namespace_writer_key" ] && [ ! -f "$service_reader_key" ]; then
            # Derive child writer key from namespace wildcard parent
            "$WORKSPACE/build/etcd-client" calypso keyder \
                --params "$CALYPSO_PARAMS" \
                --parent-key "$namespace_writer_key" \
                --domain "$domain" \
                --output "$service_writer_key" &>/dev/null

            # Derive reader key from writer key
            "$WORKSPACE/build/etcd-client" calypso reader \
                --writer "$service_writer_key" \
                --output "$service_reader_key" &>/dev/null
        fi

        if [ -f "$service_reader_key" ]; then
            q_params_final="$Q_PARAMS --key=$service_reader_key"
        else
            # For NXDOMAIN or missing keys, skip key parameter (will fail as expected)
            q_params_final="$Q_PARAMS"
        fi
    fi

    # Run query with -S flag to get Stats output (skip TLS cert verification with -i)
    local output=$($Q_TOOL -S -i A "$domain" "${DNS_ENDPOINT}" $q_params_final 2>&1)

    # Parse timing from Stats line: "Received ... in XXms" or "Received ... in XX.Xms"
    local latency_ms=$(echo "$output" | sed -n 's/.*in \([0-9.]*\)ms.*/\1/p')
    if [ -z "$latency_ms" ]; then
        latency_ms="0"
    fi

    # Parse status from Stats line: "Status: NOERROR" vs "Status: NXDOMAIN" etc.
    if echo "$output" | grep -q "Status: NOERROR"; then
        local status="success"
    else
        local status="failed"
    fi

    echo "${query_num},${domain},${latency_ms},${status}" >> "$OUTPUT_FILE"

    if [ "$VERBOSE" = true ]; then
        echo "  Query $query_num: $domain - ${latency_ms}ms ($status)"
    fi

    echo "$latency_ms"
}

echo "Running benchmark..."
echo ""

# Arrays to store latencies for percentile calculation
declare -a latencies=()

# Query pattern: Mix of existing services and NXDOMAIN based on NXDOMAIN_PCT
# This tests both successful resolutions and error paths

for ((i=1; i<=QUERY_COUNT; i++)); do
    # Generate query based on NXDOMAIN percentage
    # Random number 0-99, if < NXDOMAIN_PCT then generate NXDOMAIN query
    random_pct=$((RANDOM % 100))

    if [ $random_pct -lt $NXDOMAIN_PCT ]; then
        # NXDOMAIN (non-existent service)
        domain="nonexistent-${i}.namespace-99.svc.cluster.local"
    else
        # Existing service (random from populated ones)
        # Match the naming from populate-etcd.sh: service-X.namespace-Y.svc.cluster.local
        service_num=$((RANDOM % SERVICE_COUNT + 1))

        # Calculate which namespace this service belongs to (same logic as populate-etcd.sh)
        services_per_ns=$((SERVICE_COUNT / NAMESPACE_COUNT))
        remaining=$((SERVICE_COUNT % NAMESPACE_COUNT))
        cumulative=0
        for ((ns=1; ns<=NAMESPACE_COUNT; ns++)); do
            services_in_ns=$services_per_ns
            if [ $ns -le $remaining ]; then
                services_in_ns=$((services_in_ns + 1))
            fi
            cumulative=$((cumulative + services_in_ns))
            if [ $service_num -le $cumulative ]; then
                ns_num=$ns
                break
            fi
        done

        domain="service-${service_num}.namespace-${ns_num}.svc.cluster.local"
    fi

    # Measure query latency
    latency=$(measure_query $i "$domain")
    latencies+=("$latency")

    # Show progress
    if [ $((i % 100)) -eq 0 ] || [ $i -eq $QUERY_COUNT ]; then
        echo "  Progress: ${i}/${QUERY_COUNT}"
    fi
done

echo ""
echo "✓ Benchmark complete"
echo ""

# Calculate statistics
echo "Calculating statistics..."

# Sort latencies for percentile calculations
IFS=$'\n' sorted_latencies=($(sort -n <<<"${latencies[*]}"))
unset IFS

# Calculate percentiles
count=${#sorted_latencies[@]}
p50_idx=$((count * 50 / 100))
p90_idx=$((count * 90 / 100))
p95_idx=$((count * 95 / 100))
p99_idx=$((count * 99 / 100))

p50="${sorted_latencies[$p50_idx]}"
p90="${sorted_latencies[$p90_idx]}"
p95="${sorted_latencies[$p95_idx]}"
p99="${sorted_latencies[$p99_idx]}"

# Find min and max
min="${sorted_latencies[0]}"
max="${sorted_latencies[$((count-1))]}"

# Calculate mean (filter out invalid values)
sum=0
valid_count=0
for lat in "${latencies[@]}"; do
    # Skip empty or non-numeric values
    if [[ "$lat" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        sum=$(echo "$sum + $lat" | bc)
        valid_count=$((valid_count + 1))
    fi
done
if [ $valid_count -gt 0 ]; then
    mean=$(echo "scale=3; $sum / $valid_count" | bc)
else
    mean="0"
fi

# Write summary
{
    echo "=== DNS Latency Benchmark Summary ==="
    echo ""
    echo "Approach: $APPROACH"
    echo "Queries:  $QUERY_COUNT"
    echo "Time:     $TIMESTAMP"
    echo ""
    echo "Latency Statistics (milliseconds):"
    echo "  Min:    ${min}ms"
    echo "  P50:    ${p50}ms"
    echo "  P90:    ${p90}ms"
    echo "  P95:    ${p95}ms"
    echo "  P99:    ${p99}ms"
    echo "  Max:    ${max}ms"
    echo "  Mean:   ${mean}ms"
} | tee "$SUMMARY_FILE"

echo ""
echo "Results saved to:"
echo "  • Raw data: $OUTPUT_FILE"
echo "  • Summary:  $SUMMARY_FILE"
echo ""
echo "To generate CDF plot, use appropriate script:"