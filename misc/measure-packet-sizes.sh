#!/bin/bash
# Measure DNS packet sizes for a specific access control approach
# Note: CoreDNS configuration must be changed between approaches
# Usage: ./measure-packet-sizes.sh <approach>
#   approach: plain, jwt, wkd-ibe, or calypso
#
# Supports both DoH (https://...) and plain DNS (host:port or IP:port)
# Examples:
#   SERVER="https://localhost:8443/dns-query" (DoH)
#   SERVER="localhost:1053" (plain DNS over UDP/TCP)

set -e

# Configuration
APPROACH="${1:-plain}"
DOMAIN="${DOMAIN:-a.default.svc.cluster.local}"
RECORD_TYPE="${RECORD_TYPE:-A}"
SERVER="${SERVER:-https://localhost:443/dns-query}"

# Detect transport type based on SERVER format
if [[ "$SERVER" =~ ^https?:// ]]; then
    TRANSPORT="doh"
    TRANSPORT_FLAGS="--http2"
else
    TRANSPORT="plain"
    TRANSPORT_FLAGS=""
fi

# Path to q binary. Defaults to the artifact's build output relative to
# this script's location; override with the Q_BIN environment variable.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Q_BIN="${Q_BIN:-$SCRIPT_DIR/../experiments/build/q}"

# JWT token
JWT_TOKEN="${JWT_TOKEN:-}"

# WKD-IBE keys
WKDIBE_PARAMS="${WKDIBE_PARAMS:-}"
WKDIBE_KEY="${WKDIBE_KEY:-}"

# Calypso keys
CALYPSO_PARAMS="${CALYPSO_PARAMS:-}"
CALYPSO_KEY="${CALYPSO_KEY:-}"

echo "=== DNS Packet Size Measurement ==="
echo "Approach: $APPROACH"
echo "Domain: $DOMAIN"
echo "Record Type: $RECORD_TYPE"
echo "Server: $SERVER"
echo "Transport: $TRANSPORT"
echo ""

# Function to extract sizes from log output
extract_sizes() {
    local output="$1"
    local dns_req=$(echo "$output" | grep -o 'dns_req=[0-9]*' | cut -d'=' -f2)
    local dns_resp=$(echo "$output" | grep -o 'dns_resp=[0-9]*' | cut -d'=' -f2)

    if [ "$TRANSPORT" = "doh" ]; then
        local http_req=$(echo "$output" | grep -o 'http_req=[0-9]*' | cut -d'=' -f2)
        local http_resp=$(echo "$output" | grep -o 'http_resp=[0-9]*' | cut -d'=' -f2)
        echo "$dns_req,$dns_resp,$http_req,$http_resp"
    else
        local wire_req=$(echo "$output" | grep -o 'wire_req=[0-9]*' | cut -d'=' -f2)
        local wire_resp=$(echo "$output" | grep -o 'wire_resp=[0-9]*' | cut -d'=' -f2)
        echo "$dns_req,$dns_resp,$wire_req,$wire_resp"
    fi
}

# Run measurement based on approach
case "$APPROACH" in
    plain)
        if [ "$TRANSPORT" = "doh" ]; then
            echo "Measuring Plain DoH..."
        else
            echo "Measuring Plain DNS..."
        fi
        OUTPUT=$($Q_BIN "$RECORD_TYPE" "$DOMAIN" "@$SERVER" --measure-sizes $TRANSPORT_FLAGS 2>&1 || true)
        ;;
    jwt)
        if [ -z "$JWT_TOKEN" ]; then
            echo "Error: JWT_TOKEN environment variable required for JWT approach"
            exit 1
        fi
        if [ "$TRANSPORT" = "doh" ]; then
            echo "Measuring JWT over DoH..."
        else
            echo "Measuring JWT over DNS..."
        fi
        OUTPUT=$($Q_BIN "$RECORD_TYPE" "$DOMAIN" "@$SERVER" --measure-sizes $TRANSPORT_FLAGS --jwt --token="$JWT_TOKEN" 2>&1 || true)
        ;;
    wkd-ibe)
        if [ -z "$WKDIBE_PARAMS" ] || [ -z "$WKDIBE_KEY" ]; then
            echo "Error: WKDIBE_PARAMS and WKDIBE_KEY environment variables required for WKD-IBE approach"
            exit 1
        fi
        if [ "$TRANSPORT" = "doh" ]; then
            echo "Measuring WKD-IBE over DoH..."
        else
            echo "Measuring WKD-IBE over DNS..."
        fi
        OUTPUT=$($Q_BIN "$RECORD_TYPE" "$DOMAIN" "@$SERVER" --measure-sizes $TRANSPORT_FLAGS --wkdibe --params="$WKDIBE_PARAMS" --key="$WKDIBE_KEY" 2>&1 || true)
        ;;
    calypso)
        if [ -z "$CALYPSO_PARAMS" ] || [ -z "$CALYPSO_KEY" ]; then
            echo "Error: CALYPSO_PARAMS and CALYPSO_KEY environment variables required for Calypso approach"
            exit 1
        fi
        if [ "$TRANSPORT" = "doh" ]; then
            echo "Measuring Calypso over DoH..."
        else
            echo "Measuring Calypso over DNS..."
        fi
        OUTPUT=$($Q_BIN "$RECORD_TYPE" "$DOMAIN" "@$SERVER" --measure-sizes $TRANSPORT_FLAGS --calypso --params="$CALYPSO_PARAMS" --key="$CALYPSO_KEY" 2>&1 || true)
        ;;
    *)
        echo "Error: Unknown approach '$APPROACH'"
        echo "Usage: $0 <approach>"
        echo "  approach: plain, jwt, wkd-ibe, or calypso"
        exit 1
        ;;
esac

# Check if query was successful
if echo "$OUTPUT" | grep -qi "error\|fatal\|failed"; then
    echo "Error: Query failed"
    echo ""
    echo "=== Full Output ==="
    echo "$OUTPUT"
    exit 1
fi

# Check if we got a DNS response (should contain the domain name)
if ! echo "$OUTPUT" | grep -q "$DOMAIN"; then
    echo "Error: No DNS response found in output"
    echo ""
    echo "=== Full Output ==="
    echo "$OUTPUT"
    exit 1
fi

# For A records, verify we got an IP address
if [ "$RECORD_TYPE" = "A" ]; then
    if ! echo "$OUTPUT" | grep -Eq '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
        echo "Error: No IP address found in A record response"
        echo ""
        echo "=== Full Output ==="
        echo "$OUTPUT"
        exit 1
    fi
fi

# Extract sizes
SIZES=$(extract_sizes "$OUTPUT")
DNS_REQ=$(echo "$SIZES" | cut -d',' -f1)
DNS_RESP=$(echo "$SIZES" | cut -d',' -f2)
LAYER_REQ=$(echo "$SIZES" | cut -d',' -f3)
LAYER_RESP=$(echo "$SIZES" | cut -d',' -f4)

# Check if we got valid sizes
if [ -z "$DNS_REQ" ] || [ -z "$DNS_RESP" ]; then
    echo "Error: Failed to extract sizes from output"
    echo ""
    echo "=== Full Output ==="
    echo "$OUTPUT"
    exit 1
fi

echo ""
echo "=== Query Successful ==="
# Show the answer
echo "$OUTPUT" | grep "$DOMAIN" | head -3

echo ""
echo "=== Results ==="
echo "DNS Request Size:   $DNS_REQ bytes"
echo "DNS Response Size:  $DNS_RESP bytes"
if [ "$TRANSPORT" = "doh" ]; then
    echo "HTTP Request Size:  $LAYER_REQ bytes"
    echo "HTTP Response Size: $LAYER_RESP bytes"
else
    echo "Wire Request Size:  $LAYER_REQ bytes"
    echo "Wire Response Size: $LAYER_RESP bytes"
fi
echo ""
echo "CSV Format:"
echo "$APPROACH,$DNS_REQ,$DNS_RESP,$LAYER_REQ,$LAYER_RESP"