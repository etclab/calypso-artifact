#!/bin/bash
# Common library for Calypso benchmark approaches

# Get the repository root (parent of scripts/ directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configure CoreDNS plugin.cfg
# Args: $1 = plugins to enable (e.g., "etcd:etcd" or "etcd_calypso:etcd_calypso")
configure_coredns_plugins() {
    local plugins="$1"

    cd "$WORKSPACE/repos/coredns"

    # Backup existing plugin.cfg
    if [ -f plugin.cfg ]; then
        cp plugin.cfg plugin.cfg.backup
    fi

    # Remove all our custom plugins first
    sed -i.bak '/^etcd:etcd$/d' plugin.cfg
    sed -i.bak '/^etcd_crypto:etcd_crypto$/d' plugin.cfg
    sed -i.bak '/^etcd_calypso:etcd_calypso$/d' plugin.cfg
    sed -i.bak '/^jwt_edns:jwt_edns$/d' plugin.cfg
    rm -f plugin.cfg.bak

    # Add requested plugins after metadata:metadata
    IFS=',' read -ra PLUGIN_ARRAY <<< "$plugins"
    for plugin in "${PLUGIN_ARRAY[@]}"; do
        if ! grep -q "^${plugin}$" plugin.cfg 2>/dev/null; then
            awk -v plugin="$plugin" '/^metadata:metadata$/{print; print plugin; next} 1' plugin.cfg > plugin.cfg.tmp
            mv plugin.cfg.tmp plugin.cfg
        fi
    done

    echo "  ✓ plugin.cfg configured: $plugins"
}

# Build CoreDNS
# Args: $1 = approach name (for binary naming)
build_coredns() {
    local approach="$1"

    cd "$WORKSPACE/repos/coredns"
    go generate
    go build -o "$WORKSPACE/build/coredns-${approach}"

    if [[ "$approach" == "enclave" ]]; then
        echo "  → Building coredns with ego..."
        make ego-eval
        cp coredns-ego "$WORKSPACE/build/coredns-${approach}"
    fi

    echo "  ✓ CoreDNS built: $WORKSPACE/build/coredns-${approach}"
}

# Generate shared CA certificate (one-time setup)
generate_shared_ca() {
    local shared_ca_dir="$WORKSPACE/approaches/shared-ca"
    mkdir -p "$shared_ca_dir"

    if [ -f "$shared_ca_dir/ca-cert.pem" ] && [ -f "$shared_ca_dir/ca-key.pem" ]; then
        echo "  ✓ Shared CA already exists, skipping"
        return
    fi

    echo "  → Generating shared CA certificate"
    cd "$shared_ca_dir"

    # Generate CA private key
    openssl genrsa -out ca-key.pem 2048 2>/dev/null

    # Generate CA certificate (365 days validity)
    openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
        -subj "/C=US/ST=State/L=City/O=Calypso-Benchmark/CN=Calypso-CA" 2>/dev/null

    echo "  ✓ Shared CA generated: $shared_ca_dir/ca-cert.pem"
}

# Generate server certificate for one approach (one-time setup)
# Args: $1 = config directory
generate_server_cert() {
    local config_dir="$1"
    local shared_ca_dir="$WORKSPACE/approaches/shared-ca"

    mkdir -p "$config_dir"

    # Verify shared CA exists
    if [ ! -f "$shared_ca_dir/ca-cert.pem" ] || [ ! -f "$shared_ca_dir/ca-key.pem" ]; then
        echo "  ✗ Shared CA not found. Call generate_shared_ca first"
        return 1
    fi

    # Copy shared CA to approach directory
    cp "$shared_ca_dir/ca-cert.pem" "$config_dir/ca-cert.pem"
    cp "$shared_ca_dir/ca-key.pem" "$config_dir/ca-key.pem"

    cd "$config_dir"

    if [ -f cert.pem ] && [ -f key.pem ]; then
        echo "    ✓ Server certificates already exist, skipping"
        return
    fi

    # Generate server private key
    openssl genrsa -out key.pem 2048 2>/dev/null

    # Create OpenSSL config with SANs
    cat > cert.conf << 'SSLCONF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = State
L = City
O = Calypso-Benchmark
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
SSLCONF

    # Generate server certificate signing request with SANs
    openssl req -new -key key.pem -out cert.csr -config cert.conf 2>/dev/null

    # Generate server certificate with SANs (365 days validity)
    openssl x509 -req -days 365 -in cert.csr \
        -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
        -out cert.pem -extensions v3_req -extfile cert.conf 2>/dev/null

    # Clean up
    rm cert.csr cert.conf

    echo "    ✓ Server certificate generated"
}


# Generate Corefile
# Args: $1 = config directory, $2 = corefile content
generate_corefile() {
    local config_dir="$1"
    local content="$2"

    cd "$config_dir"
    echo "$content" > Corefile
    echo "  ✓ Corefile created: $config_dir/Corefile"
}

# Generate etcd configuration
# Args: $1 = config directory, $2 = approach name
generate_etcd_config() {
    local config_dir="$1"
    local approach="$2"

    cd "$config_dir"
    cat > etcd.conf.yml << EOF
# etcd configuration for ${approach}
name: 'default'
data-dir: /tmp/etcd-data-${approach}
listen-client-urls: http://127.0.0.1:2379
advertise-client-urls: http://127.0.0.1:2379
listen-peer-urls: http://127.0.0.1:2380
initial-advertise-peer-urls: http://127.0.0.1:2380
initial-cluster: 'default=http://127.0.0.1:2380'
initial-cluster-token: 'etcd-cluster-${approach}'
initial-cluster-state: 'new'
log-level: info
logger: zap
EOF
    echo "  ✓ etcd config created: $config_dir/etcd.conf.yml"
}

# Start etcd
# Args: $1 = config directory, $2 = approach name
start_etcd() {
    local config_dir="$1"
    local approach="$2"

    # Clean up old data
    mkdir -p "$WORKSPACE/approaches/${approach}/tmp"
    rm -rf "$WORKSPACE/approaches/${approach}/tmp/etcd-data-${approach}"

    # Update data-dir path in config (preserve template, modify at runtime)
    local etcd_data_dir="$WORKSPACE/approaches/${approach}/tmp/etcd-data-${approach}"
    sed "s|^data-dir:.*|data-dir: ${etcd_data_dir}|" "$config_dir/etcd.conf.yml" > "$config_dir/etcd.conf.yml.runtime"

    # Start etcd in background
    "$WORKSPACE/build/etcd" --config-file "$config_dir/etcd.conf.yml.runtime" > "$config_dir/etcd.log" 2>&1 &
    local etcd_pid=$!
    echo $etcd_pid > "$config_dir/etcd.pid"

    echo "  ✓ etcd started (PID: $etcd_pid)"
    echo "    Log: $config_dir/etcd.log"

    # Wait for etcd to be ready
    sleep 2
    if ! kill -0 $etcd_pid 2>/dev/null; then
        echo "  ✗ etcd failed to start. Check logs:"
        tail -n 20 "$config_dir/etcd.log"
        return 1
    fi

    return 0
}

# Start CoreDNS
# Args: $1 = config directory, $2 = approach name
start_coredns() {
    local config_dir="$1"
    local approach="$2"

    cd "$config_dir"

    # Start CoreDNS
    if [ "$approach" = "enclave" ]; then
        ego run "$WORKSPACE/build/coredns-${approach}" -conf Corefile > coredns.log 2>&1 &
    else
        "$WORKSPACE/build/coredns-${approach}" -conf Corefile > coredns.log 2>&1 &
    fi

    local coredns_pid=$!
    echo $coredns_pid > coredns.pid

    echo "  ✓ CoreDNS started (PID: $coredns_pid)"
    echo "    Log: $config_dir/coredns.log"

    # Wait for CoreDNS to be ready
    sleep 2
    if ! kill -0 $coredns_pid 2>/dev/null; then
        echo "  ✗ CoreDNS failed to start. Check logs:"
        tail -n 20 "$config_dir/coredns.log"
        return 1
    fi

    return 0
}

# Stop services for an approach
# Args: $1 = config directory, $2 = approach name
stop_services() {
    local config_dir="$1"
    local approach="$2"

    # Stop CoreDNS
    if [ -f "$config_dir/coredns.pid" ]; then
        local coredns_pid=$(cat "$config_dir/coredns.pid")
        if kill -0 $coredns_pid 2>/dev/null; then
            kill $coredns_pid
            echo "  ✓ CoreDNS stopped (PID: $coredns_pid)"
        else
            echo "  ⚠ CoreDNS not running"
        fi
        rm "$config_dir/coredns.pid"
    else
        echo "  ⚠ CoreDNS PID file not found, searching for process..."
        # Fallback: search for CoreDNS process by binary name
        local coredns_binary="coredns-${approach}"
        if pkill -f "$coredns_binary" 2>/dev/null; then
            echo "  ✓ CoreDNS stopped (found via pkill)"
        else
            echo "  ℹ No CoreDNS process found"
        fi
    fi

    # Stop etcd
    if [ -f "$config_dir/etcd.pid" ]; then
        local etcd_pid=$(cat "$config_dir/etcd.pid")
        if kill -0 $etcd_pid 2>/dev/null; then
            kill $etcd_pid
            echo "  ✓ etcd stopped (PID: $etcd_pid)"
        else
            echo "  ⚠ etcd not running"
        fi
        rm "$config_dir/etcd.pid"
    else
        echo "  ⚠ etcd PID file not found, searching for process..."
        # Fallback: search for etcd process with matching data directory
        local etcd_data_dir="$WORKSPACE/approaches/${approach}/tmp/etcd-data-${approach}"
        if pkill -f "etcd.*${etcd_data_dir}" 2>/dev/null; then
            echo "  ✓ etcd stopped (found via pkill)"
        else
            echo "  ℹ No etcd process found"
        fi
    fi

    # Clean up data directory
    if [ -d "$WORKSPACE/approaches/${approach}/tmp/etcd-data-${approach}" ]; then
        rm -rf "$WORKSPACE/approaches/${approach}/tmp/etcd-data-${approach}"
        echo "  ✓ Cleaned up etcd data directory"
    fi
}