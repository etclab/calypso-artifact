#!/bin/bash
set -e

# Parse command line arguments
INCLUDE_EGO=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -with-ego|--with-ego)
            INCLUDE_EGO=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-with-ego]"
            exit 1
            ;;
    esac
done

echo "=== Calypso Component Builder ==="
echo ""

# Load common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Check if repos exist
if [ ! -d "$WORKSPACE/repos" ]; then
    echo "ERROR: $WORKSPACE/repos not found"
    echo "Run setup-vm.sh and use-vendored.sh first"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed"
    echo "Run setup-vm.sh first to install Go"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "Using Go $GO_VERSION"
echo ""

cd "$WORKSPACE/repos"

echo "Step 1: Tidy module dependencies"
echo ""

# github.com/etclab/calypso is consumed as a published Go module
# (pinned in each go.mod); tidy fetches it and refreshes go.sum.
for dir in ztrust-dns/etcd-client q coredns; do
    if [ -d "$dir" ]; then
        echo "  → go mod tidy in $dir"
        (cd "$dir" && go mod tidy)
    fi
done

echo ""
echo "Step 2: Building components"
echo ""

# Build etcd-client
if [ -d "ztrust-dns/etcd-client" ]; then
    echo "  → Building etcd-client..."
    cd ztrust-dns/etcd-client
    go build -o "$WORKSPACE/build/etcd-client"
    echo "    ✓ $WORKSPACE/build/etcd-client"
    cd "$WORKSPACE/repos"
fi

# Build jwt-tools
if [ -d "ztrust-dns/jwt-tools" ]; then
    echo "  → Building jwt-tools..."
    cd ztrust-dns/jwt-tools
    go build -o "$WORKSPACE/build/jwt-tools"
    echo "    ✓ $WORKSPACE/build/jwt-tools"
    cd "$WORKSPACE/repos"
fi

# Build q
if [ -d "q" ]; then
    echo "  → Building q..."
    cd q
    go build -o "$WORKSPACE/build/q"
    echo "    ✓ $WORKSPACE/build/q"
    cd "$WORKSPACE/repos"
fi

# Build coredns
if [ -d "coredns" ]; then
    echo "  → Building coredns..."
    cd coredns
    go generate
    go build -o "$WORKSPACE/build/coredns"
    echo "    ✓ $WORKSPACE/build/coredns"
    cd "$WORKSPACE/repos"
fi

# Build etcd
if [ -d "etcd" ]; then
    echo "  → Building etcd..."
    cd etcd
    make build
    cp bin/etcd "$WORKSPACE/build/etcd"
    cp bin/etcdctl "$WORKSPACE/build/etcdctl"
    echo "    ✓ $WORKSPACE/build/etcd"
    echo "    ✓ $WORKSPACE/build/etcdctl"
    cd "$WORKSPACE/repos"
fi

# Build ego - only if -with-ego flag is set
if [ "$INCLUDE_EGO" = true ]; then
    # Pre-generate the AES key and TLS cert that enclave-eval.json embeds
    # into the signed enclave. start.sh would otherwise generate these at
    # runtime, but ego sign needs them at build time. Idempotent: keep the
    # existing key if one is already there so we do not invalidate any
    # records etcd-client has encrypted under it.
    ENCLAVE_DIR="$WORKSPACE/approaches/enclave"
    mkdir -p "$ENCLAVE_DIR"
    if [ ! -f "$ENCLAVE_DIR/aes.key" ]; then
        echo "  → Pre-generating enclave embed files (aes.key, cert.pem, key.pem)..."
        openssl rand -out "$ENCLAVE_DIR/aes.key" 32
        ( cd "$ENCLAVE_DIR" && bash "$WORKSPACE/repos/coredns/gen_certs.sh" ) >/dev/null
        echo "    ✓ embed files ready in $ENCLAVE_DIR"
    fi

    echo "  → Building coredns with ego..."
    cd coredns
    make ego-eval
    cp coredns-ego "$WORKSPACE/build/coredns"
    echo "    ✓ $WORKSPACE/build/coredns"
    cd - > /dev/null
fi

echo ""
echo "✓ All components built successfully!"
echo ""
echo "Binaries available in: $WORKSPACE/build/"
ls -lh "$WORKSPACE/build/"
