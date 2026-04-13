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

echo "Step 1: Update go.mod replace directives for calypso"
echo ""

CALYPSO_PATH="$WORKSPACE/repos/calypso"

# Update etcd-client
if [ -d "ztrust-dns/etcd-client" ]; then
    echo "  → Updating ztrust-dns/etcd-client/go.mod"
    cd ztrust-dns/etcd-client
    if grep -q "replace.*calypso" go.mod 2>/dev/null; then
        sed -i.bak "s|replace.*calypso.*=>.*|replace github.com/etclab/calypso => $CALYPSO_PATH|" go.mod
        rm -f go.mod.bak
    else
        echo "replace github.com/etclab/calypso => $CALYPSO_PATH" >> go.mod
    fi
    go mod tidy
    cd "$WORKSPACE/repos"
fi

# Update q
if [ -d "q" ]; then
    echo "  → Updating q/go.mod"
    cd q
    if grep -q "replace.*calypso" go.mod 2>/dev/null; then
        sed -i.bak "s|replace.*calypso.*=>.*|replace github.com/etclab/calypso => $CALYPSO_PATH|" go.mod
        rm -f go.mod.bak
    else
        echo "replace github.com/etclab/calypso => $CALYPSO_PATH" >> go.mod
    fi
    go mod tidy
    cd "$WORKSPACE/repos"
fi

# Update coredns
if [ -d "coredns" ]; then
    echo "  → Updating coredns/go.mod"
    cd coredns
    if grep -q "replace.*calypso" go.mod 2>/dev/null; then
        sed -i.bak "s|replace.*calypso.*=>.*|replace github.com/etclab/calypso => $CALYPSO_PATH|" go.mod
        rm -f go.mod.bak
    else
        echo "replace github.com/etclab/calypso => $CALYPSO_PATH" >> go.mod
    fi
    go mod tidy
    cd "$WORKSPACE/repos"
fi

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
