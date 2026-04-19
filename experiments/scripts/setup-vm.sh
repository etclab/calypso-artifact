#!/bin/bash
set -e

# Parse command line arguments
INSTALL_EGO=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -with-ego|--with-ego)
            INSTALL_EGO=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-with-ego]"
            exit 1
            ;;
    esac
done

echo "=== Calypso Benchmark VM Setup ==="
echo ""

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Detected OS: $NAME $VERSION"

    if [[ "$ID" != "ubuntu" ]]; then
        echo "WARNING: This script is designed for Ubuntu LTS"
        echo "Current OS: $ID"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
else
    echo "Cannot detect OS. Assuming compatible system..."
fi

echo ""
echo "Creating workspace directories..."

# Get the repository root (2 levels up from scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
mkdir -p "$WORKSPACE"/{repos,build,results}

echo "  ✓ $WORKSPACE/repos"
echo "  ✓ $WORKSPACE/build"
echo "  ✓ $WORKSPACE/results"

echo ""
echo "Checking Go installation..."

PIN_GO_VERSION="1.25.3"
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    # sort -V -C succeeds (exit 0) iff the input is in ascending order, so
    # the test passes when GO_VERSION >= PIN_GO_VERSION.
    if printf '%s\n%s\n' "$PIN_GO_VERSION" "$GO_VERSION" | sort -V -C; then
        echo "  ✓ Go $GO_VERSION already installed (pin: $PIN_GO_VERSION)"
    else
        echo "  ⚠ Go $GO_VERSION installed, but artifact pins $PIN_GO_VERSION."
        echo "    Build may fail on this version. Install $PIN_GO_VERSION from"
        echo "    https://go.dev/dl/ to match the tested toolchain."
    fi
else
    echo "  Go not found. Installing Go 1.25.3..."

    if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
        wget -q https://go.dev/dl/go1.25.3.linux-amd64.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf go1.25.3.linux-amd64.tar.gz
        rm go1.25.3.linux-amd64.tar.gz

        # Add to PATH if not already there
        if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        fi

        export PATH=$PATH:/usr/local/go/bin
        export PATH=$PATH:$HOME/go/bin

        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        echo "  ✓ Go $GO_VERSION installed"
        echo "  NOTE: Run 'source ~/.bashrc' or restart your shell"
    else
        echo "  WARNING: Cannot auto-install Go on $ID"
        echo "  Install manually from: https://go.dev/dl/"
    fi
fi

if [ "$INSTALL_EGO" = true ]; then
    echo ""
    echo "Installing Ego (SGX enclave runtime)..."

    if [[ "$ID" == "ubuntu" ]]; then
        UBUNTU_VERSION=$(lsb_release -rs)
        echo "  Detected Ubuntu $UBUNTU_VERSION"

        # Check if version is supported
        if [[ "$UBUNTU_VERSION" != "20.04" && "$UBUNTU_VERSION" != "22.04" && "$UBUNTU_VERSION" != "24.04" ]]; then
            echo "  WARNING: Ego officially supports Ubuntu 20.04, 22.04, and 24.04"
            echo "  Your version: $UBUNTU_VERSION"
            read -p "  Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "  Skipping Ego installation"
                INSTALL_EGO=false
            fi
        fi

        if [ "$INSTALL_EGO" = true ]; then
            echo "  Installing build dependencies..."
            sudo apt-get update -qq
            sudo apt install -y build-essential libssl-dev

            echo "  Setting up Intel SGX repository..."
            sudo mkdir -p /etc/apt/keyrings
            wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
            echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
            sudo apt-get update -qq

            echo "  Downloading and installing Ego v1.8.0..."
            EGO_DEB=ego_1.8.0_amd64_ubuntu-$(lsb_release -rs).deb
            wget -q https://github.com/edgelesssys/ego/releases/download/v1.8.0/$EGO_DEB
            sudo apt install -y ./$EGO_DEB
            rm $EGO_DEB

            if command -v ego &> /dev/null; then
                EGO_VERSION=$(ego version 2>&1 | head -n1 || echo "unknown")
                echo "  ✓ Ego installed: $EGO_VERSION"
            else
                echo "  ✗ Ego installation failed"
            fi
        fi
    else
        echo "  ERROR: Ego installation only supported on Ubuntu"
        echo "  Install manually from: https://docs.edgeless.systems/ego"
    fi
fi

echo ""
echo "Workspace setup complete!"
echo "Next step: Run 'use-vendored.sh' to wire vendored sources into ./repos/"
if [ "$INSTALL_EGO" = true ]; then
    echo "Then: ./scripts/build-components.sh -with-ego"
else
    echo "Then: ./scripts/build-components.sh"
fi
