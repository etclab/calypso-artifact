#!/bin/bash

# Load common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

echo "=== Stopping services ==="
echo ""

STOPPED_ANY=false

# Find all approach directories with PID files or running processes
for approach_dir in "$WORKSPACE/approaches"/*; do
    if [ -d "$approach_dir" ]; then
        approach=$(basename "$approach_dir")

        # Check if this approach has any running services
        if [ -f "$approach_dir/coredns.pid" ] || [ -f "$approach_dir/etcd.pid" ]; then
            echo "Stopping $approach (via PID files)..."
            stop_services "$approach_dir" "$approach"
            STOPPED_ANY=true
            echo ""
        else
            # Check if processes are running without PID files
            coredns_binary="coredns-${approach}"
            etcd_data_dir="/tmp/etcd-data-${approach}"

            if pgrep -f "$coredns_binary" > /dev/null 2>&1 || pgrep -f "etcd.*${etcd_data_dir}" > /dev/null 2>&1; then
                echo "Stopping $approach (via process search)..."
                stop_services "$approach_dir" "$approach"
                STOPPED_ANY=true
                echo ""
            fi
        fi
    fi
done

# Final cleanup: kill any remaining coredns/etcd processes as a safety net
echo "Running final cleanup check..."
remaining_killed=false

# Kill any remaining CoreDNS processes
if pgrep -f "coredns-" > /dev/null 2>&1; then
    echo "  ⚠ Found orphaned CoreDNS processes, cleaning up..."
    pkill -f "coredns-" 2>/dev/null && echo "  ✓ Orphaned CoreDNS processes killed"
    remaining_killed=true
fi

# Kill any remaining etcd processes (only from our benchmark)
if pgrep -f "etcd.*etcd-data-" > /dev/null 2>&1; then
    echo "  ⚠ Found orphaned etcd processes, cleaning up..."
    pkill -f "etcd.*etcd-data-" 2>/dev/null && echo "  ✓ Orphaned etcd processes killed"
    remaining_killed=true
fi

if [ "$remaining_killed" = false ]; then
    echo "  ✓ No orphaned processes found"
fi

if [ "$STOPPED_ANY" = false ] && [ "$remaining_killed" = false ]; then
    echo "No running services found"
fi

echo ""
echo "Done"