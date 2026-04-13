#!/bin/bash
#
# Convert DNS latency CSV to sorted DAT file for CDF plotting
#
# Usage: csv-to-dat.sh <input.csv> [output.dat]
#

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <input.csv> [output.dat]"
    echo "Example: $0 results/plain-20251020-latencies.csv results/plain.dat"
    exit 1
fi

INPUT_CSV="$1"
OUTPUT_DAT="${2:-${INPUT_CSV%.csv}.dat}"

if [ ! -f "$INPUT_CSV" ]; then
    echo "Error: Input file '$INPUT_CSV' not found"
    exit 1
fi

# Extract latency_ms column (column 3), skip header, sort numerically
tail -n +2 "$INPUT_CSV" | cut -d',' -f3 | sort -n > "$OUTPUT_DAT"

echo "Created $OUTPUT_DAT ($(wc -l < "$OUTPUT_DAT") entries)"