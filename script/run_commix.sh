#!/bin/bash

# Usage: run_commix.sh <targets_file> <output_dir>

if [ $# -lt 2 ]; then
    echo "Usage: $0 <targets_file> <output_dir>"
    exit 1
fi

TARGETS_FILE="$1"
OUT_DIR="$2"

if [ ! -f "$TARGETS_FILE" ]; then
    echo "[-] Targets file not found: $TARGETS_FILE"
    exit 1
fi

echo "[*] Starting Commix bulk scan"

# Prepare cookie arg
COOKIE_ARG=""
if [ -n "$COOKIE" ]; then
    COOKIE_ARG="--cookie=\"$COOKIE\""
fi

# Read targets and run commix
while IFS='|' read -r method url data || [ -n "$method" ]; do
    [ -z "$method" ] && continue
    
    echo "Scanning ($method): $url"
    
    # Prepare arguments
    ARGS=("--url" "$url" "--batch" "--random-agent" "--smart" "--timeout=5")
    [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")
    
    if [ "$method" == "POST" ]; then
        ARGS+=("--data=$data")
    fi

    # Run and log
    commix "${ARGS[@]}" >> "$OUT_DIR/commix_all.log" 2>&1
done < "$TARGETS_FILE"

echo "[*] Commix scan complete"
