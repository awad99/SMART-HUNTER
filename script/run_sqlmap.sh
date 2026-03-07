#!/bin/bash

# Usage: run_sqlmap.sh <targets_file> <output_dir>

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

echo "[*] Starting SQLMap bulk scan"

# Prepare cookie arg
COOKIE_ARG=""
if [ -n "$COOKIE" ]; then
    COOKIE_ARG="--cookie=\"$COOKIE\""
fi

# Read targets and run sqlmap
while IFS='|' read -r method url data || [ -n "$method" ]; do
    [ -z "$method" ] && continue
    
    echo "Scanning ($method): $url"
    
    # Prepare arguments
    ARGS=("-u" "$url" "--batch" "--random-agent" "--level=1" "--risk=1" "--output-dir=$OUT_DIR")
    [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")
    
    if [ "$method" == "POST" ]; then
        ARGS+=("--data=$data")
    fi

    echo "Running: sqlmap ${ARGS[*]}"
    sqlmap "${ARGS[@]}"
done < "$TARGETS_FILE"

echo "[*] SQLMap scan complete"
