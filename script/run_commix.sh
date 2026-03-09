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

# Read targets and run commix
while IFS='|' read -r method url data || [ -n "$method" ]; do
    [ -z "$method" ] && continue

    echo "Scanning ($method): $url"

    # Prepare arguments — no --smart (it skips valid targets), higher timeout
    ARGS=("--url" "$url" "--batch" "--random-agent" "--timeout=30")
    [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")

    if [ "$method" == "POST" ]; then
        # Find which parameter has FUZZ and target it specifically
        FUZZ_PARAM=""
        CLEAN_DATA=""
        IFS='&' read -ra PAIRS <<< "$data"
        for pair in "${PAIRS[@]}"; do
            pname="${pair%%=*}"
            pval="${pair#*=}"
            if [ "$pval" == "FUZZ" ]; then
                FUZZ_PARAM="$pname"
                # Replace FUZZ with a valid default value so commix can inject
                CLEAN_DATA="${CLEAN_DATA:+${CLEAN_DATA}&}${pname}=1"
            else
                CLEAN_DATA="${CLEAN_DATA:+${CLEAN_DATA}&}${pair}"
            fi
        done
        ARGS+=("--data=$CLEAN_DATA")
        # Tell commix exactly which parameter to test
        if [ -n "$FUZZ_PARAM" ]; then
            ARGS+=("-p" "$FUZZ_PARAM")
        fi
    fi

    # Run and log
    commix "${ARGS[@]}" >> "$OUT_DIR/commix_all.log" 2>&1
done < "$TARGETS_FILE"

echo "[*] Commix scan complete"
