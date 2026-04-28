#!/bin/bash

# Usage: run_dalfox.sh <targets_file> <output_file> <parallel_jobs> <timeout_per_url>

if [ $# -lt 2 ]; then
    echo "Usage: $0 <targets_file> <output_file> [parallel_jobs] [timeout]"
    exit 1
fi

TARGETS_FILE="$1"
OUT_FILE="$2"
PARALLEL_JOBS="${3:-5}"
TIMEOUT="${4:-60}"

if [ ! -f "$TARGETS_FILE" ]; then
    echo "[-] Targets file not found: $TARGETS_FILE"
    exit 1
fi

echo "[*] Starting dalfox XSS scan"
echo "[*] Targets : $TARGETS_FILE"
echo "[*] Output  : $OUT_FILE"

# Prepare cookie arg
COOKIE_ARG=""
if [ -n "$COOKIE" ]; then
    COOKIE_ARG="--cookie \"$COOKIE\""
fi

# Clear output file
> "$OUT_FILE"

# Read targets and run dalfox
cnt=0
total=$(wc -l < "$TARGETS_FILE")

while IFS='|' read -r method url data || [ -n "$method" ]; do
    [ -z "$method" ] && continue
    cnt=$((cnt+1))
    
    echo "[$cnt/$total] Scanning ($method): $url"
    
    # Prepare arguments
    ARGS=("--batch" "--random-agent" "--silence" "--timeout" "$TIMEOUT")
    [ -n "$COOKIE" ] && ARGS+=("--cookie" "$COOKIE")
    
    if [ "$method" == "POST" ]; then
        if [ -n "$data" ] && [ "$data" != "FUZZ" ]; then
            ARGS+=("-d" "$data")
        else
            # Usually dalfox handles the discovery but we can pass whatever we have
            ARGS+=("-d" "$data")
        fi
    fi

    echo "Running: dalfox url \"$url\" ${ARGS[*]}" >> "$OUT_FILE.log"
    dalfox url "$url" "${ARGS[@]}" >> "$OUT_FILE" 2>&1
    
done < "$TARGETS_FILE"

echo "[*] Scan complete"
