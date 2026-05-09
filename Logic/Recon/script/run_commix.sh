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
while IFS='|' read -r method url data test_params page_url || [ -n "$method" ]; do
    [ -z "$method" ] && continue

    echo "Scanning ($method): $url"

    # Prepare arguments — no --smart (it skips valid targets), higher timeout
    ARGS=(
        "--url" "$url"
        "--batch"
        "--random-agent"
        "--timeout=30"
        "--level=3"
        "--time-sec=${COMMIX_TIME_SEC:-5}"
        "--ignore-session"
        "--flush-session"
        "--url-reload"
        "--ignore-code=400,401,403,404,500"
    )
    [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")

    SELECTED_PARAMS="$test_params"
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
        if [ -n "$FUZZ_PARAM" ]; then
            SELECTED_PARAMS="$FUZZ_PARAM"
        fi
    fi

    if [ -n "$SELECTED_PARAMS" ]; then
        ARGS+=("-p" "$SELECTED_PARAMS")
    fi

    # Run and log
    commix "${ARGS[@]}" >> "$OUT_DIR/commix_all.log" 2>&1
done < "$TARGETS_FILE"

echo "[*] Commix scan complete"
