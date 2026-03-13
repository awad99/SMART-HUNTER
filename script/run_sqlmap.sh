#!/bin/bash

# Usage: run_sqlmap.sh <targets_file> <output_dir> [extra_args...]

if [ $# -lt 2 ]; then
    echo "Usage: $0 <targets_file> <output_dir> [extra_args...]"
    exit 1
fi

TARGETS_FILE="$1"
OUT_DIR="$2"
shift 2

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
    
    # Prepare arguments (defaults that can be overridden by $@)
    ARGS=("-u" "$url" "--batch" "--random-agent" "--output-dir=$OUT_DIR" "$@")
    
    if [ "$method" == "POST" ]; then
        ARGS+=("--data=$data")
        [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")
    elif [ "$method" == "COOKIE" ]; then
        # Use BOTH the global cookie AND the target-specific cookie to maintain session
        if [ -n "$COOKIE" ]; then
            # Merge cookies if possible (data usually contains TrackingId=..., COOKIE contains session=...)
            ARGS+=("--cookie=$COOKIE; $data")
        else
            ARGS+=("--cookie=$data")
        fi
    else
        [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")
    fi

    echo "Running: sqlmap ${ARGS[*]}"
    sqlmap "${ARGS[@]}"
done < "$TARGETS_FILE"

echo "[*] SQLMap scan complete"
