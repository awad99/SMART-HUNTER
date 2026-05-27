#!/bin/bash
# run_dalfox.sh - Helper script to run dalfox for XSS scanning
# Arguments passed by xss_scan.py: 
# $1: URLs file
# $2: Output file
# $3: Parallel jobs (workers)
# $4: URL timeout

URLS_FILE=$1
OUT_FILE=$2
WORKERS=$3
TIMEOUT=$4

if command -v dalfox &> /dev/null; then
    echo "[*] Running dalfox from PATH..."
    if [ -n "$COOKIE" ]; then
        dalfox file "$URLS_FILE" -o "$OUT_FILE" --worker "$WORKERS" --timeout "$TIMEOUT" --cookie "$COOKIE"
    else
        dalfox file "$URLS_FILE" -o "$OUT_FILE" --worker "$WORKERS" --timeout "$TIMEOUT"
    fi
else
    echo "[-] dalfox command not found. Falling back to SMART-HUNTER built-in advanced payload scanner."
    # We exit gracefully so that the python script doesn't crash, it just won't find dalfox results.
    exit 0
fi
