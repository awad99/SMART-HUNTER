#!/bin/bash
# get_URLs.sh
# Usage: ./get_URLs.sh <url> <out_file> <timeout>

TARGET=$1
OUT_FILE=$2
TIMEOUT=$3

if [[ -z "$TARGET" || -z "$OUT_FILE" ]]; then
    echo "Usage: $0 <url> <out_file> [timeout]"
    exit 1
fi

echo "[*] Discovering URLs for $TARGET..."

# Ensure directory exists
mkdir -p "$(dirname "$OUT_FILE")"

# Using waybackurls for discovery
if command -v waybackurls &> /dev/null; then
    echo "[*] Running waybackurls..."
    echo "$TARGET" | waybackurls > "$OUT_FILE"
else
    # Fallback to simple curl if waybackurls is missing
    echo "[!] waybackurls not found, using basic curl extraction (limited)..."
    curl -s "$TARGET" | grep -oE "https?://[a-zA-Z0-9./?=_-]+" | sort -u > "$OUT_FILE"
fi

echo "[+] Discovery complete. Results saved to $OUT_FILE"
