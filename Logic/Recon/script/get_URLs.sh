#!/bin/bash
# get_URLs.sh
# Usage: ./get_URLs.sh <url> [timeout]

TARGET=$1
TIMEOUT=$2

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <url> [timeout]"
    exit 1
fi

echo "[*] Discovering URLs for $TARGET..."

# Using waybackurls for discovery
if command -v waybackurls &> /dev/null; then
    echo "[*] Running waybackurls..."
    echo "$TARGET" | waybackurls
else
    # Fallback to simple curl if waybackurls is missing
    echo "[!] waybackurls not found, using basic curl extraction (limited)..."
    curl -s "$TARGET" | grep -oE "https?://[a-zA-Z0-9./?=_-]+" | sort -u
fi

echo "[+] Discovery complete."
