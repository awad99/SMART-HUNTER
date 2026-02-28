#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Error: No URL provided"
    echo "Usage: $0 <target_url>"
    exit 1
fi

TARGET_URL="$1"

echo "[*] Running findomain for: $TARGET_URL" 
findomain -t "$TARGET_URL" -q 

CLEAN_DOMAIN=$(echo "$TARGET_URL" | sed 's|https://||g; s|http://||g; s|www\.||g' | cut -d'/' -f1)

echo "[*] Running subfinder for: $CLEAN_DOMAIN"
subfinder -d "$CLEAN_DOMAIN" -silent

echo "[*] Running assetfinder for: $TARGET_URL" 
assetfinder --subs-only "$TARGET_URL"