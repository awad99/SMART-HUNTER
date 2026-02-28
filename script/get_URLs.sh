#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Error: No URL provided"
    echo "Usage: $0 <target_url>"
    exit 1
fi

TARGET_URL="$1"

CLEAN_DOMAIN=$(echo "$TARGET_URL" | sed 's|https://||g; s|http://||g; s|www\.||g' | cut -d'/' -f1)

# Just collect URLs without validation
{
    echo "$TARGET_URL" | waybackurls
    mkdir -p results
    paramspider --domain "$CLEAN_DOMAIN" 2>/dev/null | grep -E '^http'
} | sort -u > "discovered_urls.txt"

echo "[+] URLs saved to discovered_urls.txt"
cat "discovered_urls.txt"