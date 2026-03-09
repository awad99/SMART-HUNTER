#!/bin/bash
# Parameter discovery (simplified version fetching from web sources)
TARGET=$1
DOMAIN=$(echo $TARGET | sed -e 's|^[^/]*//||' -e 's|/.*$||')
if [[ -z "$DOMAIN" ]]; then DOMAIN=$TARGET; fi

echo "[*] Fetching parameters for $DOMAIN..."
# Using commoncrawl/wayback to find URLs with parameters
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey" | grep "\?" | head -n 100
