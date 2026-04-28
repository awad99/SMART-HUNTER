#!/bin/bash
# Subdomain discovery using crt.sh
TARGET=$1
DOMAIN=$(echo $TARGET | sed -e 's|^[^/]*//||' -e 's|/.*$||')
if [[ -z "$DOMAIN" ]]; then DOMAIN=$TARGET; fi

echo "[*] Fetching subdomains for $DOMAIN from crt.sh..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | grep -oP '"name_value":"\K[^"]+' | sed 's/\*\.//g' | sort -u
