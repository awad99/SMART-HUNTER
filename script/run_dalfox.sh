#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 <urls_file> <output_file>"
    exit 1
fi

URLS_FILE="$1"
OUTPUT_FILE="$2"

echo "[*] Starting dalfox scan for URLs in: $URLS_FILE"
echo "[*] Output: $OUTPUT_FILE"

if ! command -v dalfox &> /dev/null; then
    echo "[-] dalfox not found. Please install it first."
    exit 1
fi

if [ ! -f "$URLS_FILE" ]; then
    echo "[-] URLs file not found: $URLS_FILE"
    exit 1
fi

echo "[*] Running deep DOM XSS scan..."
dalfox file "$URLS_FILE" \
    --format plain >> "$OUTPUT_FILE" 

dalfox sxss file "$URLS_FILE" \
    --format plain >> "$OUTPUT_FILE"
    
echo "[*] dalfox scan completed"

echo "" >> "$OUTPUT_FILE"
echo "=== XSSTRIKE SCAN ===" >> "$OUTPUT_FILE"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XSSTRIKE_DIR="$SCRIPT_DIR/../XSStrike"

if [ -d "$XSSTRIKE_DIR" ]; then
    cd "$XSSTRIKE_DIR"
    echo "[*] Running XSStrike with crawling in parallel..." | tee -a "$OUTPUT_FILE"
    grep -v '^$' "$URLS_FILE" | xargs -P 5 -I {} python3 xsstrike.py -u "{}" --crawl -l 3 >> "$OUTPUT_FILE" 2>&1 || true
    cd - > /dev/null
else
    echo "[-] XSStrike not found at $XSSTRIKE_DIR, skipping" | tee -a "$OUTPUT_FILE"
fi