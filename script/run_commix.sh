#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 <urls_file> <output_dir>"
    exit 1
fi

URLS_FILE="$1"
OUTPUT_DIR="$2"

echo "[*] Starting Commix scan"
echo "[*] URLs file: $URLS_FILE"
echo "[*] Output directory: $OUTPUT_DIR"

if [ ! -f "$URLS_FILE" ]; then
    echo "[-] Error: URL file not found: $URLS_FILE"
    exit 1
fi

if [ ! -s "$URLS_FILE" ]; then
    echo "[-] Error: URL file is empty"
    exit 1
fi

if [ -f "$OUTPUT_DIR" ]; then
    echo "[!] Removing existing file: $OUTPUT_DIR"
    rm "$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR"

URL_COUNT=$(wc -l < "$URLS_FILE" | tr -d ' ')
echo "[+] Testing $URL_COUNT URL(s)"

COUNTER=0
VULN_FOUND=0

while IFS= read -r url; do
    # Skip empty lines
    [ -z "$url" ] && continue
    
    ((COUNTER++))
    echo ""
    echo "[$COUNTER/$URL_COUNT] Testing: ${url:0:60}..."
    
    # Create unique output directory
    HASH=$(echo "$url" | md5sum | cut -d' ' -f1 | cut -c1-8)
    URL_OUTPUT_DIR="$OUTPUT_DIR/scan_$HASH"
    mkdir -p "$URL_OUTPUT_DIR"
    
    # Run Commix
    commix --url "$url" \
        --batch \
        --output-dir="$URL_OUTPUT_DIR" \
        2>&1 | grep -i "vulnerable\|injection\|exploit\|error" || echo "    [-] No issues detected"
    
    # Check results
    if [ -f "$URL_OUTPUT_DIR/target.txt" ] && [ -s "$URL_OUTPUT_DIR/target.txt" ]; then
        echo "    [!] VULNERABLE - Results in: $URL_OUTPUT_DIR/"
        ((VULN_FOUND++))
    else
        rmdir "$URL_OUTPUT_DIR" 2>/dev/null
    fi
    
done < "$URLS_FILE"

echo ""
echo "[*] Scan complete"
echo "[*] Vulnerabilities found: $VULN_FOUND"

[ $VULN_FOUND -gt 0 ] && exit 0 || exit 1