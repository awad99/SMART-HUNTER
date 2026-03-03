#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 <url> <output_dir>"
    exit 1
fi

TARGET_URL="$1"
OUTPUT_DIR="$2"

echo "[*] Starting Commix scan"
echo "[*] Target URL: $TARGET_URL"
echo "[*] Output directory: $OUTPUT_DIR"

if [ -d "$OUTPUT_DIR" ]; then
    echo "[!] Removing existing directory/file: $OUTPUT_DIR"
    rm -rf "$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR"

echo "Testing: ${TARGET_URL:0:60}..."
    
# Run Commix with improved parameters for better speed and detection
commix --url "$TARGET_URL" \
    --batch \
    --random-agent \
    --smart \
    --timeout=5 \
    --output-dir="$OUTPUT_DIR" \
    2>&1 | grep -i "vulnerable\|injection\|exploit\|error\|critical" || echo "    [-] No issues detected"
    
# Check results
VULN_FOUND=0
if [ -f "$OUTPUT_DIR/target.txt" ] && [ -s "$OUTPUT_DIR/target.txt" ] || [ -d "$OUTPUT_DIR/host" ]; then
    echo "    [!] VULNERABLE - Results in: $OUTPUT_DIR/"
    VULN_FOUND=1
else
    rmdir "$OUTPUT_DIR" 2>/dev/null
fi
    
echo ""
echo "[*] Commix scan complete"

[ $VULN_FOUND -gt 0 ] && exit 0 || exit 1