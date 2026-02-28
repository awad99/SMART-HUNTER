#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Error: No URL provided"
    echo "Usage: $0 <target_url> [output_dir]"
    exit 1
fi

TARGET_URL="$1"
SCAN_DIR="${2:-web_recon_dataset/sqlmap_scan_$(date +%Y%m%d_%H%M%S)}"
LOG_FILE="$SCAN_DIR/sqlmap.log"

echo "[*] Starting SQLMap scan for: $TARGET_URL"
echo "[*] Scan directory: $SCAN_DIR"
echo "[*] Log file: $LOG_FILE"

mkdir -p "$SCAN_DIR"

if [ -f "$TARGET_URL" ]; then
    TARGET_ARG="-m \"$TARGET_URL\""
else
    TARGET_ARG="-u \"$TARGET_URL\""
fi

# Run SQLMap — all output goes to a single log file (no --output-dir to avoid per-target subfolders)
eval sqlmap $TARGET_ARG \
    --batch \
    --forms \
    --crawl=1 \
    --level=1 \
    --risk=1 \
    --threads=10 \
    --timeout=10 \
    --retries=1 \
    --time-sec=2 \
    --smart \
    --random-agent \
    2>&1 | tee -a "$LOG_FILE"

# Quick summary
echo ""
echo "[*] Scan Summary:"
VULN_COUNT=$(grep -ci "is vulnerable\|injection point" "$LOG_FILE" 2>/dev/null || echo "0")
FALSE_POS=$(grep -ci "false positive" "$LOG_FILE" 2>/dev/null || echo "0")
REAL_VULNS=$((VULN_COUNT - FALSE_POS))

if [ $REAL_VULNS -gt 0 ]; then
    echo "[!] VULNERABLE - Found $REAL_VULNS SQL injection(s)"
    grep -i "Parameter:" "$LOG_FILE" | head -5
    exit 0
else
    echo "[-] No vulnerabilities found"
    exit 1
fi