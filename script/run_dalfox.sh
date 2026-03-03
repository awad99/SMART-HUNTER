#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  run_dalfox.sh  –  Fast parallel XSS scanning with dalfox
#
#  Usage:
#    ./run_dalfox.sh <urls_file> <output_file> [parallel_jobs] [timeout_per_url]
#
#  Defaults:
#    parallel_jobs  = 5   (URLs scanned simultaneously)
#    timeout_per_url= 60  (seconds per URL before killing dalfox)
#
#  Each dalfox instance uses 10 internal workers, so effective concurrency
#  is  parallel_jobs × 10 goroutines.
# ─────────────────────────────────────────────────────────────────────────────

if [ $# -lt 2 ]; then
    echo "Usage: $0 <urls_file> <output_file> [parallel_jobs=5] [timeout_per_url=60]"
    exit 1
fi

URLS_FILE="$1"
OUTPUT_FILE="$2"
PARALLEL_JOBS="${3:-5}"
URL_TIMEOUT="${4:-60}"
DALFOX_WORKERS=10     # goroutines inside each dalfox process

# ── Pre-flight checks ────────────────────────────────────────────────────────
if ! command -v dalfox &>/dev/null; then
    echo "[-] dalfox not found."
    echo "    Install: go install github.com/hahwul/dalfox/v2@latest"
    exit 1
fi

if [ ! -f "$URLS_FILE" ]; then
    echo "[-] URLs file not found: $URLS_FILE"
    exit 1
fi

TOTAL=$(grep -vc '^$' "$URLS_FILE" 2>/dev/null || echo 0)
if [ "$TOTAL" -eq 0 ]; then
    echo "[-] No URLs in $URLS_FILE"
    exit 1
fi

echo "[*] Starting dalfox XSS scan"
echo "[*] URLs    : $TOTAL"
echo "[*] Parallel: $PARALLEL_JOBS job(s) × $DALFOX_WORKERS workers each"
echo "[*] Timeout : ${URL_TIMEOUT}s per URL"
echo "[*] Output  : $OUTPUT_FILE"
echo ""

# ── Output file header ───────────────────────────────────────────────────────
{
    echo "=== DALFOX XSS SCAN RESULTS ==="
    echo "Date    : $(date)"
    echo "URLs    : $TOTAL"
    echo "Config  : parallel=$PARALLEL_JOBS  workers=$DALFOX_WORKERS  timeout=${URL_TIMEOUT}s"
    echo "=================================================="
} > "$OUTPUT_FILE"

# ── Temp dir for per-URL results ─────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# ── Scan one URL (called by xargs) ───────────────────────────────────────────
scan_url() {
    local url="$1"
    local idx="$2"
    local total="$3"
    local out_tmp="${TMP_DIR}/result_${idx}.txt"

    echo "[${idx}/${total}] Scanning: $url"

    # --silence    = suppress info/debug lines, only show findings
    # --no-color   = clean plain-text output
    # --skip-headless = skip Chrome/headless (much faster, still catches reflected XSS)
    # --worker     = internal goroutine count
    # --timeout    = per-request HTTP timeout (seconds)
    # --follow-redirects = follow 302s automatically
    timeout "$URL_TIMEOUT" dalfox url "$url" \
        --worker "$DALFOX_WORKERS" \
        --timeout 10 \
        --silence \
        --no-color \
        --format plain \
        --skip-headless \
        --follow-redirects \
        2>/dev/null \
    | tee "$out_tmp"

    local found
    found=$(grep -c '^\[POC\]' "$out_tmp" 2>/dev/null || echo 0)
    if [ "$found" -gt 0 ]; then
        echo "[!] VULNERABLE  ($found POC)  $url"
    else
        echo "[-] Clean       $url"
    fi
}

export -f scan_url
export TMP_DIR URL_TIMEOUT DALFOX_WORKERS

# ── Parallel execution via xargs ─────────────────────────────────────────────
START_TIME=$(date +%s)

# Number every non-blank URL then pass as "url idx total" triples to xargs
grep -v '^$' "$URLS_FILE" | \
    awk -v total="$TOTAL" '{print $0, NR, total}' | \
    xargs -P "$PARALLEL_JOBS" -L 1 bash -c '
        url="$1"; idx="$2"; total="$3"
        scan_url "$url" "$idx" "$total"
    ' _

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# ── Merge findings into output file ──────────────────────────────────────────
{
    echo ""
    echo "=== VULNERABILITY FINDINGS (POC) ==="
} >> "$OUTPUT_FILE"

VULN_COUNT=0
for f in "$TMP_DIR"/result_*.txt; do
    [ -f "$f" ] || continue
    poc=$(grep '^\[POC\]' "$f" 2>/dev/null || true)
    if [ -n "$poc" ]; then
        echo "$poc" >> "$OUTPUT_FILE"
        count=$(echo "$poc" | wc -l)
        VULN_COUNT=$((VULN_COUNT + count))
    fi
done

{
    echo ""
    echo "=== ALL ALERTS (POC + Verified + Info) ==="
    cat "$TMP_DIR"/result_*.txt 2>/dev/null \
        | grep -E '^\[(POC|V|G)\]' || echo "(none)"
    echo ""
    echo "=================================================="
    echo "Scan finished in ${ELAPSED}s"
    echo "URLs scanned : $TOTAL"
    echo "XSS POC found: $VULN_COUNT"
    echo "=================================================="
} >> "$OUTPUT_FILE"

echo ""
echo "=========================================="
echo "[*] Scan complete in ${ELAPSED}s"
echo "[*] URLs scanned : $TOTAL"
echo "[*] XSS found    : $VULN_COUNT"
echo "[*] Results      : $OUTPUT_FILE"
echo "=========================================="

# ── Optional: XSStrike (only if installed) ───────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XSSTRIKE_DIR="$SCRIPT_DIR/../XSStrike"

if [ -d "$XSSTRIKE_DIR" ]; then
    echo ""
    echo "[*] Running XSStrike in parallel..."
    echo "=== XSSTRIKE SCAN ===" >> "$OUTPUT_FILE"
    cd "$XSSTRIKE_DIR"
    grep -v '^$' "$URLS_FILE" | \
        xargs -P "$PARALLEL_JOBS" -I {} \
        timeout 90 python3 xsstrike.py -u "{}" --crawl -l 2 \
        >> "$OUTPUT_FILE" 2>&1 || true
    cd - > /dev/null
    echo "[*] XSStrike done"
else
    echo "[-] XSStrike not found at $XSSTRIKE_DIR — skipping"
    echo "[-] XSStrike not found — skipped" >> "$OUTPUT_FILE"
fi