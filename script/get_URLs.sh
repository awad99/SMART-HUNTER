#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  get_URLs.sh  –  Fast parallel URL discovery
#
#  Usage: ./get_URLs.sh <target_url> [output_file] [timeout_seconds]
#
#  Tools used (in parallel, each with its own timeout):
#    - waybackurls   : archived URLs from Wayback Machine
#    - gau           : GetAllURLs (faster alternative / extra source)
#    - paramspider   : parameter-bearing URLs from archived sources
#    - hakrawler     : live crawl of the target
#
#  Only installed tools are used; missing ones are skipped automatically.
# ─────────────────────────────────────────────────────────────────────────────

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_url> [output_file] [timeout=120]"
    exit 1
fi

TARGET_URL="$1"
OUTPUT_FILE="${2:-discovered_urls.txt}"
TIMEOUT="${3:-120}"   # max seconds to wait for each tool

# Strip scheme/www to get clean domain
CLEAN_DOMAIN=$(echo "$TARGET_URL" | sed 's|https://||g; s|http://||g; s|www\.||g' | cut -d'/' -f1)

echo "[*] URL discovery for: $TARGET_URL (domain: $CLEAN_DOMAIN)"
echo "[*] Timeout per tool : ${TIMEOUT}s"
echo "[*] Output file      : $OUTPUT_FILE"
echo ""

# ── Temp dir for parallel results ─────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

FOUND_ANY=0

# ── Run tools in parallel using background jobs ───────────────────────────────

# 1. waybackurls
if command -v waybackurls &>/dev/null; then
    (
        echo "[*] waybackurls starting..."
        count=$(echo "$TARGET_URL" | timeout "$TIMEOUT" waybackurls 2>/dev/null \
            | grep -E '^https?://' \
            | tee "$TMP_DIR/wayback.txt" \
            | wc -l)
        echo "[+] waybackurls: $count URLs"
    ) &
    PIDS="$! "
else
    echo "[-] waybackurls not found — skipping"
fi

# 2. gau (GetAllURLs) — faster, more sources
if command -v gau &>/dev/null; then
    (
        echo "[*] gau starting..."
        count=$(timeout "$TIMEOUT" gau --threads 5 --timeout 30 "$CLEAN_DOMAIN" 2>/dev/null \
            | grep -E '^https?://' \
            | tee "$TMP_DIR/gau.txt" \
            | wc -l)
        echo "[+] gau: $count URLs"
    ) &
    PIDS="$PIDS$! "
else
    echo "[-] gau not found — skipping (install: go install github.com/lc/gau/v2/cmd/gau@latest)"
fi

# 3. hakrawler — live crawl (depth 3, fast)
if command -v hakrawler &>/dev/null; then
    (
        echo "[*] hakrawler starting (live crawl)..."
        count=$(echo "$TARGET_URL" | timeout "$TIMEOUT" hakrawler -d 3 -t 20 -h 2>/dev/null \
            | grep -E '^https?://' \
            | tee "$TMP_DIR/hakrawler.txt" \
            | wc -l)
        echo "[+] hakrawler: $count URLs"
    ) &
    PIDS="$PIDS$! "
else
    echo "[-] hakrawler not found — skipping (install: go install github.com/hakluke/hakrawler@latest)"
fi

# 4. paramspider (slower — run with shorter timeout)
if command -v paramspider &>/dev/null; then
    SHORT_TIMEOUT=$(( TIMEOUT / 2 ))
    (
        echo "[*] paramspider starting (timeout=${SHORT_TIMEOUT}s)..."
        timeout "$SHORT_TIMEOUT" paramspider --domain "$CLEAN_DOMAIN" 2>/dev/null \
            | grep -E '^https?://' \
            | tee "$TMP_DIR/paramspider.txt" > /dev/null
        count=$(wc -l < "$TMP_DIR/paramspider.txt" 2>/dev/null || echo 0)
        echo "[+] paramspider: $count URLs"
    ) &
    PIDS="$PIDS$! "
else
    echo "[-] paramspider not found — skipping"
fi

# 5. Quick curl-based crawl as fallback (always available)
(
    echo "[*] curl crawl starting (fast, targets with params)..."
    {
        # Fetch the page and extract hrefs
        curl -sL --max-time 15 -A "Mozilla/5.0" "$TARGET_URL" 2>/dev/null \
        | grep -oE 'href="[^"]*"' \
        | sed 's/href="//; s/"//' \
        | grep -E '^https?://' \
        | grep -E '[?&][^=]+=.'   # only URLs with query params
        
        # Also try robots.txt for endpoint hints
        curl -sL --max-time 10 "$TARGET_URL/robots.txt" 2>/dev/null \
        | grep -E '^(Allow|Disallow):' \
        | awk '{print $2}' \
        | while read -r path; do
            [[ "$path" == *FUZZ* ]] && continue
            echo "${TARGET_URL%/}$path"
        done
    } | tee "$TMP_DIR/curl.txt" > /dev/null
    count=$(wc -l < "$TMP_DIR/curl.txt" 2>/dev/null || echo 0)
    echo "[+] curl crawl: $count URLs"
) &
PIDS="$PIDS$! "

# ── Wait for all background jobs ──────────────────────────────────────────────
echo ""
echo "[*] Waiting for all discovery tools to finish..."
for pid in $PIDS; do
    wait "$pid" 2>/dev/null || true
done

# ── Merge, deduplicate, save ──────────────────────────────────────────────────
echo ""
echo "[*] Merging results..."

TOTAL_RAW=0
for f in "$TMP_DIR"/*.txt; do
    [ -f "$f" ] || continue
    count=$(wc -l < "$f" 2>/dev/null || echo 0)
    TOTAL_RAW=$((TOTAL_RAW + count))
done

# Combine, filter only valid HTTP URLs, deduplicate, sort
cat "$TMP_DIR"/*.txt 2>/dev/null \
    | grep -E '^https?://[^ ]+' \
    | grep -v '\.js$\|\.css$\|\.png$\|\.jpg$\|\.gif$\|\.ico$\|\.svg$\|\.woff' \
    | sort -u \
    > "$OUTPUT_FILE"

UNIQUE=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)

echo ""
echo "=========================================="
echo "[*] Discovery complete"
echo "[*] Raw URLs found  : $TOTAL_RAW"
echo "[*] Unique kept     : $UNIQUE"
echo "[*] Saved to        : $OUTPUT_FILE"
echo "=========================================="
cat "$OUTPUT_FILE"