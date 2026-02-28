#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Error: No URL provided"
    echo "Usage: $0 <target_url>"
    exit 1
fi

TARGET_URL="$1"

echo "[*] ULTRA-AGGRESSIVE Parameter Filtering"
echo "[*] Target: $TARGET_URL"

echo "[*] Step 1: Extreme URL filtering..."

cat discovered_urls.txt | grep -v -E \
    "\.(css|js|png|jpg|jpeg|gif|svg|woff|ttf|ico|pdf|xml|txt|mp4|mp3|avi|mov|zip|rar)$|\
    (robots|sitemap|humans|security)\.txt|\
    (cdn|static|assets|uploads|images|img|css|js|fonts|media|dist|build)/|\
    (google|facebook|twitter|linkedin|youtube|instagram|analytics|tracking|pixel)|\
    (doubleclick|googlesyndication|googleads|gstatic|facebook|fbcdn)|\
    (api|ajax|feed|rss|atom|json|xml|graphql)/|\
    \?(v|version|ver|cache|timestamp|t|time|_)=[0-9]|\
    (share|social|like|tweet|follow|subscribe)|\
    (calendar|date|time|month|day|year|schedule)|\
    \?(page|p|offset|limit|start|end)=[0-9]|\
    \?(sort|order|orderby|direction)=|\
    \?(lang|language|locale|region|country)=|\
    \?(theme|template|layout|style|color|font|size)=|\
    \?(view|display|mode|type|format|output)=" \
    | grep "?" > filtered_urls.txt

echo "[+] Raw URLs: $(wc -l < discovered_urls.txt)"
echo "[+] After basic filtering: $(wc -l < filtered_urls.txt)"

echo "[*] Step 2: Manual high-value parameter extraction..."

> high_value_xss.txt
> high_value_sqli.txt
> high_value_rce.txt

cat filtered_urls.txt | while read url; do
    echo "$url" | grep -o -E "(\?|&)[a-zA-Z_]{2,30}=" | sed 's/[?&]//g' | sed 's/=$//' | while read param; do
        # XSS - User input parameters
        if echo "$param" | grep -q -E -i "^(name|email|message|comment|title|subject|content|search|query|q|feedback|review|description)$"; then
            echo "$url" >> high_value_xss.txt
        fi
        
        # SQLi - Data/ID parameters  
        if echo "$param" | grep -q -E -i "^(id|user|username|account|customer|admin|uid|member|client|product|item|sku|order|cart|payment|transaction|invoice)$"; then
            echo "$url" >> high_value_sqli.txt
        fi
        
        # RCE - Execution parameters
        if echo "$param" | grep -q -E -i "^(cmd|command|exec|execute|run|system|shell|script|code|eval)$"; then
            echo "$url" >> high_value_rce.txt
        fi
    done
done

sort -u high_value_xss.txt -o high_value_xss.txt
sort -u high_value_sqli.txt -o high_value_sqli.txt  
sort -u high_value_rce.txt -o high_value_rce.txt

echo "[+] High-value XSS URLs: $(wc -l < high_value_xss.txt)"
echo "[+] High-value SQLi URLs: $(wc -l < high_value_sqli.txt)"
echo "[+] High-value RCE URLs: $(wc -l < high_value_rce.txt)"

# Step 3: Run gf only on high-value URLs
echo "[*] Step 3: Running gf on high-value URLs only..."

if [ -s high_value_xss.txt ]; then
    gf xss high_value_xss.txt > xss_parameters.txt
else
    > xss_parameters.txt
fi

if [ -s high_value_sqli.txt ]; then
    gf sqli high_value_sqli.txt > sqli_parameters.txt
else
    > sqli_parameters.txt
fi

if [ -s high_value_rce.txt ]; then
    gf rce high_value_rce.txt > rce_parameters.txt
else
    > rce_parameters.txt
fi

# Step 4: Final results
XSS_COUNT=$(wc -l < xss_parameters.txt 2>/dev/null || echo 0)
SQLI_COUNT=$(wc -l < sqli_parameters.txt 2>/dev/null || echo 0)
RCE_COUNT=$(wc -l < rce_parameters.txt 2>/dev/null || echo 0)

echo ""
echo "[*] ULTRA-FILTERED RESULTS:"
echo "    ======================="
echo "    XSS parameters: $XSS_COUNT "
echo "    SQLi parameters: $SQLI_COUNT" 
echo "    RCE parameters: $RCE_COUNT"
echo ""

# Show samples
if [ $XSS_COUNT -gt 0 ]; then
    echo "[*] Sample XSS parameters:"
    head -3 xss_parameters.txt | sed 's/^/    /'
fi

if [ $SQLI_COUNT -gt 0 ]; then
    echo "[*] Sample SQLi parameters:"
    head -3 sqli_parameters.txt | sed 's/^/    /'
fi

# Cleanup
rm -f filtered_urls.txt high_value_*.txt