#!/bin/bash
# fuzzing_command_Tools.sh
# Usage: ./fuzzing_command_Tools.sh <base_url>

TARGET=$1

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <base_url>"
    exit 1
fi

# Wordlist path
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"

# Check if wordlist exists
if [[ ! -f "$WORDLIST" ]]; then
    echo "[-] Wordlist not found at $WORDLIST. Using a fallback list..."
    # Create a small fallback list if seclists is missing
    echo -e "admin\nlogin\napi\nconfig\ntest\n.env\n.git" > /tmp/fallback_wordlist.txt
    WORDLIST="/tmp/fallback_wordlist.txt"
fi

echo "[*] Fuzzing $TARGET with ffuf..."

# Run ffuf and save to json as expected by url_connection.py
ffuf -u "$TARGET/FUZZ" -w "$WORDLIST" -o ffuf_results.json -of json -t 50 -mc 200,204,301,302,307,401,403,405,500

echo "[*] ffuf scan complete. Results in ffuf_results.json"
