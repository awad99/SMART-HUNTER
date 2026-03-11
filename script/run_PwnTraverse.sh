#!/bin/bash
# run_PwnTraverse.sh
# Usage: ./run_PwnTraverse.sh <targets_file>
TARGETS_FILE=$1

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PWN_DIR="$DIR/../vulnerability_scan/PwnTraverse"

if [ -f "$PWN_DIR/exploit.py" ]; then
    echo "[*] Running PwnTraverse on targets in $TARGETS_FILE ..."
    python3 "$PWN_DIR/exploit.py" --file "$TARGETS_FILE"
else
    echo "[-] PwnTraverse exploit.py not found at $PWN_DIR/exploit.py"
fi
