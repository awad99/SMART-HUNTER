#!/bin/bash
# run_PwnTraverse.sh
# Usage: ./run_PwnTraverse.sh <targets_file>
TARGETS_FILE=$1

# Ensure TARGETS_FILE is an absolute path
if [[ "$TARGETS_FILE" != /* ]] && [[ "$TARGETS_FILE" != ?:* ]]; then
    TARGETS_FILE="$(pwd)/$TARGETS_FILE"
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PWN_DIR="$DIR/../vulnerability_scan/PwnTraverse"

if [ -f "$PWN_DIR/exploit.py" ]; then
    echo "[*] Running PwnTraverse on targets in $TARGETS_FILE ..."
    cd "$PWN_DIR" || exit 1
    python3 "exploit.py" --file "$TARGETS_FILE"
else
    echo "[-] PwnTraverse exploit.py not found at $PWN_DIR/exploit.py"
fi
