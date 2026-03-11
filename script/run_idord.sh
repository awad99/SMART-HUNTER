#!/bin/bash
# run_idord.sh
# Usage: ./run_idord.sh <url>
TARGET_URL=$1

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
IDORD_WRAPPER="$DIR/../vulnerability_scan/IDORD/Wrapper/IDORD.py"

if [ -f "$IDORD_WRAPPER" ]; then
    python3 "$IDORD_WRAPPER" "$TARGET_URL"
else
    echo "IDORD wrapper not found at $IDORD_WRAPPER"
fi
