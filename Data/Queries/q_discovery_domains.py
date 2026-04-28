"""
q_discovery_domains.py — Queries for the `discovery_domains` table
"""

# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = """
    INSERT INTO discovery_domains (scan_id, domain_name, domain_type, source)
    VALUES %s
"""

_GET_FOR_SCAN = """
    SELECT domain_name, domain_type, source
    FROM discovery_domains
    WHERE scan_id = %s
"""

# ────────────────────────── Functions ──────────────────────────
def save_discovered_domains(db, scan_id, domains_list, source='recon'):
    """
    Saves a batch of discovered domains/URLs.
    domains_list: list of dicts with keys: domain_name, domain_type
    """
    if not domains_list:
        return 0
    
    data = [
        (scan_id, d.get('domain_name'), d.get('domain_type'), source)
        for d in domains_list if d
    ]
    
    if not data:
        return 0
        
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)

def get_domains_for_scan(db, scan_id):
    """
    Retrieves all domains discovered for a specific scan.
    """
    rows = db._execute_all(_GET_FOR_SCAN, (scan_id,))
    results = []
    for row in rows:
        results.append({
            'domain_name': row[0],
            'domain_type': row[1],
            'source': row[2]
        })
    return results
