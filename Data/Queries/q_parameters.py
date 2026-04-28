"""
q_parameters.py — Queries for the `discovery_parameters` table
"""

# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = """
    INSERT INTO discovery_parameters (scan_id, url, parameter, method, source, raw_line)
    VALUES %s
"""

_GET_FOR_SCAN = """
    SELECT url, parameter, method, source, raw_line
    FROM discovery_parameters
    WHERE scan_id = %s
"""

# ────────────────────────── Functions ──────────────────────────
def save_discovered_parameters(db, scan_id, params_list, source='recon'):
    """
    Saves a batch of discovered parameters.
    params_list: list of dicts with keys: url, parameter, method, raw_line
    """
    if not params_list:
        return 0
    
    data = [
        (scan_id, p.get('url'), p.get('parameter'), p.get('method', 'GET'), source, p.get('raw_line'))
        for p in params_list if p
    ]
    
    if not data:
        return 0
        
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)

def get_parameters_for_scan(db, scan_id):
    """
    Retrieves all parameters discovered for a specific scan.
    """
    rows = db._execute_all(_GET_FOR_SCAN, (scan_id,))
    results = []
    for row in rows:
        results.append({
            'url': row[0],
            'parameter': row[1],
            'method': row[2],
            'source': row[3],
            'raw_line': row[4]
        })
    return results
