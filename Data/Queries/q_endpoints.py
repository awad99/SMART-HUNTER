"""
q_endpoints.py — Queries for the `endpoints` table
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = """
    INSERT INTO endpoints (scan_id, url, discovered_from)
    VALUES %s
    ON CONFLICT DO NOTHING
"""

# ────────────────────────── Functions ──────────────────────────
def save_endpoints(db, scan_id, url, endpoints_list, source='crawler'):
    """
    حفظ endpoints مكتشفة.
    يُعيد عدد السجلات المحفوظة.

    مثال:
        from Data.Queries.q_endpoints import save_endpoints
        save_endpoints(self.db, self.scan_id, url, endpoints, source='form')
    """
    if not endpoints_list:
        return 0
    data = [(scan_id, ep, source) for ep in endpoints_list if ep]
    if not data:
        return 0
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)
