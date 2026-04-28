"""
q_subdomains.py — Queries for the `subdomains` table
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = """
    INSERT INTO subdomains (scan_id, subdomain, source, is_alive)
    VALUES %s
    ON CONFLICT (scan_id, subdomain) DO NOTHING
"""

# ────────────────────────── Functions ──────────────────────────
def save_subdomains(db, scan_id, subdomains_list, source='script'):
    """
    حفظ قائمة subdomains في قاعدة البيانات.
    يُعيد عدد السجلات المحفوظة.

    مثال:
        from Data.Queries.q_subdomains import save_subdomains
        n = save_subdomains(self.db, self.scan_id, subs_list)
    """
    if not subdomains_list:
        return 0
    data = [(scan_id, s, source, True) for s in subdomains_list if s]
    if not data:
        return 0
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)
