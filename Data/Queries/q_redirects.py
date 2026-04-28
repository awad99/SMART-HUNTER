"""
q_redirects.py — Queries for the `redirect_chain` table
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_ONE = """
    INSERT INTO redirect_chain (scan_id, hop_number, url, status_code, location, hop_type)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT (scan_id, hop_number) DO NOTHING;
"""

# ────────────────────────── Functions ──────────────────────────
def save_redirect_hop(db, scan_id, hop_number, url, status_code, location, hop_type):
    """
    حفظ hop واحد في سلسلة الـ redirects.
    يُعيد 1 عند النجاح، 0 عند الفشل.

    مثال:
        from Data.Queries.q_redirects import save_redirect_hop
        save_redirect_hop(self.db, self.scan_id, 1, url, 301, loc, 'REDIRECT')
    """
    result = db._execute(_INSERT_ONE, (scan_id, hop_number, url, status_code, location, hop_type))
    return 1 if result is not None else 0
