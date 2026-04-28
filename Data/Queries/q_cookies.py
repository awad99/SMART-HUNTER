"""
q_cookies.py — Queries for the `cookies` table
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = """
    INSERT INTO cookies (scan_id, url, name, value, domain, secure, http_only, same_site, expires)
    VALUES %s
"""

# ────────────────────────── Functions ──────────────────────────
def save_cookies(db, scan_id, url, cookies_list):
    """
    حفظ قائمة cookies.
    يُعيد عدد السجلات المحفوظة.

    مثال:
        from Data.Queries.q_cookies import save_cookies
        save_cookies(self.db, self.scan_id, url, cookies_list)
    """
    if not cookies_list:
        return 0
    data = []
    for c in cookies_list:
        data.append((
            scan_id, url,
            c.get('name'), c.get('value'), c.get('domain'),
            bool(c.get('secure', False)),
            bool(c.get('http_only', False)),
            c.get('same_site', 'Lax'),
            None,   # expires — يمكن إضافتها لاحقاً
        ))
    if not data:
        return 0
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)
