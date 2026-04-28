"""
q_headers.py — Queries for the `response_headers` table
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = "INSERT INTO response_headers (scan_id, url, status_code, header_name, header_value) VALUES %s"

# ────────────────────────── Functions ──────────────────────────
def save_headers(db, scan_id, url, status_code, headers_dict):
    """
    حفظ جميع headers كسجلات منفصلة.
    يُعيد عدد السجلات المحفوظة.

    مثال:
        from Data.Queries.q_headers import save_headers
        save_headers(self.db, self.scan_id, url, resp.status_code, dict(resp.headers))
    """
    if not headers_dict:
        return 0
    data = [(scan_id, url, status_code, str(k), str(v)) for k, v in headers_dict.items()]
    if not data:
        return 0
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)
