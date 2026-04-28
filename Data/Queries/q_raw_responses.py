"""
q_raw_responses.py — Queries for the `raw_responses` table
"""
import json as _json

# ────────────────────────── SQL ──────────────────────────
_INSERT_ONE = """
    INSERT INTO raw_responses (scan_id, url, status_code, response_body, response_headers)
    VALUES (%s, %s, %s, %s, %s)
"""

# ────────────────────────── Functions ──────────────────────────
def save_raw_response(db, scan_id, url, status_code, body, headers):
    """
    حفظ الاستجابة الخام مع تنظيف null bytes التي يرفضها PostgreSQL.
    يُعيد 1 عند النجاح، 0 عند الفشل.

    مثال:
        from Data.Queries.q_raw_responses import save_raw_response
        save_raw_response(self.db, self.scan_id, url, resp.status_code, resp.text, resp.headers)
    """
    # تنظيف null bytes
    clean_body = (body or '').replace('\x00', '')[:500_000]   # حد 500 KB
    try:
        clean_headers = _json.dumps({str(k): str(v) for k, v in dict(headers).items()})
    except Exception:
        clean_headers = '{}'

    result = db._execute(_INSERT_ONE, (scan_id, url, status_code, clean_body, clean_headers))
    return 1 if result is not None else 0
