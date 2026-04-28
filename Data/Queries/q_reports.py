"""
q_reports.py — Queries for the `scan_reports` table
"""

# ────────────────────────── SQL ──────────────────────────
_INSERT_REPORT = """
    INSERT INTO scan_reports (scan_id, report_type, content)
    VALUES (%s, %s, %s)
    RETURNING id;
"""

_GET_REPORTS_BY_SCAN = """
    SELECT report_type, content, timestamp FROM scan_reports WHERE scan_id = %s ORDER BY timestamp;
"""

# ────────────────────────── Functions ──────────────────────────
def save_report(db, scan_id, report_type, content):
    """
    حفظ تقرير نصي في قاعدة البيانات.
    """
    if not content:
        return None
        
    if not isinstance(content, str):
        import json
        content = json.dumps(content, indent=2)

    result = db._execute(_INSERT_REPORT, (scan_id, report_type, content))
    return result[0] if result else None


def get_scan_reports(db, scan_id):
    """
    استرجاع كافة التقارير الخاصة بفحص معين.
    """
    if not db.connect(): return []
    try:
        with db.conn.cursor() as cur:
            cur.execute(_GET_REPORTS_BY_SCAN, (scan_id,))
            return cur.fetchall()
    except Exception as e:
        print(f"[-] Error fetching reports: {e}")
        return []
