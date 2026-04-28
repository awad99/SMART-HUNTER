"""
q_scans.py — Queries for the `scans` table
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_SCAN = """
    INSERT INTO scans (scan_id, original_url, user_agent, cookie_used, proxy_used, status, start_time)
    VALUES (%s, %s, %s, %s, %s, 'running', NOW())
    ON CONFLICT (scan_id) DO NOTHING;
"""

_UPDATE_SCAN = """
    UPDATE scans
    SET status          = %s,
        final_url       = %s,
        has_waf         = %s,
        waf_vendors     = %s,
        security_grade  = %s,
        security_score  = %s,
        end_time        = NOW()
    WHERE scan_id = %s;
"""

_UPDATE_ORIGINAL_URL = """
    UPDATE scans SET original_url = %s WHERE scan_id = %s;
"""

# ────────────────────────── Functions ──────────────────────────
def create_scan(db, scan_id, original_url, user_agent=None, cookie=None, proxy=None):
    """
    إنشاء سجل فحص جديد في جدول scans.
    يُعيد True عند النجاح، None عند الفشل.
    """
    result = db._execute(_INSERT_SCAN, (scan_id, original_url, user_agent, cookie, proxy))
    return 1 if result is not None else 0


def update_scan_status(db, scan_id, status='completed', final_url=None,
                       has_waf=False, waf_vendors=None, grade=None, score=None):
    """
    تحديث حالة الفحص عند الانتهاء.
    يُعيد 1 عند النجاح، 0 عند الفشل.
    """
    result = db._execute(_UPDATE_SCAN, (status, final_url, has_waf, waf_vendors, grade, score, scan_id))
    return 1 if result is not None else 0


def update_scan_original_url(db, scan_id, original_url):
    """تحديث رابط الفحص الأصلي."""
    result = db._execute(_UPDATE_ORIGINAL_URL, (original_url, scan_id))
    return 1 if result is not None else 0
