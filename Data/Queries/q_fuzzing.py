"""
q_fuzzing.py — Queries for the `fuzzing_results` table
"""
import urllib.parse as _up

# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = """
    INSERT INTO fuzzing_results (scan_id, target_url, discovered_path, status_code, response_size)
    VALUES %s
"""

# ────────────────────────── Functions ──────────────────────────
def save_fuzz_results(db, scan_id, results_list):
    """
    حفظ نتائج ffuf في جدول fuzzing_results.
    يُعيد عدد السجلات المحفوظة.

    مثال:
        from Data.Queries.q_fuzzing import save_fuzz_results
        n = save_fuzz_results(self.db, self.scan_id, fuzzing['raw'])
    """
    if not results_list:
        return 0
    data = [
        (
            scan_id,
            r.get('url'),
            _up.urlparse(r.get('url', '')).path or '/',
            r.get('status'),
            r.get('length'),
        )
        for r in results_list
    ]
    if not data:
        return 0
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)
