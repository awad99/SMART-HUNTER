"""
q_forms.py — Queries for the `forms` table
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_BATCH = """
    INSERT INTO forms (scan_id, url, action, method, inputs, has_password, has_file, has_hidden)
    VALUES %s
    ON CONFLICT DO NOTHING
"""

# ────────────────────────── Functions ──────────────────────────
def save_forms(db, scan_id, url, forms_list):
    """
    حفظ forms مكتشفة.
    يُعيد عدد السجلات المحفوظة.

    مثال:
        from Data.Queries.q_forms import save_forms
        save_forms(self.db, self.scan_id, url, forms_list)
    """
    if not forms_list:
        return 0
    data = []
    for f in forms_list:
        inputs = f.get('inputs', [])
        data.append((
            scan_id, url,
            f.get('action'),
            f.get('method', 'GET'),
            inputs,
            any('pass' in str(i).lower() for i in inputs),
            any('file' in str(i).lower() for i in inputs),
            any('hidden' in str(i).lower() for i in inputs),
        ))
    if not data:
        return 0
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)
