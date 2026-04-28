"""
q_vulnerabilities.py — Queries for the `vulnerabilities` table
يُستدعى مباشرة من scan files:
    from Data.Queries.q_vulnerabilities import save_vulnerability
"""
# ────────────────────────── SQL ──────────────────────────
_INSERT_ONE = """
    INSERT INTO vulnerabilities
        (scan_id, url, vulnerability_type, parameter, payload, evidence, tool, confidence, method)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

_INSERT_BATCH = """
    INSERT INTO vulnerabilities
        (scan_id, url, vulnerability_type, parameter, payload, evidence, tool, confidence, method)
    VALUES %s
"""

# ────────────────────────── Functions ──────────────────────────
def save_vulnerability(db, scan_id, vuln_dict):
    """
    حفظ ثغرة واحدة في قاعدة البيانات.
    يُعيد 1 عند النجاح، 0 عند الفشل.

    مثال على الاستخدام:
        from Data.Queries.q_vulnerabilities import save_vulnerability
        save_vulnerability(self.db, self.scan_id, {
            'url': url, 'type': 'SQL Injection (UNION)', 'parameter': 'id',
            'payload': "' UNION ...", 'evidence': '...', 'tool': 'builtin_sqli',
            'confidence': 'high', 'method': 'GET'
        })
    """
    result = db._execute(_INSERT_ONE, (
        scan_id,
        vuln_dict.get('url'),
        vuln_dict.get('type'),
        vuln_dict.get('parameter'),
        vuln_dict.get('payload'),
        vuln_dict.get('evidence'),
        vuln_dict.get('tool'),
        vuln_dict.get('confidence'),
        vuln_dict.get('method'),
    ))
    return 1 if result is not None else 0


def save_vulnerabilities_batch(db, scan_id, vulns_list):
    """
    حفظ قائمة ثغرات دفعة واحدة (أسرع).
    يُعيد عدد السجلات المحفوظة.

    مثال على الاستخدام:
        from Data.Queries.q_vulnerabilities import save_vulnerabilities_batch
        save_vulnerabilities_batch(self.db, self.scan_id, self.vulnerabilities_found)
    """
    if not vulns_list:
        return 0
    data = []
    for v in vulns_list:
        data.append((
            scan_id,
            v.get('url'),
            v.get('type'),
            v.get('parameter'),
            v.get('payload'),
            v.get('evidence'),
            v.get('tool'),
            v.get('confidence'),
            v.get('method'),
        ))
    if not data:
        return 0
    db._execute_batch(_INSERT_BATCH, data)
    return len(data)
