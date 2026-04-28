"""
q_payloads.py — Queries for the `payloads` table
"""
import json

# ────────────────────────── SQL ──────────────────────────
_INSERT_PAYLOAD = """
    INSERT INTO scanning_payloads (category, filename, content, raw_content)
    VALUES (%s, %s, %s, %s)
    RETURNING id
"""

_GET_PAYLOADS = """
    SELECT id, category, filename, content, raw_content
    FROM scanning_payloads
    WHERE category = %s
"""

_DELETE_BY_CATEGORY = """
    DELETE FROM scanning_payloads
    WHERE category = %s
"""

# ────────────────────────── Functions ──────────────────────────
def save_payload(db, category, filename, content=None, raw_content=None):
    """
    Saves a single payload file content to the database.
    """
    content_json = json.dumps(content) if content is not None else None
    res = db._execute(_INSERT_PAYLOAD, (category, filename, content_json, raw_content))
    return res[0] if res else None

def get_payloads_by_category(db, category):
    """
    Retrieves all payloads for a specific category.
    Returns a list of dictionaries.
    """
    rows = db._execute_all(_GET_PAYLOADS, (category,))
    results = []
    for row in rows:
        results.append({
            'id': row[0],
            'category': row[1],
            'filename': row[2],
            'content': row[3] if row[3] else None,
            'raw_content': row[4]
        })
    return results

def clear_payloads_by_category(db, category):
    """
    Deletes all payloads for a specific category (useful for re-importing).
    """
    db._execute(_DELETE_BY_CATEGORY, (category,))
