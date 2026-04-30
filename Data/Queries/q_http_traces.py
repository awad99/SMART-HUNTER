_TRACE_COLUMNS = [
    "scan_id",
    "trace_id",
    "parent_trace_id",
    "source_module",
    "target_root",
    "page_url",
    "method",
    "scheme",
    "host",
    "port",
    "path",
    "route_template",
    "query_string_raw",
    "query_param_count",
    "body_content_type",
    "body_raw_truncated",
    "header_text_canonical",
    "cookie_names_only",
    "auth_context_type",
    "referer",
    "origin",
    "sec_fetch_dest",
    "user_agent_family",
    "status_code",
    "response_time_ms",
    "content_type",
    "body_title",
    "body_text_truncated",
    "body_hash",
    "response_size",
    "redirect_location",
    "cache_signals",
    "security_header_signals",
    "error_signatures_text",
]

_HEADER_INSERT = """
    INSERT INTO http_trace_headers
    (scan_id, trace_id, source_module, header_scope, header_name,
     header_value_masked_text, header_value_canonical_text, header_semantic_text, header_order)
    VALUES %s
"""


def save_http_trace(db, request_row, response_row):
    if not request_row:
        return 0
    merged = {}
    merged.update(request_row or {})
    merged.update(response_row or {})
    data = {key: merged.get(key) for key in _TRACE_COLUMNS if key in merged}
    if not data:
        return 0
    columns = ", ".join(data.keys())
    placeholders = ", ".join(["%s"] * len(data))
    query = f"INSERT INTO http_traces ({columns}) VALUES ({placeholders})"
    result = db._execute(query, tuple(data.values()))
    return 1 if result is not None else 0


def save_http_trace_headers(db, header_rows):
    if not header_rows:
        return 0
    data = []
    for row in header_rows:
        data.append(
            (
                row.get("scan_id"),
                row.get("trace_id"),
                row.get("source_module"),
                row.get("header_scope"),
                row.get("header_name"),
                row.get("header_value_masked_text"),
                row.get("header_value_canonical_text"),
                row.get("header_semantic_text"),
                row.get("header_order"),
            )
        )
    db._execute_batch(_HEADER_INSERT, data)
    return len(data)
