_LABEL_COLUMNS = [
    "scan_id",
    "trace_id",
    "parent_trace_id",
    "baseline_trace_id",
    "source_module",
    "label_target_value",
    "label_candidate_family",
    "label_confirmed_family",
    "label_source",
    "label_confidence",
    "human_reviewed",
    "validation_tool",
    "analyzer_route",
    "analyzer_reason",
]


def save_http_trace_label(db, label_row):
    if not label_row:
        return 0
    data = {key: label_row.get(key) for key in _LABEL_COLUMNS if key in label_row}
    if not data:
        return 0
    columns = ", ".join(data.keys())
    placeholders = ", ".join(["%s"] * len(data))
    query = f"INSERT INTO http_trace_labels ({columns}) VALUES ({placeholders})"
    result = db._execute(query, tuple(data.values()))
    return 1 if result is not None else 0
