#!/usr/bin/env python3
import os
import re
import threading
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd


DATA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_SCAN_DIR = os.path.join(DATA_DIR, "Datasets", "Dataets_for_targetscan")

_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


def _safe_part(value, fallback="target", max_len=90):
    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._-")
    return (text or fallback)[:max_len]


def _target_name(target_url):
    parsed = urlparse(str(target_url or ""))
    base = parsed.netloc or parsed.path or "target"
    return _safe_part(base.replace(":", "_"), fallback="target")


def _lock_for(path):
    with _LOCKS_GUARD:
        if path not in _LOCKS:
            _LOCKS[path] = threading.Lock()
        return _LOCKS[path]


def get_target_scan_dataset_path(target_url, scan_id=None):
    target = _target_name(target_url)
    suffix = _safe_part(scan_id, fallback="", max_len=40)
    filename = f"{target}_{suffix}.csv" if suffix else f"{target}.csv"
    return os.path.join(TARGET_SCAN_DIR, filename)


def append_target_scan_row(features, target_url=None, scan_id=None, record_type="recon_page"):
    if not features:
        return None

    row = dict(features)
    effective_target = target_url or row.get("original_url") or row.get("target_root") or row.get("target_url") or ""
    effective_scan_id = scan_id or row.get("scan_id") or ""

    row.setdefault("scan_id", effective_scan_id)
    row.setdefault("target_root", effective_target)
    row.setdefault("page_url", row.get("target_url", ""))
    row.setdefault("dataset_record_type", record_type)
    row.setdefault("saved_at", datetime.now().isoformat())

    path = get_target_scan_dataset_path(effective_target, effective_scan_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    lock = _lock_for(path)
    with lock:
        file_exists = os.path.exists(path) and os.path.getsize(path) > 0
        if file_exists:
            columns = pd.read_csv(path, nrows=0).columns.tolist()
            new_columns = [col for col in row.keys() if col not in columns]
            if new_columns:
                existing = pd.read_csv(path)
                for col in new_columns:
                    existing[col] = 0
                columns = columns + new_columns
                existing.to_csv(path, index=False)
        else:
            columns = list(row.keys())

        out_row = {col: row.get(col, 0) for col in columns}
        pd.DataFrame([out_row], columns=columns).to_csv(
            path,
            mode="a",
            header=not file_exists,
            index=False,
        )

    return path
