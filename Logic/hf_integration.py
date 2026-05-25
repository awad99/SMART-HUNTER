"""
hf_integration.py â€” SMART-HUNTER Cloud Integration Module
Handles:
  1. Smart-Cache asset syncing (Payloads, Wordlists, etc.) from HF
  2. Background uploading of local CSV datasets to the HF Proxy
"""

import os
import json
import hashlib
import platform
import requests
import threading
from pathlib import Path
from datetime import datetime, timezone
from queue import Queue

# â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# IMPORTANT: The user provided this space link in their request
PROXY_BASE_URL  = "https://smart-hunter-smarthunter-proxy.hf.space"
UPLOAD_URL      = f"{PROXY_BASE_URL}/upload_scan"
HF_DATASET_ID   = "Smart-Hunter/SMART-HUNTER-DATA"

BASE_DIR  = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR  = BASE_DIR / "Data"
CACHE_META_FILE = DATA_DIR / ".hf_cache_metadata.json"

# Queue for background uploads to avoid blocking the scanner
upload_queue = Queue()

# â”€â”€ Anonymous User Fingerprint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _get_user_fingerprint() -> str:
    try:
        node = str(platform.node())
        system = platform.system()
        machine = platform.machine()
        raw = f"{node}|{system}|{machine}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    except Exception:
        return "anonymous"

USER_FINGERPRINT = _get_user_fingerprint()

# â”€â”€ Asset Synchronization (The "Pull") â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _get_hf_last_modified(filename: str, category: str) -> str | None:
    url = f"{PROXY_BASE_URL}/check_payload_version"
    try:
        params = {"filename": filename, "category": category}
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("last_modified")
    except Exception:
        pass
    return None

def sync_assets():
    """
    Synchronizes all critical assets (Payloads, Wordlists, Parameters)
    at the start of the application.
    """
    print(f"\n{'='*60}")
    print(f"[*] Starting Cloud Asset Synchronization...")
    
    assets_to_sync = {
        "Payloads": ["xss.txt", "sqli.txt", "rce.txt", "lfi.txt"], # Example filenames
        "Wordlists": ["common.txt", "admin.txt"],
        "Parameters": ["params.txt"]
    }
    
    for category, files in assets_to_sync.items():
        for filename in files:
            _smart_download(filename, category)
    
    print(f"[*] Cloud Sync Complete.")
    print(f"{'='*60}\n")

def _smart_download(filename: str, category: str):
    category_dir = DATA_DIR / category
    local_path = category_dir / filename
    
    # Load cache
    cache_meta = {}
    if CACHE_META_FILE.exists():
        try:
            with open(CACHE_META_FILE, "r") as f:
                cache_meta = json.load(f)
        except: pass
    
    cache_key = f"{category}/{filename}"
    
    try:
        hf_date = _get_hf_last_modified(filename, category)
        local_date = cache_meta.get(cache_key, "")
        
        if local_path.exists() and hf_date == local_date and hf_date is not None:
            return # Up to date
            
        # Download
        url = f"{PROXY_BASE_URL}/download_payload"
        params = {"filename": filename, "category": category}
        resp = requests.get(url, params=params, timeout=30, stream=True)
        
        if resp.status_code == 200:
            category_dir.mkdir(parents=True, exist_ok=True)
            with open(local_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Update cache
            cache_meta[cache_key] = hf_date or datetime.now(timezone.utc).isoformat()
            with open(CACHE_META_FILE, "w") as f:
                json.dump(cache_meta, f, indent=2)
            print(f"  [+] Updated asset: {category}/{filename}")
    except Exception as e:
        print(f"  [-] Failed to sync {filename}: {e}")

# â”€â”€ Cloud Mirroring (The "Push") â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def upload_data_to_cloud(relative_path: str, filename: str, records: list[dict], scan_id: str = "unknown"):
    """
    Queues data for background upload to the HF Proxy.
    This mimics the local directory structure in the cloud.
    """
    if not records:
        return

    # Enrich records with user fingerprint and timestamp
    enriched_records = []
    for r in records:
        # Create a copy to avoid modifying original data
        record_copy = dict(r)
        record_copy["user_fingerprint"] = USER_FINGERPRINT
        if "scan_id" not in record_copy:
            record_copy["scan_id"] = scan_id
        enriched_records.append(record_copy)

    # Put in queue for worker thread
    upload_queue.put({
        "path": relative_path,
        "filename": filename,
        "records": enriched_records,
        "scan_id": scan_id
    })
    
    # Ensure worker is running
    _ensure_worker_running()

_worker_thread = None
def _ensure_worker_running():
    global _worker_thread
    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(target=_upload_worker, daemon=True)
        _worker_thread.start()

def _upload_worker():
    """Background thread that handles the HTTP POST requests."""
    while True:
        task = upload_queue.get()
        if task is None: break
        
        try:
            payload = {
                "relative_path": task["path"],
                "filename": task["filename"],
                "records": task["records"],
                "scan_id": task["scan_id"]
            }
            # Send to proxy
            resp = requests.post(UPLOAD_URL, json=payload, timeout=20)
            if resp.status_code != 200:
                # We don't want to spam the console during scan, so we log only serious errors
                # print(f"  [!] Cloud upload failed for {task['filename']}: {resp.status_code}")
                pass
        except Exception:
            pass # Silent failure for background sync
        finally:
            upload_queue.task_done()

# â”€â”€ Helper to determine relative path from absolute â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def sync_local_file_to_cloud(local_file_path: str, scan_id: str = "unknown"):
    """
    Helper function to automatically determine the relative path of a file 
    under Data/Datasets and trigger an upload.
    """
    try:
        path = Path(local_file_path).resolve()
        datasets_root = (DATA_DIR / "Datasets").resolve()
        
        if datasets_root in path.parents or path == datasets_root:
            rel_path = path.relative_to(datasets_root).parent
            filename = path.name
            
            # Read the last record if possible (for real-time mirroring)
            # Or read everything if it's the first time.
            # For simplicity, we assume the caller provides the records to upload.
            pass
    except:
        pass

