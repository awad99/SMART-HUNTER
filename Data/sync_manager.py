import os
import requests
import json
from pathlib import Path
from datetime import datetime

# Import sync function from Logic
try:
    from Logic.hf_integration import sync_scan_results_to_proxy, PROXY_URL
except ImportError:
    # Fallback if paths are not set yet (main.py sets them)
    PROXY_URL = "https://thehnx-smarthunter-proxy.hf.space/upload_scan"

def get_scan_results_dir():
    base_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return base_dir / "Data" / "Scan_Results"

def check_if_scan_exists_on_hf(scan_id):
    """
    Queries the HF Proxy to see if this scan_id is already in the global dataset.
    """
    check_url = PROXY_URL.replace("/upload_scan", "/check_scan_exists")
    try:
        response = requests.get(check_url, params={"scan_id": scan_id}, timeout=10)
        if response.status_code == 200:
            return response.json().get("exists", False)
    except Exception as e:
        print(f"    [!] Error connecting to proxy for check: {e}")
    return False

def check_and_sync_all():
    """
    Scans the local Data/Scan_Results directory for old scans,
    checks if they are missing from Hugging Face, and uploads them.
    """
    scan_dir = get_scan_results_dir()
    
    print("\n" + "="*60)
    print(" ًں›،ï¸ڈ  SMART-HUNTER: Legacy Data Scan & Sync System")
    print("="*60)
    print(f"[*] Scanning local directory: {scan_dir}")
    
    if not scan_dir.exists():
        print("[+] No legacy local data found. Directory does not exist.")
        print("="*60 + "\n")
        return

    all_scans = [d for d in os.listdir(scan_dir) if os.path.isdir(scan_dir / d)]
    
    if not all_scans:
        print("[+] No legacy scan sessions found.")
        print("="*60 + "\n")
        return

    print(f"[*] Found ({len(all_scans)}) local scan sessions. Starting scan...")
    
    synced_count = 0
    skipped_count = 0
    failed_count = 0

    for scan_id in sorted(all_scans):
        print(f"\n[>] Checking session: {scan_id}")
        
        # 1. Check local marker (optional optimization)
        marker_file = scan_dir / scan_id / ".synced"
        if marker_file.exists():
            print(f"    [âœ“] Session marked as already uploaded (Local Cache).")
            skipped_count += 1
            continue

        # 2. Check Hugging Face Cloud
        print(f"    [*] Checking existence on Hugging Face...")
        exists = check_if_scan_exists_on_hf(scan_id)
        
        if exists:
            print(f"    [âœ“] Session already exists in the cloud. Skipping.")
            # Create local marker to speed up next check
            try:
                with open(marker_file, "w") as f:
                    f.write(datetime.now().isoformat())
            except: pass
            skipped_count += 1
        else:
            print(f"    [!] Session not found in the cloud! Starting upload...")
            try:
                from Logic.hf_integration import sync_scan_results_to_proxy
                sync_scan_results_to_proxy(scan_id)
                
                # Verify again or assume success if no exception
                # Let's create the marker
                with open(marker_file, "w") as f:
                    f.write(datetime.now().isoformat())
                
                print(f"    [+] Session {scan_id} uploaded successfully!")
                synced_count += 1
            except Exception as e:
                print(f"    [-] Failed to upload session: {e}")
                failed_count += 1

    print("\n" + "="*60)
    print(" âœ… Sync Summary:")
    print(f"    - Total sessions scanned: {len(all_scans)}")
    print(f"    - Sessions skipped (already uploaded): {skipped_count}")
    print(f"    - Sessions uploaded successfully: {synced_count}")
    if failed_count > 0:
        print(f"    - Sessions failed (Internet required): {failed_count}")
    print("="*60 + "\n")

if __name__ == "__main__":
    # Test run
    check_and_sync_all()
