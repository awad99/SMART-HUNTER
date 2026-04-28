import os
import json
import sys
from pathlib import Path

# Add project root and Logic/Recon to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "Logic" / "Recon"))

from database_manager import DatabaseManager
from Data.Queries.q_payloads import save_payload, clear_payloads_by_category
from Data.Queries.q_parameters import save_discovered_parameters
from Data.Queries.q_discovery_domains import save_discovered_domains

def migrate_payloads(db):
    print("[*] Migrating Payloads...")
    payloads_dir = PROJECT_ROOT / "Data" / "Payloads"
    if not payloads_dir.exists():
        print(f"[-] Payloads directory not found: {payloads_dir}")
        return

    for file_path in payloads_dir.glob("*"):
        if file_path.is_file():
            category = file_path.stem.split('_')[0] # e.g. sqli, xss, rce
            print(f"    [>] Processing {file_path.name} (Category: {category})")
            
            try:
                if file_path.suffix == '.json':
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        save_payload(db, category, file_path.name, content=data)
                else:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = f.read()
                        save_payload(db, category, file_path.name, raw_content=data)
            except Exception as e:
                print(f"    [-] Error processing {file_path.name}: {e}")

def migrate_parameters(db):
    print("[*] Migrating Parameters...")
    params_dir = PROJECT_ROOT / "Data" / "Parameters"
    if not params_dir.exists():
        print(f"[-] Parameters directory not found: {params_dir}")
        return

    # Mock scan_id for historical data
    scan_id = "HISTORICAL_IMPORT"
    
    for file_path in params_dir.glob("*.txt"):
        print(f"    [>] Processing {file_path.name}")
        params_to_save = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    
                    # Try to parse line format: method|url|data|params
                    parts = line.split('|')
                    if len(parts) >= 2:
                        params_to_save.append({
                            'method': parts[0],
                            'url': parts[1],
                            'raw_line': line
                        })
                    else:
                        params_to_save.append({
                            'url': line,
                            'raw_line': line
                        })
            
            if params_to_save:
                save_discovered_parameters(db, scan_id, params_to_save, source='file_import')
        except Exception as e:
            print(f"    [-] Error processing {file_path.name}: {e}")

def migrate_domains(db):
    print("[*] Migrating Domains...")
    domains_dir = PROJECT_ROOT / "Data" / "domains"
    if not domains_dir.exists():
        print(f"[-] Domains directory not found: {domains_dir}")
        return

    scan_id = "HISTORICAL_IMPORT"
    
    # subdomains.txt
    sub_file = domains_dir / "subdomains.txt"
    if sub_file.exists():
        print(f"    [>] Processing {sub_file.name}")
        domains = []
        with open(sub_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('[*]'):
                    domains.append({'domain_name': line, 'domain_type': 'subdomain'})
        save_discovered_domains(db, scan_id, domains, source='file_import')

    # discovered_urls.txt
    urls_file = domains_dir / "discovered_urls.txt"
    if urls_file.exists():
        print(f"    [>] Processing {urls_file.name}")
        urls = []
        with open(urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    urls.append({'domain_name': line, 'domain_type': 'discovered_url'})
        # Batch save to avoid memory issues for large files
        batch_size = 1000
        for i in range(0, len(urls), batch_size):
            save_discovered_domains(db, scan_id, urls[i:i+batch_size], source='file_import')

def migrate_wordlists(db):
    print("[*] Migrating Wordlists...")
    wl_dir = PROJECT_ROOT / "Data" / "Wordlists"
    if not wl_dir.exists():
        print(f"[-] Wordlists directory not found: {wl_dir}")
        return

    # Files to migrate from Wordlists
    targets = {
        'idor_keyword.txt': 'idor',
        'path_traversal.txt': 'path_traversal'
    }

    for fn, category in targets.items():
        file_path = wl_dir / fn
        if file_path.exists():
            print(f"    [>] Processing {fn} (Category: {category})")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = f.read()
                    save_payload(db, category, fn, raw_content=data)
            except Exception as e:
                print(f"    [-] Error processing {fn}: {e}")

def seed_missing_data(db):
    print("[*] Seeding Missing/Default Data...")
    
    # Best Practice Seeds for Path Traversal
    pt_seeds = {
        'path_traversal_successful.txt': [
            "root:x:0:0:", "root:*:0:0:", "[extensions]", 
            "bin:x:1:1:", "[font]", "[boot loader]", 
            "boot.ini", "win.ini", "C:\\Windows\\", "/etc/passwd"
        ],
        'path_traversal_target_parameters.txt': [
            ".php", ".jsp", ".asp", ".aspx", ".html", 
            ".js", ".txt", ".json", ".conf", ".config", ".xml"
        ],
        'path_traversal_paramtrs.txt': [
            "file", "path", "src", "include", "item", "doc", 
            "report", "view", "data", "id", "name", "root"
        ]
    }
    
    for fn, items in pt_seeds.items():
        # Only seed if file doesn't exist or is empty
        fpath = PROJECT_ROOT / "Data" / "Parameters" / fn
        should_seed = True
        if fpath.exists() and fpath.stat().st_size > 0:
            should_seed = False
            
        if should_seed:
            print(f"    [+] Seeding {fn} with default signatures")
            save_payload(db, 'path_traversal', fn, raw_content='\n'.join(items))

def main():
    db = DatabaseManager()
    print("="*50)
    print("SMART-HUNTER Migration: Phase 2 (Wordlists & Seeds)")
    print("="*50)
    
    # Ensure historical scan exists
    scan_id = "HISTORICAL_IMPORT"
    db.create_scan(scan_id, "file://historical_import", user_agent="migration_script")
    
    migrate_payloads(db)
    migrate_parameters(db)
    migrate_domains(db)
    migrate_wordlists(db)
    seed_missing_data(db)
    
    db.update_scan_status(scan_id, 'completed')
    
    print("="*50)
    print("[+] Migration phase 2 finished!")
    print("="*50)

if __name__ == "__main__":
    main()
