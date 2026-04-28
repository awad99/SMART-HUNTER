#!/usr/bin/env python3
"""
SMART-HUNTER Data Uploader - Incremental Upload
Only uploads new data, avoids duplicates
"""

import os
import re
import json
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Base path
BASE_PATH = os.path.join(os.getcwd(), "Data")

# Colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_colored(text, color=Colors.RESET):
    print(f"{color}{text}{Colors.RESET}")

def ask_confirmation(question, default="yes"):
    prompt = f"{Colors.CYAN}[Y/n]{Colors.RESET}" if default == "yes" else f"{Colors.CYAN}[y/N]{Colors.RESET}"
    response = input(f"{Colors.BOLD}{question}{Colors.RESET} {prompt} ").strip().lower()
    if not response:
        return default == "yes"
    return response in ['y', 'yes']

def extract_domain_from_url(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return None

def get_existing_targets():
    """Get all existing target URLs from database"""
    try:
        response = supabase.table("targets").select("url").execute()
        return {item["url"] for item in response.data}
    except Exception as e:
        print_colored(f"Error fetching existing targets: {e}", Colors.RED)
        return set()

def get_existing_scan_hashes():
    """Get all existing scan hashes to avoid duplicates"""
    try:
        response = supabase.table("scans").select("id, target_id, scan_start").execute()
        # Create hash based on target_id and scan_start date (only date, not time)
        hashes = set()
        for scan in response.data:
            # Use target_id + date as unique identifier
            scan_date = scan["scan_start"][:10] if scan["scan_start"] else ""
            hash_key = f"{scan['target_id']}_{scan_date}"
            hashes.add(hash_key)
        return hashes
    except Exception as e:
        print_colored(f"Error fetching existing scans: {e}", Colors.RED)
        return set()

def get_existing_vulnerabilities():
    """Get all existing vulnerability hashes"""
    try:
        response = supabase.table("vulnerabilities").select("type, url, parameter, payload, scan_id").execute()
        # Create hash for each vulnerability
        hashes = set()
        for vuln in response.data:
            hash_key = f"{vuln['type']}_{vuln['url']}_{vuln.get('parameter', '')}_{vuln.get('payload', '')}"
            hashes.add(hash_key)
        return hashes
    except Exception as e:
        print_colored(f"Error fetching existing vulnerabilities: {e}", Colors.RED)
        return set()

def get_existing_features():
    """Get all existing feature hashes"""
    try:
        response = supabase.table("features").select("scan_id, feature_name").execute()
        hashes = set()
        for feature in response.data:
            hash_key = f"{feature['scan_id']}_{feature['feature_name']}"
            hashes.add(hash_key)
        return hashes
    except Exception as e:
        print_colored(f"Error fetching existing features: {e}", Colors.RED)
        return set()

def get_or_create_target(url, existing_targets):
    """Get existing target or create new one (only if not exists)"""
    if url in existing_targets:
        # Get the actual ID
        try:
            response = supabase.table("targets").select("id").eq("url", url).execute()
            if response.data:
                return response.data[0]["id"]
        except:
            pass
        return None
    
    try:
        domain = extract_domain_from_url(url)
        new_target = {
            "url": url,
            "domain": domain,
            "ip_address": None
        }
        response = supabase.table("targets").insert(new_target).execute()
        # Add to existing targets set for this session
        existing_targets.add(url)
        return response.data[0]["id"]
    except Exception as e:
        print_colored(f"Error creating target: {e}", Colors.RED)
        return None

def create_scan_if_not_exists(target_id, scan_name, existing_scan_hashes):
    """Create scan only if it doesn't exist for this target on this date"""
    today = datetime.now().strftime("%Y-%m-%d")
    hash_key = f"{target_id}_{today}"
    
    if hash_key in existing_scan_hashes:
        print_colored(f"  Scan already exists for target {target_id} on {today}, skipping", Colors.YELLOW)
        return None
    
    try:
        scan_data = {
            "target_id": target_id,
            "scan_start": datetime.now().isoformat(),
            "scan_end": None,
            "status": "running"
        }
        response = supabase.table("scans").insert(scan_data).execute()
        scan_id = response.data[0]["id"]
        
        add_log(scan_id, "info", f"Scan: {scan_name}")
        existing_scan_hashes.add(hash_key)
        return scan_id
    except Exception as e:
        print_colored(f"Error creating scan: {e}", Colors.RED)
        return None

def update_scan_status(scan_id, status, scan_end=None):
    try:
        update_data = {"status": status}
        if scan_end:
            update_data["scan_end"] = scan_end.isoformat()
        supabase.table("scans").update(update_data).eq("id", scan_id).execute()
        return True
    except Exception as e:
        print_colored(f"Error: {e}", Colors.RED)
        return False

def add_log(scan_id, log_type, message):
    try:
        supabase.table("logs").insert({
            "scan_id": scan_id,
            "log_type": log_type,
            "message": message
        }).execute()
        return True
    except Exception as e:
        print_colored(f"Error: {e}", Colors.RED)
        return False

def map_cvss_to_severity(score):
    try:
        s = float(score)
        if s >= 9: return "critical"
        elif s >= 7: return "high"
        elif s >= 4: return "medium"
        else: return "low"
    except:
        return "low"

def is_vulnerability_true(value):
    if value is None:
        return False
    if isinstance(value, str):
        return value == '1' or value.lower() == 'true' or value == 'True'
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, bool):
        return value
    return False

def upload_vulnerabilities_from_csv(scan_id, csv_path, tool_name, existing_vulns):
    """Upload vulnerabilities from CSV file (only new ones)"""
    if not os.path.exists(csv_path):
        return 0
    
    print_colored(f"\n[VULNERABILITIES] {os.path.basename(csv_path)}", Colors.BLUE)
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
            # Detect vulnerability columns
            vuln_columns = []
            for col in reader.fieldnames:
                if col in ['url', 'cvss_estimate', 'total_vulns_high', 'total_issues_med_low']:
                    continue
                if any(kw in col.lower() for kw in ['_vuln', 'xss', 'sqli', 'lfi', 'rfi', 'cmdi', 'idor', 'pt']):
                    vuln_columns.append(col)
            
            if not vuln_columns:
                print_colored("  No vulnerability columns found", Colors.YELLOW)
                return 0
            
            # Collect new vulnerabilities
            new_vulns = []
            for row in rows:
                url = row.get('url', '')
                if not url:
                    continue
                
                for col in vuln_columns:
                    value = row.get(col)
                    if is_vulnerability_true(value):
                        vuln_type = col.lower().replace('_vuln', '').replace('vuln_', '')
                        severity = map_cvss_to_severity(row.get('cvss_estimate', 0))
                        
                        # Create hash to check if exists
                        hash_key = f"{vuln_type}_{url}_"
                        if hash_key not in existing_vulns:
                            new_vulns.append((url, vuln_type, severity))
            
            if not new_vulns:
                print_colored("  No new vulnerabilities found", Colors.GREEN)
                return 0
            
            print_colored(f"  Found {len(new_vulns)} new vulnerabilities", Colors.CYAN)
            
            if not ask_confirmation(f"Upload {len(new_vulns)} new vulnerabilities?"):
                return 0
            
            inserted = 0
            for url, vuln_type, severity in new_vulns:
                try:
                    supabase.table("vulnerabilities").insert({
                        "scan_id": scan_id,
                        "type": vuln_type,
                        "url": url,
                        "severity": severity,
                        "tool_used": tool_name
                    }).execute()
                    inserted += 1
                    existing_vulns.add(f"{vuln_type}_{url}_")
                except Exception as e:
                    print_colored(f"    Error: {e}", Colors.RED)
            
            print_colored(f"  ✓ Uploaded {inserted} new vulnerabilities", Colors.GREEN)
            return inserted
            
    except Exception as e:
        print_colored(f"  Error: {e}", Colors.RED)
        return 0

def upload_parameter_vulnerabilities(scan_id, parameters_dir, existing_vulns):
    """Upload parameters as potential vulnerabilities (only new ones)"""
    if not os.path.exists(parameters_dir):
        print_colored("  Parameters folder not found", Colors.YELLOW)
        return
    
    print_colored(f"\n[PARAMETER VULNS] Parameters folder", Colors.BLUE)
    
    files = {
        "idor_params.txt": ("idor_suspect", "low"),
        "xss_parameters.txt": ("xss_suspect", "medium"),
        "sqli_parameters.txt": ("sqli_suspect", "high"),
        "rce_parameters.txt": ("rce_suspect", "critical"),
        "path_traversal_successful.txt": ("path_traversal", "high")
    }
    
    # Collect new parameters
    new_params = []
    total = 0
    
    for filename, (vtype, severity) in files.items():
        path = os.path.join(parameters_dir, filename)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        total += 1
                        parts = line.split('|')
                        url = parts[0] if len(parts) > 0 and parts[0].startswith('http') else None
                        param = parts[1] if len(parts) > 1 else line
                        
                        hash_key = f"{vtype}_{url}_{param}"
                        if hash_key not in existing_vulns:
                            new_params.append((url, param, line, vtype, severity))
    
    if total == 0:
        print_colored("  No parameter files found", Colors.YELLOW)
        return
    
    print_colored(f"  Found {len(new_params)} new parameters out of {total} total", Colors.CYAN)
    
    if not new_params:
        print_colored("  No new parameters to upload", Colors.GREEN)
        return
    
    if not ask_confirmation(f"Upload {len(new_params)} new parameters?"):
        return
    
    inserted = 0
    for url, param, line, vtype, severity in new_params:
        try:
            supabase.table("vulnerabilities").insert({
                "scan_id": scan_id,
                "type": vtype,
                "url": url,
                "parameter": param if not url else param,
                "payload": line if vtype == "path_traversal" else None,
                "severity": severity,
                "tool_used": "param_discovery"
            }).execute()
            inserted += 1
            existing_vulns.add(f"{vtype}_{url}_{param}")
        except Exception as e:
            print_colored(f"    Error: {e}", Colors.RED)
    
    print_colored(f"  ✓ Uploaded {inserted} new parameters", Colors.GREEN)

def upload_domain_features(scan_id, base_path, existing_features):
    """Upload domain-related features (only new ones)"""
    print_colored(f"\n[DOMAIN FEATURES] Extracting...", Colors.BLUE)
    
    new_features = []
    
    # Discovered URLs count
    discovered_file = os.path.join(base_path, "domains", "discovered_urls.txt")
    if os.path.exists(discovered_file):
        with open(discovered_file, 'r', encoding='utf-8') as f:
            count = sum(1 for _ in f)
            feature_name = "total_discovered_urls"
            hash_key = f"{scan_id}_{feature_name}"
            if hash_key not in existing_features:
                new_features.append((feature_name, str(count)))
                print_colored(f"  New: total_discovered_urls: {count:,}", Colors.CYAN)
    
    # Subdomains count
    subdomains_file = os.path.join(base_path, "domains", "subdomains.txt")
    if os.path.exists(subdomains_file):
        with open(subdomains_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            count = sum(1 for line in lines if line.strip() and not line.startswith('[*]'))
            feature_name = "total_subdomains"
            hash_key = f"{scan_id}_{feature_name}"
            if hash_key not in existing_features:
                new_features.append((feature_name, str(count)))
                print_colored(f"  New: total_subdomains: {count}", Colors.CYAN)
    
    if not new_features:
        print_colored("  No new domain features found", Colors.GREEN)
        return
    
    if not ask_confirmation(f"Upload {len(new_features)} new domain features?"):
        return
    
    for name, value in new_features:
        try:
            supabase.table("features").insert({
                "scan_id": scan_id,
                "feature_name": name,
                "feature_value": value
            }).execute()
            existing_features.add(f"{scan_id}_{name}")
        except Exception as e:
            print_colored(f"    Error: {e}", Colors.RED)
    
    print_colored(f"  ✓ Uploaded {len(new_features)} new features", Colors.GREEN)

def upload_ml_features(scan_id, base_path, existing_features):
    """Upload ML features from CSV files (only new ones)"""
    print_colored(f"\n[ML FEATURES] Extracting...", Colors.BLUE)
    
    new_features = []
    
    csv_files = [
        os.path.join(base_path, "master_vulnerability_data.csv"),
        os.path.join(base_path, "Datasets", "master_vulnerability_data.csv"),
        os.path.join(base_path, "Datasets", "vulnerability_ml_dataset.csv"),
        os.path.join(base_path, "Datasets", "web_recon_ml_dataset.csv")
    ]
    
    for csv_path in csv_files:
        if not os.path.exists(csv_path):
            continue
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                if not rows:
                    continue
                
                feature_cols = [c for c in reader.fieldnames if c.startswith('has_')]
                
                for col in feature_cols:
                    true_count = 0
                    for row in rows:
                        val = row.get(col, '0')
                        if is_vulnerability_true(val):
                            true_count += 1
                    
                    percentage = (true_count / len(rows)) * 100
                    
                    # Check if features already exist
                    perc_name = f"{col}_percentage"
                    count_name = f"{col}_count"
                    perc_key = f"{scan_id}_{perc_name}"
                    count_key = f"{scan_id}_{count_name}"
                    
                    if perc_key not in existing_features:
                        new_features.append((perc_name, f"{percentage:.2f}"))
                    if count_key not in existing_features:
                        new_features.append((count_name, str(true_count)))
                    
        except Exception as e:
            print_colored(f"  Error reading {os.path.basename(csv_path)}: {e}", Colors.RED)
            continue
    
    if not new_features:
        print_colored("  No new ML features found", Colors.GREEN)
        return
    
    print_colored(f"  Found {len(new_features)} new ML features", Colors.CYAN)
    
    if not ask_confirmation(f"Upload {len(new_features)} new ML features?"):
        return
    
    inserted = 0
    for name, value in new_features:
        try:
            supabase.table("features").insert({
                "scan_id": scan_id,
                "feature_name": name,
                "feature_value": value
            }).execute()
            inserted += 1
            existing_features.add(f"{scan_id}_{name}")
        except Exception as e:
            print_colored(f"    Error: {e}", Colors.RED)
    
    print_colored(f"  ✓ Uploaded {inserted} new ML features", Colors.GREEN)

def upload_sqli_report(scan_id, base_path, existing_vulns):
    """Upload SQLi report vulnerability (only if new)"""
    sqli_report = None
    scan_folder = os.path.join(base_path, "vuln_scan_20260325_090854")
    
    if os.path.exists(scan_folder):
        for root, dirs, files in os.walk(scan_folder):
            for file in files:
                if "blind_sqli_report" in file and file.endswith('.txt'):
                    sqli_report = os.path.join(root, file)
                    break
            if sqli_report:
                break
    
    if not sqli_report or not os.path.exists(sqli_report):
        return
    
    print_colored(f"\n[SQLI REPORT] Found report", Colors.BLUE)
    
    with open(sqli_report, 'r', encoding='utf-8') as f:
        content = f.read()
        url_match = re.search(r'URL\s*:\s*(.+)', content)
        url = url_match.group(1).strip() if url_match else None
        
        if not url:
            return
        
        hash_key = f"blind_sqli_{url}_"
        
        if hash_key in existing_vulns:
            print_colored("  SQLi vulnerability already exists, skipping", Colors.GREEN)
            return
        
        print_colored(f"  New SQLi vulnerability for: {url}", Colors.CYAN)
        
        if ask_confirmation("Upload new SQLi vulnerability?"):
            try:
                supabase.table("vulnerabilities").insert({
                    "scan_id": scan_id,
                    "type": "blind_sqli",
                    "url": url,
                    "severity": "high",
                    "tool_used": "blind_sqli_scanner"
                }).execute()
                existing_vulns.add(hash_key)
                print_colored("  ✓ Uploaded", Colors.GREEN)
            except Exception as e:
                print_colored(f"  ✗ Error: {e}", Colors.RED)

def upload_recon_data(scan_id, base_path, existing_recon):
    """Upload reconnaissance data (only if new)"""
    headers_file = os.path.join(base_path, "request_headers.txt")
    if not os.path.exists(headers_file):
        return
    
    # Check if recon data already exists for this scan
    try:
        response = supabase.table("recon_data").select("id").eq("scan_id", scan_id).execute()
        if response.data:
            print_colored("  Recon data already exists for this scan, skipping", Colors.GREEN)
            return
    except:
        pass
    
    print_colored(f"\n[RECON DATA] request_headers.txt", Colors.BLUE)
    if not ask_confirmation("Upload new recon data?"):
        return
    
    with open(headers_file, 'r', encoding='utf-8') as f:
        content = f.read()
        headers = {}
        for line in content.split('\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
    
    supabase.table("recon_data").insert({
        "scan_id": scan_id,
        "headers": headers,
        "waf_detected": False,
        "server": headers.get("Server"),
        "technologies": {},
        "cookies": headers.get("Cookie")
    }).execute()
    print_colored("  ✓ Uploaded", Colors.GREEN)

def get_all_targets_from_data(base_path):
    """Get all unique targets from all data sources"""
    targets = set()
    
    csv_files = [
        os.path.join(base_path, "master_vulnerability_data.csv"),
        os.path.join(base_path, "Datasets", "master_vulnerability_data.csv"),
        os.path.join(base_path, "Datasets", "vulnerability_ml_dataset.csv"),
        os.path.join(base_path, "Datasets", "web_recon_ml_dataset.csv")
    ]
    
    for csv_path in csv_files:
        if os.path.exists(csv_path):
            try:
                with open(csv_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get('url'):
                            targets.add(row['url'])
            except:
                pass
    
    train_file = os.path.join(base_path, "train.txt")
    if os.path.exists(train_file):
        try:
            with open(train_file, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and url.startswith(('http://', 'https://')):
                        targets.add(url)
        except:
            pass
    
    return list(targets)

def main():
    print_colored("\n" + "="*60, Colors.BOLD)
    print_colored("SMART-HUNTER Data Uploader - Incremental Mode", Colors.BOLD)
    print_colored("Only new data will be uploaded (no duplicates)", Colors.BOLD)
    print_colored("="*60, Colors.BOLD)
    
    if not os.path.exists(BASE_PATH):
        print_colored(f"Error: Data directory not found", Colors.RED)
        return
    
    # Get existing data from database
    print_colored(f"\n[PRE-CHECK] Fetching existing data from database...", Colors.BLUE)
    existing_targets = get_existing_targets()
    existing_scans = get_existing_scan_hashes()
    existing_vulns = get_existing_vulnerabilities()
    existing_features = get_existing_features()
    
    print_colored(f"  Existing targets: {len(existing_targets)}", Colors.CYAN)
    print_colored(f"  Existing scans: {len(existing_scans)}", Colors.CYAN)
    print_colored(f"  Existing vulnerabilities: {len(existing_vulns)}", Colors.CYAN)
    print_colored(f"  Existing features: {len(existing_features)}", Colors.CYAN)
    
    # Get all targets from files
    print_colored(f"\n[STEP 1] Scanning for new targets...", Colors.BLUE)
    file_targets = get_all_targets_from_data(BASE_PATH)
    new_targets = [t for t in file_targets if t not in existing_targets]
    
    print_colored(f"  Found {len(file_targets)} total targets in files", Colors.CYAN)
    print_colored(f"  New targets: {len(new_targets)}", Colors.GREEN if new_targets else Colors.YELLOW)
    
    if new_targets:
        if ask_confirmation(f"Create {len(new_targets)} new targets?"):
            for url in new_targets[:10]:  # Show first 10
                print_colored(f"    - {url}", Colors.CYAN)
            if len(new_targets) > 10:
                print_colored(f"    ... and {len(new_targets)-10} more", Colors.CYAN)
    
    # Create scans for all targets (not just new ones, to ensure they have a scan today)
    print_colored(f"\n[STEP 2] Creating scan records for today...", Colors.BLUE)
    scan_ids = []
    all_targets = file_targets  # Use all targets from files
    
    for target_url in all_targets:
        target_id = get_or_create_target(target_url, existing_targets)
        if target_id:
            scan_id = create_scan_if_not_exists(target_id, "Incremental_Upload", existing_scans)
            if scan_id:
                scan_ids.append((target_id, scan_id, target_url))
    
    if not scan_ids:
        print_colored("  No new scans created for today", Colors.GREEN)
    else:
        print_colored(f"  Created {len(scan_ids)} new scan records for today", Colors.GREEN)
    
    # Use first scan ID for shared data (or None if no new scans)
    first_scan_id = scan_ids[0][1] if scan_ids else None
    
    if first_scan_id:
        # Upload shared data
        print_colored(f"\n[STEP 3] Uploading shared data (if new)...", Colors.BLUE)
        upload_recon_data(first_scan_id, BASE_PATH, None)
        upload_parameter_vulnerabilities(first_scan_id, os.path.join(BASE_PATH, "Parameters"), existing_vulns)
        upload_domain_features(first_scan_id, BASE_PATH, existing_features)
        upload_ml_features(first_scan_id, BASE_PATH, existing_features)
        upload_sqli_report(first_scan_id, BASE_PATH, existing_vulns)
        
        # Upload vulnerabilities from CSV files
        print_colored(f"\n[STEP 4] Uploading vulnerabilities from CSV files...", Colors.BLUE)
        csv_files = [
            (os.path.join(BASE_PATH, "master_vulnerability_data.csv"), "master_scanner"),
            (os.path.join(BASE_PATH, "Datasets", "master_vulnerability_data.csv"), "ml_dataset"),
            (os.path.join(BASE_PATH, "Datasets", "vulnerability_ml_dataset.csv"), "ml_dataset"),
            (os.path.join(BASE_PATH, "Datasets", "web_recon_ml_dataset.csv"), "ml_dataset")
        ]
        
        for csv_path, tool_name in csv_files:
            if os.path.exists(csv_path):
                upload_vulnerabilities_from_csv(first_scan_id, csv_path, tool_name, existing_vulns)
        
        # Update all scans as completed
        print_colored(f"\n[STEP 5] Finalizing scans...", Colors.BLUE)
        for target_id, scan_id, target_url in scan_ids:
            update_scan_status(scan_id, "completed", datetime.now())
            add_log(scan_id, "info", f"Incremental upload completed")
    
    # Summary
    print_colored(f"\n{'='*60}", Colors.BOLD)
    print_colored("UPLOAD SUMMARY", Colors.BOLD)
    print_colored(f"New targets created: {len(new_targets)}", Colors.GREEN)
    print_colored(f"New scans created: {len(scan_ids)}", Colors.GREEN)
    print_colored(f"All operations completed!", Colors.GREEN)
    print_colored("="*60, Colors.BOLD)

if __name__ == "__main__":
    main()