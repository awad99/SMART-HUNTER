import os
import sys
import argparse

# Add the project root and necessary subdirectories to sys.path to allow importing from top-level packages
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Data"))
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))

from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker
from vulnerability_scan.findings import split_findings
from Data.Update_Data import get_data_system

def run_standalone_sqli(url, cookie=None, thorough=False):
    print(f"\n{'='*60}")
    print(f"      SMART-HUNTER: STANDALONE SQLi SCANNER")
    print(f"{'='*60}")
    print(f"[*] Target: {url}")
    if cookie:
        print(f"[*] Cookie: [PROVIDED]")
    
    # Initialize the modularized checker
    checker = URLVulnerabilityChecker(cookie=cookie)
    checker.current_target_url = url
    
    # 1. Parameter Discovery
    targets = checker.discover_parameters(url)
    
    # Dump targets to sqli_parameters.txt for SQLMap
    param_file = os.path.join(root, "Data", "Parameters", "sqli_parameters.txt")
    os.makedirs(os.path.dirname(param_file), exist_ok=True)
    with open(param_file, "w") as f:
        # Add a special line for global session if provided as cookie arg
        if cookie:
            f.write(f"COOKIE|{url}|{cookie}\n")
            
        for meth in ['get', 'post', 'cookie']:
            for t in targets.get(meth, []):
                turl = t['url']
                plist = ",".join(t.get('params', []))
                if meth == 'get':
                    qs = "&".join(f"{p}=*" for p in t.get('params', []))
                    f.write(f"GET|{turl}?{qs}||{plist}\n")
                elif meth == 'post':
                    qs = "&".join(f"{p}=*" for p in t.get('params', []))
                    f.write(f"POST|{turl}|{qs}|{plist}\n")
                elif meth == 'cookie':
                    qs = "&".join(f"{p}=*" for p in t.get('params', []))
                    f.write(f"COOKIE|{turl}|{qs}|{plist}\n")
    print(f"    [*] Saved discovered targets to {param_file} for SQLMap")
    
    # 2. Built-in SQLi Checks (Phase 2)
    print(f"\n[+] Starting Phase 2: Built-in SQLi Checks...")
    sqli_vulns = checker.check_sqli_builtin(url, targets)
    if sqli_vulns:
        print(f"    [!] Built-in checks found {len(sqli_vulns)} potential SQLi!")
    else:
        print(f"    [-] Built-in checks: No findings.")
    

    native_sqli = any('SQL Injection' in v['type'] and v.get('confidence') == 'high' for v in sqli_vulns)
    
    print(f"\n[+] Starting Phase 3: SQLMap Integration...")
    if thorough or not native_sqli:
        try:
            checker.check_sql_injection_with_sqlmap()
        except Exception as e:
            print(f"    [-] SQLMap skipped/failed: {e}")
    else:
        print(f"    [*] High confidence SQLi already found. Skipping SQLMap to save time.")
        print(f"    [*] (Hint: Use --thorough to force SQLMap if needed)")

    # 4. Final Report
    existing_candidates = list(getattr(checker, 'scan_candidates', []))
    confirmed, candidates = split_findings(checker.vulnerabilities_found)
    _, normalized_existing_candidates = split_findings(existing_candidates)
    checker.vulnerabilities_found = confirmed
    checker.scan_candidates = normalized_existing_candidates + candidates

    checker.generate_report(url)
    resp = checker._make_request(url)
    if resp:
        features = get_data_system.extract_vulnerability_features(url, resp, confirmed)
        features['scan_id'] = getattr(checker, 'scan_id', '')
        features['target_url'] = url
        features['has_sql_errors'] = features.get('has_database_errors', 0)
        features['reflection_detected'] = features.get('has_reflection', 0)
        features['is_vulnerable'] = 1 if confirmed else 0
        if get_data_system.training_dataset_updates_enabled(default=True):
            get_data_system.update_dataset(features)
        else:
            print("[*] Dataset update disabled by SMART_HUNTER_UPDATE_DATASET=0")
    
    print(f"\n{'='*60}")
    print(f"      SCAN COMPLETE")
    print(f"{'='*60}")

def main():
    target = input("\nEnter URL Target: ").strip()
    if not target: return
    cookie = input("Enter Session Cookie (optional): ").strip()
    thorough = input("Enable Thorough Scan (SQLMap) [y/N]: ").strip().lower() == 'y'
    run_standalone_sqli(target, cookie if cookie else None, thorough)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Standalone SQLi Scanner")
        parser.add_argument("url", help="Target URL to scan")
        parser.add_argument("--cookie", help="Session cookie (optional)")
        parser.add_argument("--thorough", action="store_true", help="Force SQLMap even if built-in finds SQLi")
        args = parser.parse_args()
        run_standalone_sqli(args.url, args.cookie, args.thorough)
    else:
        main()
