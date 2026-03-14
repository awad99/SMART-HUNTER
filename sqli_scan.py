import os
import sys
import argparse
from vulnerability_scan.URL_checkIfhaveVun import URLVulnerabilityChecker

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
    param_file = os.path.join("Data", "Parameters", "sqli_parameters.txt")
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
        checker.vulnerabilities_found.extend(sqli_vulns)
        print(f"    [!] Built-in checks found {len(sqli_vulns)} potential SQLi!")
    else:
        print(f"    [-] Built-in checks: No findings.")
    
    # 3. SQLMap Integration (Phase 3)
    # Only run SQLMap if no high-confidence SQLi found yet (to save time)
    # or if the user wants thorough testing.
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
    checker.generate_report(url)
    checker.extract_vulnerability_features(url)
    
    print(f"\n{'='*60}")
    print(f"      SCAN COMPLETE")
    print(f"{'='*60}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone SQLi Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--cookie", help="Session cookie (optional)")
    parser.add_argument("--thorough", action="store_true", help="Force SQLMap even if built-in finds SQLi")
    
    args = parser.parse_args()
    
    if not args.url.startswith("http"):
        print("[-] Error: URL must start with http:// or https://")
        sys.exit(1)
        
    run_standalone_sqli(args.url, args.cookie, args.thorough)
