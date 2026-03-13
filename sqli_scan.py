import os
import sys
import urllib.parse
import warnings
from datetime import datetime

# Add the current directory to sys.path so we can import internal modules
sys.path.append(os.getcwd())

import vulnerability_scan.URL_checkIfhaveVun as URL_checkIfhaveVun

warnings.filterwarnings('ignore')

def run_sqli_only_scan():
    print(r"""
    =========================================
       Standalone SQL Injection Scanner
    =========================================
    """)

    # 1) Get target
    target_url = input("Enter Target URL (e.g., http://example.com/page.php?id=1): ").strip()
    if not target_url:
        print("[-] Error: No target URL provided.")
        return

    cookie = input("Enter Session Cookie (optional): ").strip() or None

    # 2) Initialize Scanner
    print(f"[*] Initializing SQLi Scanner for: {target_url}")
    checker = URL_checkIfhaveVun.URLVulnerabilityChecker(cookie=cookie)
    checker.current_target_url = target_url # Set this so scoping works in internal methods

    # 3) Discovery Phase
    print("\n[*] Phase 1: Parameter Discovery")
    targets = checker.discover_parameters(target_url)
    
    # 3.1) Populate sqli_parameters.txt for external tools
    sqli_param_file = os.path.join(URL_checkIfhaveVun.DATASET_DIR, "Parameters", "sqli_parameters.txt")
    os.makedirs(os.path.dirname(sqli_param_file), exist_ok=True)
    
    sqli_targets = []
    # Convert discovered targets into the format expected by SQLMap script (METHOD|URL|DATA)
    # Use original values when available — SQLMap works much better with real data
    for t in targets.get('get', []):
        u = t['url']
        defaults = t.get('defaults', {})
        # URL-encode values to prevent & in values (e.g. "Toys & Games") from breaking the URL
        p = "&".join([f"{k}={urllib.parse.quote(defaults.get(k, 'FUZZ'), safe='')}" for k in t['params']])
        full_u = f"{u}?{p}" if p else u
        sqli_targets.append(f"GET|{full_u}|")
    
    for t in targets.get('post', []):
        u = t['url']
        defaults = t.get('defaults', {})
        d = "&".join([f"{k}={urllib.parse.quote(defaults.get(k, 'FUZZ'), safe='')}" for k in t['params']])
        sqli_targets.append(f"POST|{u}|{d}")

    for t in targets.get('cookie', []):
        u = t['url']
        defaults = t.get('defaults', {})
        c = "; ".join([f"{k}={defaults.get(k, 'FUZZ')}" for k in t['params']])
        sqli_targets.append(f"COOKIE|{u}|{c}")

    # Fallback if discovery missed things but user provided a query-string URL
    if not sqli_targets:
        parsed = urllib.parse.urlparse(target_url)
        if parsed.query:
             sqli_targets.append(f"GET|{target_url.split('?')[0]}?{parsed.query}|")
        else:
            # Minimal targets if nothing else
            sqli_targets.append(f"GET|{target_url}?id=FUZZ|")

    with open(sqli_param_file, 'w') as f:
        f.write("\n".join(sqli_targets) + "\n")
    print(f"    [+] Saved {len(sqli_targets)} targets to {sqli_param_file}")

    # 4) Built-in SQLi Scan
    print("\n[*] Phase 2: Built-in SQLi Check")
    builtin_vulns = checker.check_sqli_builtin(target_url, targets)
    
    if builtin_vulns:
        checker.vulnerabilities_found.extend(builtin_vulns)
        print(f"[!] Found {len(builtin_vulns)} potential SQLi using built-in engine.")
    else:
        print("[+] Built-in engine found no obvious SQLi.")

    # 5) SQLMap Scan (Optional but recommended if built-in fails or to confirm)
    confirm_with_sqlmap = input("\nDo you want to run SQLMap for deep analysis? (y/n): ").strip().lower()
    if confirm_with_sqlmap == 'y':
        print("\n[*] Phase 3: External SQLMap Check")
        dump_choice = input("    Do you want to automatically extract data? (none/dbs/tables/all): ").strip().lower()
        if dump_choice == 'dbs':
            os.environ['SQLMAP_EXTRA_ARGS'] = '--dbs'
        elif dump_choice == 'tables':
            os.environ['SQLMAP_EXTRA_ARGS'] = '--tables'
        elif dump_choice == 'all':
            os.environ['SQLMAP_EXTRA_ARGS'] = '--dump'
        else:
            os.environ['SQLMAP_EXTRA_ARGS'] = ''
            
        print("    [*] Starting SQLMap... (this may take time, please wait)")
        try:
            # Modify the checker's current target to ensure scoping works
            checker.current_target_url = target_url
            checker.check_sql_injection_with_sqlmap()
        except Exception as e:
            print(f"[-] SQLMap error: {e}")

    # 6) Final Report
    print("\n" + "="*60)
    print("  SCAN COMPLETE - SQLi SUMMARY")
    print("="*60)
    
    sqli_found = [v for v in checker.vulnerabilities_found if 'SQL Injection' in v.get('type', '')]
    
    if sqli_found:
        print(f"[!] Total SQL Injection findings: {len(sqli_found)}")
        for i, v in enumerate(sqli_found, 1):
            conf = v.get('confidence', 'unknown').upper()
            print(f"    {i}. [{conf}] {v['type']} in parameter: {v.get('parameter', 'unknown')}")
            print(f"       Payload: {v.get('payload', 'N/A')}")
            print(f"       Evidence: {v.get('evidence', '')}")
            print("-" * 30)
    else:
        print("[+] No SQL Injection vulnerabilities were confirmed.")
    
    print(f"[*] Results saved in: {checker.scan_dir}")
    print("="*60)

    # 7) Read and display dumped CSV data
    dump_dir = os.path.abspath(os.path.join(checker.scan_dir, "sqlmap_results"))
    if os.path.exists(dump_dir):
        import glob
        import pandas as pd
        # Use a more flexible glob to find CSVs in the dump directory
        csv_files = glob.glob(os.path.join(dump_dir, "**", "dump", "**", "*.csv"), recursive=True)
        if csv_files:
            summary_file = os.path.join(checker.scan_dir, "database_dump_summary.txt")
            print("\n" + "█"*60)
            print("  EXTRACTED DATABASE TABLES (SQLMAP)")
            print("█"*60)
            
            with open(summary_file, 'w', encoding='utf-8') as sf_out:
                sf_out.write(f"DATABASE DUMP SUMMARY\nTarget: {target_url}\nScan ID: {checker.scan_id}\n{'='*60}\n\n")
                
                for csvf in csv_files:
                    try:
                        # Robustly get table and database names from path
                        # Handle both \ and / separators
                        norm_path = csvf.replace('\\', '/')
                        parts = norm_path.split('/')
                        table_name = parts[-1].replace('.csv', '')
                        db_name = parts[-2] if len(parts) > 1 else "unknown"
                        
                        header = f"\n[!] TABLE DATA: {db_name}.{table_name}"
                        underline = "-" * (len(header) - 1)
                        print(header)
                        print(underline)
                        sf_out.write(header + "\n" + underline + "\n")
                        
                        df = pd.read_csv(csvf)
                        if not df.empty:
                            table_str = df.to_string(index=False)
                            print(table_str)
                            sf_out.write(table_str + "\n")
                        else:
                            empty_msg = "    (Table is empty)"
                            print(empty_msg)
                            sf_out.write(empty_msg + "\n")
                        sf_out.write("\n" + "="*60 + "\n")
                    except Exception as e:
                        err_msg = f"[-] Could not read {csvf}: {e}"
                        print(err_msg)
                        sf_out.write(err_msg + "\n")
            
            print("\n" + "█"*60)
            print(f"[*] Database summary saved to: {summary_file}")
        else:
            # If no CSVs found, maybe check if a log exists but no dump
            log_files = glob.glob(os.path.join(dump_dir, "**", "log"), recursive=True)
            if log_files:
                print("\n[*] SQLMap scan logs found, but no file dumps detected yet.")
                print("    Try running with 'all' or 'tables' to trigger a dump.")
    else:
        print("\n[-] No SQLMap results directory found.")

if __name__ == "__main__":
    try:
        run_sqli_only_scan()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")
