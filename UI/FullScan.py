import os, sys, urllib.parse, requests, httpx, ipaddress, warnings

# Add the project root and necessary subdirectories to sys.path to allow importing from top-level packages
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
    sys.path.append(os.path.join(root, "Data"))

import Recon.url_connection as url_connection

import vulnerability_scan.Scanner_vulnerability as URL_checkIfhaveVun
import vulnerability_scan.pathScanner.path_Analyze as path_Analyze
from vulnerability_scan.findings import split_findings
from Data.Queries.scan_stats import ScanStats
import machine
from Machine_Learning.Ai_model import MODEL_FILE
from Machine_Learning.prediction import SmartVulnerabilityScanner, ensure_prediction_model, show_phase_prediction

msg = r"""
      ___           _              _   _               _   _                     
     / _ \         | |            | | | |             | | (_)                    
    / /_\ \  _   _ | |_  ___      | |_| | _   _  _ __ | |_  _  _ __    __ _      
   / / _ \ \| | | || __|/ _ \     |  _  || | | || '_ \| __|| || '_ \  / _` |     
  / / ___ \ \ |_| || |_| (_) |    | | | || |_| || | | || |_ | || | | || (_| |     
 /_/ /   \_\ \__,_| \__|\___/     \_| |_/ \__,_||_| |_| \__||_||_| |_| \__, |     
                                                                        __/ |     
                                                                       |___/
"""

def typewriter(msg):
    for chart in msg:
        sys.stdout.write(chart)
        sys.stdout.flush()

def display_banner():
    typewriter(msg)

def get_user_inputs():
    target = input("\nEnter URL or IP Target: ").strip()
    cookie = input("Enter Session Cookie (or leave blank to auto-detect): ").strip()
    
    username = input("Enter Username (optional): ").strip()
    password = ""
    if username:
        password = input("Enter Password: ").strip()
    
    # Enable OOB via Interactsh by default for full scans
    enable_oob = True
    use_interactsh = True
    collaborator_domain = None

    return target, cookie, username, password, enable_oob, use_interactsh, collaborator_domain

def auto_extract_cookie(target):
    print(f"\n[*] Attempting to extract session cookie automatically from {target}...")
    cookie = ""
    try:
        with httpx.Client(verify=False, timeout=30.0, follow_redirects=True) as client:
            client.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            })
            print("[*] Request 1 (httpx)...")
            client.get(target)
            
            parsed = urllib.parse.urlparse(target)
            root_url = f"{parsed.scheme}://{parsed.netloc}/"
            if root_url != target:
                client.get(root_url)
            
            if client.cookies:
                cookie = "; ".join([f"{n}={v}" for n, v in client.cookies.items()])
                print(f"[+] Extracted via httpx: {cookie}")
    except Exception as e:
        print(f"[-] httpx error: {e.__class__.__name__} - {e}")
    
    if not cookie:
        print("[*] httpx got no cookies, trying fallback (requests)...")
        try:
            session = requests.Session()
            session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
            session.get(target, verify=False, timeout=20)
            cookies_dict = session.cookies.get_dict()
            if cookies_dict:
                cookie = "; ".join([f"{n}={v}" for n, v in cookies_dict.items()])
                print(f"[+] Extracted via requests: {cookie}")
        except Exception as e:
            print(f"[-] requests error: {e.__class__.__name__} - {e}")

    if not cookie:
        print("[-] Automated extraction reached the site but found no cookies, or the site is unresponsive.")
    return cookie

def setup_active_scanner(target, cookie, scan_id=None):
    scanner = SmartVulnerabilityScanner(target, cookie=cookie)
    if scan_id:
        scanner.scan_id = scan_id
    if not ensure_prediction_model(scanner, model_path=MODEL_FILE, allow_train=True):
        print("[!] ML prediction disabled: no saved model is available and the canonical training datasets are not ready yet.")
    return scanner

def run_url_pentest(target, cookie, scanner, scan_id, stats, enable_oob=False, use_interactsh=False, collaborator_domain=None, interactive=False):
    print("\n" + "*"*64)
    print("*  LOGIC PHASE 1: RECON")
    print("*"*64)

    recon_result = url_connection.MainRecon(target, cookie=cookie, scan_id=scan_id, stats=stats, return_details=True)
    recon_ok = recon_result.get("ok", False) if isinstance(recon_result, dict) else recon_result
    waf_bypass_cookies = recon_result.get("waf_bypass_cookies", {}) if isinstance(recon_result, dict) else {}
    if waf_bypass_cookies:
        print(f"\n[+] WAF bypass cookies available — will inject into vulnerability scanner")
    if recon_ok:
        print("\n[+] Recon phase complete")
    else:
        print("\n[!] Recon phase did not complete cleanly; continuing with vulnerability_scan phase")

    print("\n" + "*"*64)
    print("*  LOGIC PHASE 2: VULNERABILITY_SCAN")
    print("*"*64)

    print("\n[*] Running path traversal crawler & scanner...")
    pt_results = path_Analyze.crawl_and_scan(target, max_depth=3, cookie=cookie, scan_id=scan_id, stats=stats)
    pt_vulns = pt_results.get('vulns', []) if pt_results else []

    print("\n" + "*"*64)
    print("*  VULNERABILITY PREDICTION PHASE 1: POST-RECON")
    print("*"*64)
    show_phase_prediction(scanner, phase=21, url=target)

    print("\n[*] Running ML-guided active vulnerability tests...")
    # Passing stats via the scanner object if supported, otherwise just proceeding
    # The SmartVulnerabilityScanner might need update too if it does DB ops, 
    # but usually it uses other tools.
    quick_vulns = scanner.smart_vulnerability_scan(MODEL_FILE, crawl_results=pt_results)

    quick_vulns.extend(pt_vulns)

    main_vulns = URL_checkIfhaveVun.MainestVuln(target, cookie=cookie, scan_id=scan_id, stats=stats, enable_oob=enable_oob, collaborator_domain=collaborator_domain, use_interactsh=use_interactsh, interactive=interactive, waf_bypass_cookies=waf_bypass_cookies)
    if main_vulns:
        quick_vulns.extend(main_vulns)

    confirmed_vulns, candidate_vulns = split_findings(quick_vulns)

    print("\n" + "*"*64)
    print("*  VULNERABILITY PREDICTION PHASE 2: POST-TESTING")
    print("*"*64)

    show_phase_prediction(scanner, phase=22, url=target, confirmed_vulns=confirmed_vulns)
    return confirmed_vulns, candidate_vulns

def run_ip_pentest(target, scan_id, stats):
    try:
        ipaddress.ip_address(target)
        print(f"[*] Target IP: {target}")
        machine.MainPenTest(target, scan_id=scan_id, stats=stats)
    except ValueError:
        print(f"[-] Invalid target: {target}")

def display_scan_summary(confirmed_vulns, candidate_vulns=None):
    candidate_vulns = candidate_vulns or []
    print(f"\n{'='*64}\n  SCAN COMPLETE - FULL SUMMARY\n{'='*64}")
    print(f"  Confirmed findings   : {len(confirmed_vulns)}")
    print(f"  Candidates/suspected : {len(candidate_vulns)}")
    for v in confirmed_vulns:
        finding_type = "VULNERABILITY" if v.get('confidence', '').lower() == 'high' else "ISSUE"
        print(f"    [{finding_type:13}] [{v.get('confidence', 'unknown').upper():6}] {v.get('type', ''):<35} param: {v.get('parameter', '')}")
    print(f"{'='*64}")

def run_scanner(target, cookie, enable_oob=False, use_interactsh=False, collaborator_domain=None):
    from datetime import datetime
    scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    print(f"[*] Starting Global Scan Session: {scan_id}")
    
    # Initialize session-wide statistics
    stats = ScanStats(scan_id)
    stats.add('scans', 1)
    
    scanner = setup_active_scanner(target, cookie, scan_id=scan_id)
    confirmed_vulns, candidate_vulns = run_url_pentest(target, cookie, scanner, scan_id, stats, enable_oob=enable_oob, use_interactsh=use_interactsh, collaborator_domain=collaborator_domain, interactive=True)
    display_scan_summary(confirmed_vulns, candidate_vulns)
    
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme and not parsed.netloc:
        run_ip_pentest(target, scan_id, stats)

def main():
    display_banner()
    target, cookie, username, password, enable_oob, use_interactsh, collaborator_domain = get_user_inputs()
    if not target:
        print("[-] No target"); return
        
    if username and password:
        os.environ['CSRF_USER'] = username
        os.environ['CSRF_PASS'] = password
        
    if target.startswith(("http://", "https://")):
        if not cookie:
            cookie = auto_extract_cookie(target)
        
        print(f"\n[*] Target URL: {target}")
        if cookie: print(f"[*] Using Cookie: {cookie}")

        run_scanner(target, cookie, enable_oob=enable_oob, use_interactsh=use_interactsh, collaborator_domain=collaborator_domain)
    else:
        run_ip_pentest(target)

if __name__ == "__main__":
    main()
