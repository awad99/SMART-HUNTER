import os, sys, urllib.parse, requests, httpx, ipaddress, warnings
import Recon.url_connection as url_connection
import vulnerability_scan.Scanner_vulnerability as URL_checkIfhaveVun
import vulnerability_scan.path_Analyze as path_Analyze
import machine
from Machine_Learning.Ai_model import VulnerabilityCheckerTraining, MODEL_FILE
from Machine_Learning.prediction import SmartVulnerabilityScanner, show_phase_prediction

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
    return target, cookie

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

def setup_active_scanner(target, cookie):
    scanner = SmartVulnerabilityScanner(target, cookie=cookie)
    if not scanner.load_model(MODEL_FILE):
        print("[*] No saved model found, training from scratch...")
        scanner.train_model()
        scanner.save_model(MODEL_FILE)
    return scanner

def run_url_pentest(target, cookie, scanner):
    print("\n" + "*"*64)
    print("*  VULNERABILITY PREDICTION PHASE 1: PRE-RECON START")
    print("*"*64)
    show_phase_prediction(scanner, phase=1, url=target)

    if url_connection.MainRecon(target, cookie=cookie):
        print("\n[+] Recon complete")

    print("\n[*] Running path traversal crawler & scanner...")
    pt_results = path_Analyze.crawl_and_scan(target, max_depth=3, cookie=cookie)
    pt_vulns = pt_results.get('vulns', []) if pt_results else []

    print("\n[*] Running ML-guided active vulnerability tests...")
    quick_vulns = scanner.smart_vulnerability_scan(MODEL_FILE, crawl_results=pt_results)

    quick_vulns.extend(pt_vulns)

    URL_checkIfhaveVun.MainestVuln(target, cookie=cookie)

    print("\n" + "*"*64)
    print("*  VULNERABILITY PREDICTION PHASE 2: POST-TESTING")
    print("*"*64)

    show_phase_prediction(scanner, phase=21, url=target)
    show_phase_prediction(scanner, phase=22, url=target, confirmed_vulns=quick_vulns)
    return quick_vulns

def run_ip_pentest(target):
    try:
        ipaddress.ip_address(target)
        print(f"[*] Target IP: {target}")
        mchine.MainPenTest(target)
    except ValueError:
        print(f"[-] Invalid target: {target}")

def display_scan_summary(quick_vulns):
    print(f"\n{'='*64}\n  SCAN COMPLETE - FULL SUMMARY\n{'='*64}")
    print(f"  Active scan findings : {len(quick_vulns)}")
    for v in quick_vulns:
        finding_type = "VULNERABILITY" if v.get('confidence', '').lower() == 'high' else "ISSUE"
        print(f"    [{finding_type:13}] [{v.get('confidence', 'unknown').upper():6}] {v.get('type', ''):<35} param: {v.get('parameter', '')}")
    print(f"{'='*64}")

def run_scanner(target, cookie):
    scanner = setup_active_scanner(target, cookie)
    quick_vulns = run_url_pentest(target, cookie, scanner)
    display_scan_summary(quick_vulns)
    
def main():
    display_banner()
    target, cookie = get_user_inputs()
    if not target:
        print("[-] No target"); return
        
    if target.startswith(("http://", "https://")):
        if not cookie:
            cookie = auto_extract_cookie(target)
        
        print(f"\n[*] Target URL: {target}")
        if cookie: print(f"[*] Using Cookie: {cookie}")

        run_scanner(target, cookie)
    else:
        run_ip_pentest(target)

if __name__ == "__main__":
    main()