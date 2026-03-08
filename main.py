import os, sys, urllib.parse, requests, httpx, ipaddress, warnings
import Recon.url_connection as url_connection
import vulnerability_scan.URL_checkIfhaveVun as URL_checkIfhaveVun
import vulnerability_scan.path_Analyze as path_Analyze
import mchine
from Mchine_Learning.Ai_model import VulnerabilityCheckerTraining, MODEL_FILE
from Mchine_Learning.prediction import SmartVulnerabilityScanner, show_phase_prediction

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

warnings.filterwarnings('ignore')

def get_parameters(url):
    try:
        import subprocess
        r = subprocess.run(['curl', '-s', '-L', url], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            import re
            print(f"[+] Fetched: {url}")
            names = list(set(re.findall(r'<input[^>]*name\s*=\s*["\']([^"\']*)["\']', r.stdout, re.I)))
            if names: print(f"[+] Parameters: {', '.join(names)}")
    except: pass

def main():
    # 1) Train / load model
    trainer = VulnerabilityCheckerTraining()
    if os.path.exists(MODEL_FILE):
        trainer.load_model(MODEL_FILE)
        print("[*] Retraining with latest data...")
    trainer.train_model()
    trainer.save_model()

    # 2) Get target
    Target = input("\nEnter URL or IP Target: ").strip()
    if not Target:
        print("[-] No target"); return
        
    Cookie = input("Enter Session Cookie (or leave blank to auto-detect): ").strip()
    
    # 3) URL target
    if Target.startswith(("http://", "https://")):
        if not Cookie:
            print(f"\n[*] Attempting to extract session cookie automatically from {Target}...")
            # 1) Try with httpx (modern, usually preferred)
            try:
                with httpx.Client(verify=False, timeout=30.0, follow_redirects=True) as client:
                    client.headers.update({
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    })
                    print("[*] Request 1 (httpx)...")
                    client.get(Target)
                    
                    parsed = urllib.parse.urlparse(Target)
                    root_url = f"{parsed.scheme}://{parsed.netloc}/"
                    if root_url != Target:
                        client.get(root_url)
                    
                    if client.cookies:
                        Cookie = "; ".join([f"{n}={v}" for n, v in client.cookies.items()])
                        print(f"[+] Extracted via httpx: {Cookie}")
            except httpx.ConnectError as e:
                print(f"[-] httpx Connection Error: {e}")
            except httpx.TimeoutException:
                print("[-] httpx Timeout: The server took too long to respond.")
            except Exception as e:
                print(f"[-] httpx error: {e.__class__.__name__} - {e}")
            
            # 2) Fallback to requests if httpx didn't get cookies
            if not Cookie:
                print("[*] httpx got no cookies, trying fallback (requests)...")
                try:
                    session = requests.Session()
                    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
                    session.get(Target, verify=False, timeout=20)
                    cookies_dict = session.cookies.get_dict()
                    if cookies_dict:
                        Cookie = "; ".join([f"{n}={v}" for n, v in cookies_dict.items()])
                        print(f"[+] Extracted via requests: {Cookie}")
                except requests.exceptions.ConnectionError as e:
                    print(f"[-] requests Connection Error: {e}")
                    print("[!] Suggestion: Check if the lab has expired, or if you need a VPN/Proxy.")
                except requests.exceptions.Timeout:
                    print("[-] requests Timeout: The lab may be sleeping or has expired.")
                except Exception as e:
                    print(f"[-] requests error: {e.__class__.__name__} - {e}")

            if not Cookie:
                print("[-] Automated extraction reached the site but found no cookies, or the site is unresponsive.")
        
        get_parameters(Target)
        print(f"\n[*] Target URL: {Target}")
        if Cookie: print(f"[*] Using Cookie: {Cookie}")

        # -- Build scanner & load/train model ---------------------------
        scanner = SmartVulnerabilityScanner(Target, cookie=Cookie)
        if not scanner.load_model(MODEL_FILE):
            print("[*] No saved model fresh training...")
            scanner.train_model()
            scanner.save_model(MODEL_FILE)

        print("\n" + "*"*64)
        print("*  VULNERABILITY PREDICTION PHASE 1: PRE-RECON START")
        print("*"*64)
        show_phase_prediction(scanner, phase=1, url=Target)

        if url_connection.MainRecon(Target, cookie=Cookie):
            print("\n[+] Recon complete")

        # -- Path Traversal Crawl & Scan --------------------------
        print("\n[*] Running path traversal crawler & scanner...")
        pt_results = path_Analyze.crawl_and_scan(Target, max_depth=3, cookie=Cookie)
        pt_vulns = pt_results.get('vulns', []) if pt_results else []

        print("\n[*] Running ML-guided active vulnerability tests...")
        quick_vulns = scanner.smart_vulnerability_scan(MODEL_FILE, crawl_results=pt_results)

        # Merge path traversal vulns into quick_vulns
        quick_vulns.extend(pt_vulns)

        URL_checkIfhaveVun.MainestVuln(Target, cookie=Cookie)

   
        print("\n" + "*"*64)
        print("*  VULNERABILITY PREDICTION PHASE 2: POST-TESTING")
        print("*"*64)

        show_phase_prediction(scanner, phase=21, url=Target)
        show_phase_prediction(scanner, phase=22, url=Target, confirmed_vulns=quick_vulns)

        # -- Summary -----------------------------------------------------
        print(f"\n{'='*64}\n  SCAN COMPLETE - FULL SUMMARY\n{'='*64}")
        print(f"  Active scan findings : {len(quick_vulns)}")
        for v in quick_vulns:
            finding_type = "VULNERABILITY" if v.get('confidence', '').lower() == 'high' else "ISSUE"
            print(f"    [{finding_type:13}] [{v.get('confidence', 'unknown').upper():6}] {v.get('type', ''):<35} param: {v.get('parameter', '')}")
        print(f"{'='*64}")

    # 4) IP target
    else:
        try:
            ipaddress.ip_address(Target)
            print(f"[*] Target IP: {Target}")
            mchine.MainPenTest(Target)
        except ValueError:
            print(f"[-] Invalid target: {Target}")

if __name__ == "__main__":
    typewriter(msg)
    main()