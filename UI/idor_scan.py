import os
import sys
import argparse

# Add the project root and necessary subdirectories to sys.path to allow importing from top-level packages
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))

from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker

def run_standalone_idor(url, cookie=None, lab_only=True):
    print(f"\n{'='*60}")
    print(f"      SMART-HUNTER: STANDALONE IDOR SCANNER")
    print(f"{'='*60}")
    print(f"[*] Target: {url}")
    
    if lab_only and "portswigger.net" not in url and "localhost" not in url and "127.0.0.1" not in url:
        print("[!] WARNING: Target does not appear to be a known lab environment.")
        print("[!] Use --allow-out-of-scope or run in non-lab-only mode to scan this target.")
        return
    
    checker = URLVulnerabilityChecker(cookie=cookie)
    checker.current_target_url = url
    
    # 1. Parameter Discovery
    targets = checker.discover_parameters(url)
    
    # 2. Autonomous IDOR Hunter
    print(f"\n[+] Starting Phase 2: Autonomous IDOR Hunter...")
    checker.check_generic_idor(url, targets)
    
    # 3. Final Report
    print(f"\n[+] Starting Phase 3: Final Report...")
    checker.generate_report(url)
    
    print(f"\n{'='*60}")
    print(f"      SCAN COMPLETE")
    print(f"{'='*60}")

def main():
    target = input("\nEnter URL Target: ").strip()
    if not target: return
    cookie = input("Enter Session Cookie (optional): ").strip()
    force = input("Allow out-of-scope targets? (y/N): ").strip().lower() == 'y'
    run_standalone_idor(target, cookie if cookie else None, lab_only=not force)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Standalone IDOR Scanner")
        parser.add_argument("url", help="Target URL to scan")
        parser.add_argument("--cookie", help="Session cookie (optional)")
        parser.add_argument("--allow-out-of-scope", action="store_true", help="Allow scanning targets outside of lab environments")
        args = parser.parse_args()
        run_standalone_idor(args.url, args.cookie, lab_only=not args.allow_out_of_scope)
    else:
        main()
