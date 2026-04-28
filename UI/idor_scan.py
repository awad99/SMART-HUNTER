import os
import sys
import argparse

# Add the project root and necessary subdirectories to sys.path to allow importing from top-level packages
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "Recon", "vulnerability_scan"))

from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker

def run_standalone_idor(url, cookie=None):
    print(f"\n{'='*60}")
    print(f"      SMART-HUNTER: STANDALONE IDOR SCANNER")
    print(f"{'='*60}")
    print(f"[*] Target: {url}")
    
    checker = URLVulnerabilityChecker(cookie=cookie)
    checker.current_target_url = url
    
    # 1. Parameter Discovery
    targets = checker.discover_parameters(url)
    
    # 2. Autonomous IDOR Hunter
    print(f"\n[+] Starting Phase 2: Autonomous IDOR Hunter...")
    checker.check_generic_idor(url, targets)
    
    # 3. IDORD Tool Integration
    print(f"\n[+] Starting Phase 3: IDORD Tool Integration...")
    checker.check_idor_with_idord(url, targets)
    
    # 4. Final Report
    checker.generate_report(url)
    
    print(f"\n{'='*60}")
    print(f"      SCAN COMPLETE")
    print(f"{'='*60}")

def main():
    target = input("\nEnter URL Target: ").strip()
    if not target: return
    cookie = input("Enter Session Cookie (optional): ").strip()
    run_standalone_idor(target, cookie if cookie else None)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Standalone IDOR Scanner")
        parser.add_argument("url", help="Target URL to scan")
        parser.add_argument("--cookie", help="Session cookie (optional)")
        args = parser.parse_args()
        run_standalone_idor(args.url, args.cookie)
    else:
        main()
