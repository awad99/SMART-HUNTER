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
    sys.path.append(os.path.join(root, "Data"))

from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker
from Data.Update_Data import get_data_system

def run_standalone_xxe(url, cookie=None):
    print(f"\n{'='*60}")
    print(f"      SMART-HUNTER: STANDALONE XXE SCANNER")
    print(f"{'='*60}")
    print(f"[*] Target: {url}")
    
    checker = URLVulnerabilityChecker(cookie=cookie)
    checker.current_target_url = url
    
    # 1. Parameter Discovery
    targets = checker.discover_parameters(url)
    
    # 2. XXE Tool Checks
    print(f"\n[+] Starting Phase 2: XXE Tool Checks...")
    checker.check_xxe_with_tool(url, targets)
    
    # 3. Final Report
    checker.generate_report(url)
    
    print(f"\n{'='*60}")
    print(f"      SCAN COMPLETE")
    print(f"{'='*60}")

def main():
    target = input("\nEnter URL Target: ").strip()
    if not target: return
    cookie = input("Enter Session Cookie (optional): ").strip()
    run_standalone_xxe(target, cookie if cookie else None)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Standalone XXE Scanner")
        parser.add_argument("url", help="Target URL to scan")
        parser.add_argument("--cookie", help="Session cookie (optional)")
        args = parser.parse_args()
        run_standalone_xxe(args.url, args.cookie)
    else:
        main()
