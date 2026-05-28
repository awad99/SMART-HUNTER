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
from Recon.framework_detector import FrameworkDetector, detect_framework


def run_standalone_csrf(url, cookie=None):
    print(f"\n{'='*60}")
    print(f"      SMART-HUNTER: STANDALONE CSRF SCANNER")
    print(f"{'='*60}")
    print(f"[*] Target: {url}")

    # ── Phase 1: Framework Detection (Recon) ──
    print(f"\n[+] Phase 1: Framework Detection (Recon)...")
    framework_info = detect_framework(url, cookie=cookie)
    fw_name = framework_info.get('framework', 'unknown')
    fw_conf = framework_info.get('confidence', 'none')
    print(f"    [*] Detected Framework: {fw_name} (confidence: {fw_conf})")
    if framework_info.get('evidence'):
        for ev in framework_info['evidence'][:5]:
            print(f"        - {ev}")

    # ── Phase 2: CSRF Vulnerability Scanning ──
    print(f"\n[+] Phase 2: CSRF Vulnerability Scanning...")
    checker = URLVulnerabilityChecker(cookie=cookie, interactive=True)
    checker.current_target_url = url

    # 1. Parameter Discovery
    targets = checker.discover_parameters(url)

    # 2. CSRF Checks
    print(f"\n[+] Starting CSRF vulnerability checks...")
    checker.check_csrf_vulnerabilities(url, targets=targets)

    # 3. Final Report
    checker.generate_report(url)

    print(f"\n{'='*60}")
    print(f"      SCAN COMPLETE")
    print(f"{'='*60}")


def main():
    target = input("\nEnter URL Target: ").strip()
    if not target:
        return
    cookie = input("Enter Session Cookie (optional): ").strip()
    run_standalone_csrf(target, cookie if cookie else None)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Standalone CSRF Scanner")
        parser.add_argument("url", help="Target URL to scan")
        parser.add_argument("--cookie", help="Session cookie (optional)")
        args = parser.parse_args()
        run_standalone_csrf(args.url, args.cookie)
    else:
        main()
