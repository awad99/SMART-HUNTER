import os, sys
root = os.path.dirname(os.path.abspath(__file__))
if root not in sys.path:
    sys.path.insert(0, root)
logic = os.path.join(root, 'Logic')
recon = os.path.join(logic, 'Recon')
if logic not in sys.path:
    sys.path.insert(0, logic)
if recon not in sys.path:
    sys.path.insert(0, recon)

import urllib3
urllib3.disable_warnings()

from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker

# Test URL from user
TARGET_URL = "https://0ab20074043a609b806a3fdf00720030.web-security-academy.net/"

print(f"Testing OOB SSRF against {TARGET_URL}")
print("=" * 60)

# Create scanner with OOB Interactsh enabled
scanner = URLVulnerabilityChecker(
    enable_oob=True, 
    use_interactsh=True
)

# We will just run the SSRF check directly to save time, 
# rather than the full suite which includes sqlmap/dalfox etc.
try:
    scanner.current_target_url = TARGET_URL
    targets = scanner.discover_parameters(TARGET_URL)
    
    print("\n[+] Running check_ssrf_oob")
    scanner.check_ssrf_oob(TARGET_URL, targets)
    
    findings = scanner.vulnerabilities_found
    print(f"\n[+] Total findings: {len(findings)}")
    for f in findings:
        print(f"  - {f['type']} in {f['parameter']}")
        
except Exception as e:
    import traceback
    traceback.print_exc()
