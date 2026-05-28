import sys
import os

root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root)
sys.path.append(os.path.join(root, "UI"))
sys.path.append(os.path.join(root, "Logic"))
sys.path.append(os.path.join(root, "Logic", "Recon"))
sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
sys.path.append(os.path.join(root, "Data"))

from Logic.vulnerability_scan.csrf.csrf_scanner import CSRFScanner
from Logic.vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker

url = "https://0a8000fb04de162181f9a431008d0070.web-security-academy.net/"
print("Testing CSRF Lab:", url)

# Use URLVulnerabilityChecker to simulate the crawler gathering forms, then pass to CSRF
checker = URLVulnerabilityChecker()
# It will run discover_parameters internally
targets = checker.discover_parameters(url)

# Now pass those targets to CSRF scanner directly with credentials
scanner = CSRFScanner(credentials={'username': 'wiener', 'password': 'peter'})
findings = scanner.scan(url, targets=targets)

for f in findings:
    print(f"FINDING: {f['type']} - {f['evidence']}")
