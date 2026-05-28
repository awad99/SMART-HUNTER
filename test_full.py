import sys
import os

root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root)
sys.path.append(os.path.join(root, "UI"))
sys.path.append(os.path.join(root, "Logic"))
sys.path.append(os.path.join(root, "Logic", "Recon"))
sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
sys.path.append(os.path.join(root, "Data"))

from Logic.vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker

checker = URLVulnerabilityChecker()
# We don't want it to block on credentials prompt, so we pass interactive=False
checker.scan_url("https://0a5500a1036311f480dc80d1003e00c5.web-security-academy.net/", "CSRF", interactive=False)
