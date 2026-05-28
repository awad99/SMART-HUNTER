import sys
import os

root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root)
sys.path.append(os.path.join(root, "UI"))
sys.path.append(os.path.join(root, "Logic"))
sys.path.append(os.path.join(root, "Logic", "Recon"))
sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
sys.path.append(os.path.join(root, "Data"))

from Logic.vulnerability_scan.csrf.xsrfprobe_runner import XSRFProbeRunner

url = "https://0a8000fb04de162181f9a431008d0070.web-security-academy.net/"
print("Testing XSRFProbe on:", url)

scanner = XSRFProbeRunner()
findings = scanner.run(url)
print("Findings:", findings)
