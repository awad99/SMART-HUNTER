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

scanner = CSRFScanner()
url = "https://0a5500a1036311f480dc80d1003e00c5.web-security-academy.net/"
# Pre-populate targets simulating the crawler output
targets = {
    'get': [],
    'post': [
        {
            'url': 'https://0a5500a1036311f480dc80d1003e00c5.web-security-academy.net/login',
            'params': ['csrf', 'username', 'password'],
            'defaults': {'csrf': 'dummy', 'username': 'test', 'password': 'test'},
            'page_url': url
        }
    ],
    'cookie': []
}

findings = scanner.scan(url, targets=targets)
for f in findings:
    print(f"FINDING: {f['type']} - {f['evidence']}")
