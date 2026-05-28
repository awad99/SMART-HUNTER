from Logic.vulnerability_scan.csrf.csrf_scanner import CSRFScanner

url = "https://0a5500a1036311f480dc80d1003e00c5.web-security-academy.net/"
scanner = CSRFScanner()
findings = scanner.scan(url)
print("Findings:", findings)
