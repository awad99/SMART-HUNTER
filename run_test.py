import sys
import os

root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root)
sys.path.append(os.path.join(root, "Logic"))
sys.path.append(os.path.join(root, "Data"))

from Logic.vulnerability_scan.Scanner_vulnerability import MainestVuln

url = "https://0ac900a40445e0b18367464b006100ce.web-security-academy.net/"
print(f"Starting test scan on {url} ...")

try:
    results = MainestVuln(url)
    print("\n--- FINAL RESULTS ---")
    if results:
        import json
        print(json.dumps(results, indent=2))
    else:
        print("No vulnerabilities confirmed.")
except Exception as e:
    print(f"Error during scan: {e}")
