"""
VERIFICATION: CSRF Scanner after fixes
Target: PortSwigger XSS Lab (should produce 0 CSRF findings)
"""
import os, sys
root = os.path.dirname(os.path.abspath(__file__))
for p in [root, os.path.join(root,"Logic"), os.path.join(root,"Logic","Recon"),
          os.path.join(root,"Logic","vulnerability_scan"), os.path.join(root,"Data")]:
    if p not in sys.path:
        sys.path.insert(0, p)

TARGET_URL = "https://0a55003d04dbcc12807d03da00af00e7.web-security-academy.net/"

print("=" * 70)
print("  CSRF SCANNER VERIFICATION (POST-FIX)")
print("  Target:", TARGET_URL)
print("  Expected: 0 findings")
print("=" * 70)

import requests, urllib3
urllib3.disable_warnings()

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})

# Quick parameter discovery
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

r = session.get(TARGET_URL, verify=False, timeout=10)
soup = BeautifulSoup(r.text, 'html.parser')

targets = {'get': [], 'post': [], 'cookie': []}
base_host = urlparse(TARGET_URL).netloc

internal_links = set()
for a_tag in soup.find_all('a', href=True):
    href = a_tag['href']
    full_url = urljoin(TARGET_URL, href)
    parsed = urlparse(full_url)
    if parsed.netloc == base_host:
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if clean_url != TARGET_URL.rstrip('/'):
            internal_links.add(clean_url)

def extract_forms(page_soup, page_url):
    for form in page_soup.find_all('form'):
        meth = form.get('method', 'get').lower()
        action = form.get('action', '')
        turl = urljoin(page_url, action)
        params = []
        defaults = {}
        for inpt in form.find_all(['input','textarea','select']):
            name = inpt.get('name')
            if name:
                params.append(name)
                defaults[name] = inpt.get('value', '') or 'test'
        if params:
            targets[meth].append({'url': turl, 'params': params, 'defaults': defaults, 'page_url': page_url})

extract_forms(soup, TARGET_URL)
for link_url in list(internal_links)[:10]:
    try:
        lr = session.get(link_url, timeout=5, verify=False)
        extract_forms(BeautifulSoup(lr.text, 'html.parser'), link_url)
    except:
        pass

seen = set()
new_post = []
for t in targets['post']:
    key = (t['url'], tuple(sorted(t['params'])))
    if key not in seen:
        seen.add(key)
        new_post.append(t)
targets['post'] = new_post

print(f"\n  POST forms: {len(targets['post'])}")
for t in targets['post']:
    print(f"    -> {t['url']}")

# Run native CSRF scanner
print("\n" + "=" * 70)
print("  NATIVE CSRF SCANNER")
print("=" * 70)

from vulnerability_scan.csrf.csrf_scanner import CSRFScanner
native_scanner = CSRFScanner(session=session, cookie=None, timeout=10)
native_findings = native_scanner.scan(TARGET_URL, targets=targets)

print(f"\n\n  NATIVE RESULTS: {len(native_findings)} finding(s)")
for i, f in enumerate(native_findings, 1):
    print(f"    #{i}: {f.get('type')} [{f.get('confidence')}] -> {f.get('form_url', 'N/A')}")

# Summary
print("\n" + "=" * 70)
print(f"  TOTAL FINDINGS: {len(native_findings)}")
print(f"  EXPECTED:       0")
if native_findings:
    print(f"  RESULT: STILL HAS FALSE POSITIVES")
else:
    print(f"  RESULT: FIXED! No false positives")
print("=" * 70)
