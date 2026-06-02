import time
import os
import httpx
from urllib.parse import urlparse, urljoin
from datetime import datetime

from Logic.Recon.utils import normalize_url
from Logic.Recon.http_client import ReconHttpClient
from Data.Queries.q_cookies import save_cookies
from Data.Queries.q_headers import save_headers
from Data.Queries.q_redirects import save_redirect_hop
from Data.Queries.q_reports import save_report

REQUEST_DELAY = float(os.getenv("SMART_HUNTER_RECON_REDIRECT_DELAY", "0"))
MAX_REDIRECTS = max(1, int(os.getenv("SMART_HUNTER_RECON_MAX_REDIRECTS", "10")))

class RedirectTracker:
    """Tracks HTTP redirects and captures intermediate headers/cookies."""
    
    def __init__(self, db, scan_id, stats):
        self.db = db
        self.scan_id = scan_id
        self.stats = stats
        self.redirect_chain = []
        self.cookies = []
        self.headers = []
        self.final_url = None
        self.last_response = None

    def track(self, original_url, cookie, on_hop_callback=None):
        current = normalize_url(original_url)
        count = 0
        self.redirect_chain = [{'url': current, 'type': 'ORIGINAL'}]
        self.cookies = []
        self.headers = []

        try:
            with ReconHttpClient.build_client(cookie=cookie, follow_redirects=False) as c:
                while count < MAX_REDIRECTS:
                    if count and REQUEST_DELAY:
                        time.sleep(REQUEST_DELAY)
                    try:
                        resp = c.get(current)
                    except httpx.TimeoutException:
                        print(f"    [-] Timeout: {current}")
                        break
                    except Exception as e:
                        print(f"    [-] Error: {e}")
                        break

                    self.last_response = resp
                    self._grab_cookies(resp, current)
                    self._grab_headers(resp, current)
                    print(f"    [{count+1}] {current} -> {resp.status_code}")
                    
                    if on_hop_callback:
                        on_hop_callback(resp, current, count)
                    
                    save_redirect_hop(self.db, self.scan_id, count+1, current, resp.status_code, 
                                     resp.headers.get('location',''), 'REDIRECT' if count else 'ORIGINAL')
                    self.stats.add('redirect_chain', 1)

                    self.redirect_chain.append({'url': current, 'status_code': resp.status_code,
                                                'location': resp.headers.get('location','')})

                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get('location')
                        if not loc:
                            break
                        current = urljoin(current, loc)
                        count += 1
                    else:
                        self.final_url = str(resp.url)
                        self.redirect_chain.append({'url': self.final_url, 'type': 'FINAL', 'status': resp.status_code})
                        return resp
        except Exception as e:
            print(f"    [-] Client setup error: {e}")
        return None

    def _grab_cookies(self, response, url):
        cookies_to_save = []
        for name, val in response.cookies.items():
            c_data = {'name': name, 'value': val,
                      'domain': urlparse(url).hostname, 'url': url,
                      'timestamp': datetime.now().isoformat()}
            self.cookies.append(c_data)
            cookies_to_save.append(c_data)
        if cookies_to_save:
            save_cookies(self.db, self.scan_id, url, cookies_to_save)
            self.stats.add('cookies', len(cookies_to_save))

    def _grab_headers(self, response, url):
        self.headers.append({'url': url, 'status_code': response.status_code,
                             'headers': dict(response.headers),
                             'timestamp': datetime.now().isoformat()})
        save_headers(self.db, self.scan_id, url, response.status_code, dict(response.headers))
        self.stats.add('response_headers', len(response.headers))

    def get_cookies_for_requests(self):
        return {c['name']: c['value'] for c in self.cookies}

    def save_redirect_analysis(self, original_url):
        if len(self.redirect_chain) <= 1: return
        domains = {urlparse(s['url']).netloc for s in self.redirect_chain if 'url' in s}
        upgraded = (original_url.startswith('http://') and
                    bool(self.final_url) and self.final_url.startswith('https://'))
        lines = [
            "REDIRECT CHAIN ANALYSIS", "="*50,
            f"Original : {original_url}",
            f"Final    : {self.final_url or 'N/A'}",
            f"Hops     : {len(self.redirect_chain)-2}",
            "", "CHAIN:",
        ]
        for i, s in enumerate(self.redirect_chain):
            if i == 0:
                lines.append(f"  {i+1}. ORIGINAL: {s['url']}")
            elif 'status_code' in s:
                lines.append(f"  {i+1}. {s['status_code']}: {s['url']} -> {s.get('location','')}")
            else:
                lines.append(f"  {i+1}. FINAL: {s['url']} ({s.get('status','')})")
        lines += ["", "SECURITY:",
                  f"  Domains     : {len(domains)} ({', '.join(domains)})",
                  f"  HTTP->HTTPS  : {'Yes' if upgraded else 'No'}"]

        content = "\n".join(lines)
        save_report(self.db, self.scan_id, 'redirect_analysis', content)
        print(f"[+] Redirect analysis saved to DB")
        save_report(self.db, self.scan_id, 'redirect_chain', self.redirect_chain)
        print(f"[+] Redirect chain saved to DB")

    def print_redirect_summary(self, original_url):
        if len(self.redirect_chain) <= 1: return
        print(f"\n{'='*60}\nREDIRECT SUMMARY\n{'='*60}")
        print(f"  {original_url}  ->  {self.final_url}  ({len(self.redirect_chain)-2} hops)")
        for i, s in enumerate(self.redirect_chain):
            if 'status_code' in s:
                print(f"  {i+1}. [{s['status_code']}] {s['url']} -> {s.get('location','')}")
            else:
                print(f"  {i+1}. {'START' if i==0 else 'FINAL'}: {s['url']}")
        print("="*60)
