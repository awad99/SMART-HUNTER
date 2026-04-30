import concurrent.futures
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import urllib.parse
import warnings
from datetime import datetime
from urllib.parse import parse_qs, urlparse, urljoin

import httpx, pandas as pd
from bs4 import BeautifulSoup
from database_manager import DatabaseManager

# ── استيراد مباشر من ملفات Queries ────────────────────────────────────
from Data.Queries.q_subdomains    import save_subdomains
from Data.Queries.q_fuzzing       import save_fuzz_results
from Data.Queries.q_raw_responses import save_raw_response
from Data.Queries.q_features      import save_features      as _save_features_direct
from Data.Queries.q_scans         import create_scan        as _create_scan_direct, update_scan_status as _update_scan_status_direct
from Data.Queries.q_cookies       import save_cookies
from Data.Queries.q_headers       import save_headers
from Data.Queries.scan_stats      import ScanStats
from Data.Queries.q_reports         import save_report
from Data.Update_Data.target_scan_dataset import append_target_scan_row

warnings.filterwarnings('ignore')

# -- Constants --------------------------------------------------------------
UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36'}
DATASET_DIR      = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "Data")
SCRIPT_DIR       = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script")
ML_DATASET_FILE  = os.path.join(DATASET_DIR, "Datasets", "Datasets_for_Model_Evaluation", "recon", "web_recon_ml_dataset.csv")
REQUEST_DELAY    = float(os.getenv("SMART_HUNTER_RECON_REDIRECT_DELAY", "0"))
MAX_REDIRECTS    = max(1, int(os.getenv("SMART_HUNTER_RECON_MAX_REDIRECTS", "10")))
HTTP_TIMEOUT     = float(os.getenv("SMART_HUNTER_RECON_TIMEOUT", "10"))
MAX_ANALYSIS_BYTES = max(50000, int(os.getenv("SMART_HUNTER_RECON_MAX_ANALYSIS_BYTES", "500000")))
DISCOVERY_WORKERS = max(1, int(os.getenv("SMART_HUNTER_RECON_DISCOVERY_WORKERS", "3")))
DATASET_LOCK = threading.Lock()
_RECON_DATASET_COLUMNS_CACHE = None
_PROXY_CACHE = {"checked": False, "value": None}

# -- WAF signatures ---------------------------------------------------------
_WAF_SIGS = {
    "Cloudflare":       ["cf-ray", "__cfduid", "cloudflare"],
    "AWS WAF":          ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":           ["akamai-grn", "x-akamai-transformed"],
    "Sucuri":           ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":          ["x-iinfo", "incap_ses", "visid_incap"],
    "F5 BIG-IP":        ["x-wa-info", "bigipserver"],
    "ModSecurity":      ["mod_security", "modsecurity"],
    "Barracuda":        ["barra_counter_session"],
}

_CONTENT_TYPES = {
    'html': 'html', 'json': 'json', 'xml': 'xml',
    'javascript': 'javascript', 'css': 'css',
    'image': 'image', 'pdf': 'pdf', 'text/plain': 'text',
}

_SEC_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
    "Referrer-Policy", "Permissions-Policy", "Cache-Control",
]

# -- Precompiled Regexes --------------------------------------------------
_RE_PASSWORD = re.compile(r'<input[^>]*type=[\'"]password[\'"]', re.I)
_RE_HIDDEN = re.compile(r'<input[^>]*type=[\'"]hidden[\'"]', re.I)
_RE_FILE = re.compile(r'<input[^>]*type=[\'"]file[\'"]', re.I)
_RE_SEARCH = re.compile(r'<input[^>]*type=[\'"]search[\'"]', re.I)
_RE_SEARCH_NAME = re.compile(r'<input[^>]*name=[\'"](?:search|q|query)[\'"]', re.I)
_RE_SCRIPT_SRC = re.compile(r'<script[^>]*src=[\'"]([^\'"]+)[\'"]', re.I)
_RE_HREF = re.compile(r'<a[^>]*href=[\'"]([^\'"]+)[\'"]', re.I)
_RE_JWT = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
_RE_API_KEY = re.compile(r'(?i)(?:api_key|apikey|access_token|secret_key)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?')
_RE_FILE_PATHS = re.compile(r'(?i)(?:/etc/|/var/www/|/home/|[A-Z]:\\(?:inetpub|xampp|Users|Windows)\\)')
_RE_DEBUG_INFO = re.compile(r'(?i)(?:debug|console\.log|var_dump|print_r|traceback|stack trace)')
_RE_ERROR_MSG = re.compile(r'(?i)(?:error|exception|warning|traceback|stack trace|fatal)')
_RE_SQL_ERR = re.compile(r'(?i)(?:sql syntax|mysql|postgresql|oracle|sqlite|database error|odbc|ora-\d+)')
_RE_TOKEN_NAME = re.compile(r'(?i)(?:csrf|xsrf|token|authenticity|nonce)')
_RE_LOGIN_HINT = re.compile(r'(?i)(?:login|signin|auth|account|user|email|pass)')
_RE_COMMENT = re.compile(r'<!--')


def _env_bool(name, default=False):
    raw = str(os.getenv(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "enable", "enabled"}


def _normalize_url(url):
    text = (url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = "https://" + text
    return text


def _ordered_unique(items):
    out = []
    seen = set()
    for item in items:
        if item in seen or item in ("", None):
            continue
        seen.add(item)
        out.append(item)
    return out


def _safe_ratio(numerator, denominator):
    return (numerator / denominator) if denominator else 0.0


def _host_scope_suffix(hostname):
    parts = [part for part in (hostname or "").split(".") if part]
    if len(parts) > 2:
        return ".".join(parts[1:])
    return hostname or ""


def _same_scope_host(candidate_host, base_host):
    candidate = (candidate_host or "").lower()
    base = (base_host or "").lower()
    suffix = _host_scope_suffix(base)
    return bool(candidate) and (
        candidate == base or
        candidate.endswith("." + base) or
        candidate == suffix or
        candidate.endswith("." + suffix)
    )


def _same_scope_url(candidate_url, base_url):
    candidate_host = urlparse(candidate_url).hostname or ""
    base_host = urlparse(base_url).hostname or ""
    return _same_scope_host(candidate_host, base_host)


def _normalize_candidate_url(base_url, candidate):
    href = (candidate or "").strip()
    if not href:
        return ""
    if href.startswith(("javascript:", "data:", "mailto:", "tel:", "#")):
        return ""
    return urljoin(base_url, href)


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return 1
    except ValueError:
        return 0



# ===========================================================================
def robust_input(prompt, default='n'):
    """
    سؤال المستخدم بطريقة أكثر استقراراً لتجنب مشاكل التجميد في تيرمينال ويندوز.
    """
    import sys
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            return default
        return line.strip().lower()
    except Exception:
        return default

class ReconWebSite:
# ===========================================================================

    def __init__(self, url, cookie=None, scan_id=None, stats=None):
        self.original_url = self.url = _normalize_url(url)
        self.cookie       = cookie
        self.final_url    = None
        self.Get_Response = self.Get_Request = None
        self.scan_id      = scan_id or datetime.now().strftime('%Y%m%d_%H%M%S')
        self._analysis_cache = {}
        self._last_response = None
        self._request_headers = {**UA, **({'Cookie': self.cookie} if self.cookie else {})}
        
        # Database Initialization
        self.db = DatabaseManager()
        _create_scan_direct(self.db, self.scan_id, self.original_url, UA['User-Agent'], self.cookie)
        
        # استخدام إحصائيات موحدة إذا تم تمريرها، وإلا إنشاء نسخة جديدة
        self.stats = stats if stats else ScanStats(self.scan_id)
        if not stats: 
            self.stats.add('scans', 1)
        
        self.redirect_chain: list = []
        self.cookies:        list = []
        self.headers:        list = []

    # -- Proxy --------------------------------------------------------------
    def _find_proxy(self):
        manual_proxy = os.getenv("SMART_HUNTER_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        if manual_proxy:
            return manual_proxy

        if not _env_bool("SMART_HUNTER_AUTO_PROXY", False):
            return None

        if _PROXY_CACHE["checked"]:
            return _PROXY_CACHE["value"]

        for port in (8080, 8081):
            proxy_url = f"http://127.0.0.1:{port}"
            try:
                with httpx.Client(proxy=proxy_url, timeout=2.0, verify=False, trust_env=False) as client:
                    client.get("http://example.com", timeout=2.0)
                _PROXY_CACHE["checked"] = True
                _PROXY_CACHE["value"] = proxy_url
                print(f"[+] Proxy detected on port {port}")
                return proxy_url
            except Exception:
                continue

        _PROXY_CACHE["checked"] = True
        _PROXY_CACHE["value"] = None
        return None

    def _build_client(self, follow_redirects=False):
        proxy = self._find_proxy()
        params = {
            "timeout": httpx.Timeout(HTTP_TIMEOUT),
            "follow_redirects": follow_redirects,
            "verify": False,
            "http2": True,
            "headers": self._request_headers,
            "cookies": self.get_cookies_for_requests() if self.cookies else None,
            "limits": httpx.Limits(max_connections=20, max_keepalive_connections=10),
            "trust_env": not bool(proxy),
        }
        if proxy:
            params["proxy"] = proxy
        return httpx.Client(**params)

    def _get_waf_matches(self, response):
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        body_lower = (response.text or "")[:4000].lower()
        return [
            vendor for vendor, sigs in _WAF_SIGS.items()
            if any(sig in headers_lower or sig in headers_lower.get("set-cookie", "") or sig in body_lower for sig in sigs)
        ]

    # -- WAF detection ------------------------------------------------------
    def detect_waf(self, response):
        found = self._get_waf_matches(response)
        print(f"    [!] WAF/CDN: {', '.join(found)}" if found else "    [*] No WAF detected")
        return found

    # -- Security header audit ----------------------------------------------
    def print_security_summary(self, response):
        present = 0
        print("\n" + "="*65 + "\n  SECURITY HEADERS AUDIT\n" + "="*65)
        for h in _SEC_HEADERS:
            if h in response.headers:
                print(f"  [OK]   {h}: {response.headers[h][:60]}")
                present += 1
            else:
                print(f"  [MISS] {h}")
        grade = "A" if present >= 7 else "B" if present >= 5 else "C" if present >= 3 else "F"
        print(f"{'='*65}\n  Score: {present}/{len(_SEC_HEADERS)}  Grade: {grade}\n{'='*65}\n")
        return present

    # ── Redirect tracker ───────────────────────────────────────────────────
    def track_redirects(self, url):
        current = _normalize_url(url or self.original_url)
        count = 0
        self.redirect_chain = [{'url': current, 'type': 'ORIGINAL'}]
        self.cookies = []
        self.headers = []

        try:
            with self._build_client(follow_redirects=False) as c:
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

                    self._last_response = resp
                    self._grab_cookies(resp, current)
                    self._grab_headers(resp, current)
                    print(f"    [{count+1}] {current} → {resp.status_code}")
                    
                    # DB: Save features for each hop via q_features directly
                    features = self.extract_recon_features(resp, current, is_redirect=True)
                    _save_features_direct(self.db, features)
                    self.stats.add('features', 1)
                    try:
                        append_target_scan_row(
                            features,
                            target_url=self.original_url,
                            scan_id=self.scan_id,
                            record_type="recon_redirect_hop",
                        )
                    except Exception as e:
                        print(f"    [-] Target scan dataset update skipped: {e}")
                    
                    # DB: Save redirect hop via q_redirects directly
                    from Data.Queries.q_redirects import save_redirect_hop
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

    # ── Redirect reporting ─────────────────────────────────────────────────
    def save_redirect_analysis(self):
        if len(self.redirect_chain) <= 1: return
        domains = {urlparse(s['url']).netloc for s in self.redirect_chain if 'url' in s}
        upgraded = (self.original_url.startswith('http://') and
                    bool(self.final_url) and self.final_url.startswith('https://'))
        lines = [
            "REDIRECT CHAIN ANALYSIS", "="*50,
            f"Original : {self.original_url}",
            f"Final    : {self.final_url or 'N/A'}",
            f"Hops     : {len(self.redirect_chain)-2}",
            "", "CHAIN:",
        ]
        for i, s in enumerate(self.redirect_chain):
            if i == 0:
                lines.append(f"  {i+1}. ORIGINAL: {s['url']}")
            elif 'status_code' in s:
                lines.append(f"  {i+1}. {s['status_code']}: {s['url']} → {s.get('location','')}")
            else:
                lines.append(f"  {i+1}. FINAL: {s['url']} ({s.get('status','')})")
        lines += ["", "SECURITY:",
                  f"  Domains     : {len(domains)} ({', '.join(domains)})",
                  f"  HTTP→HTTPS  : {'Yes' if upgraded else 'No'}"]

        content = "\n".join(lines)
        save_report(self.db, self.scan_id, 'redirect_analysis', content)
        print(f"[+] Redirect analysis saved to DB")

        save_report(self.db, self.scan_id, 'redirect_chain', self.redirect_chain)
        print(f"[+] Redirect chain saved to DB")

    def print_redirect_summary(self):
        if len(self.redirect_chain) <= 1: return
        print(f"\n{'='*60}\nREDIRECT SUMMARY\n{'='*60}")
        print(f"  {self.original_url}  →  {self.final_url}  ({len(self.redirect_chain)-2} hops)")
        for i, s in enumerate(self.redirect_chain):
            if 'status_code' in s:
                print(f"  {i+1}. [{s['status_code']}] {s['url']} → {s.get('location','')}")
            else:
                print(f"  {i+1}. {'START' if i==0 else 'FINAL'}: {s['url']}")
        print("="*60)

    # ── Feature extraction ─────────────────────────────────────────────────
    @staticmethod
    def _ct(content_type):
        ct = content_type.lower()
        return next((v for k, v in _CONTENT_TYPES.items() if k in ct), 'other')

    @staticmethod
    def _count(compiled_regex_or_pattern, text):
        if isinstance(compiled_regex_or_pattern, str):
            return len(re.findall(compiled_regex_or_pattern, text, re.IGNORECASE))
        return len(compiled_regex_or_pattern.findall(text))

    def _analyze_html_document(self, html, base_url, content_type=""):
        body = html or ""
        key = f"{base_url}|{len(body)}|{hash(body[:4096])}"
        cached = self._analysis_cache.get(key)
        if cached is not None:
            return cached

        analysis = {
            'forms': [],
            'get_params': [],
            'post_params': [],
            'buttons': [],
            'links': [],
            'inputs': [],
            'endpoints': [],
            'password_count': 0,
            'hidden_count': 0,
            'file_upload_count': 0,
            'search_count': 0,
            'email_input_count': 0,
            'url_input_count': 0,
            'textarea_count': 0,
            'select_count': 0,
            'button_count': 0,
            'link_count': 0,
            'image_count': 0,
            'meta_count': 0,
            'stylesheet_count': 0,
            'script_count': 0,
            'inline_script_count': 0,
            'internal_script_count': 0,
            'external_script_count': 0,
            'internal_link_count': 0,
            'external_link_count': 0,
            'same_origin_form_count': 0,
            'external_form_count': 0,
            'get_form_count': 0,
            'post_form_count': 0,
            'login_form_count': 0,
            'csrf_token_input_count': 0,
            'unique_input_names': 0,
            'unique_endpoint_count': 0,
            'parameterized_link_count': 0,
            'api_like_endpoint_count': 0,
            'inline_event_handler_count': 0,
            'mailto_link_count': 0,
            'tel_link_count': 0,
            'comment_count': len(_RE_COMMENT.findall(body[:MAX_ANALYSIS_BYTES])),
            'has_title': 0,
            'analysis_truncated': int(len(body) > MAX_ANALYSIS_BYTES),
        }

        is_html = "html" in (content_type or "").lower() or "<html" in body[:1000].lower() or "<form" in body[:1000].lower()
        if not is_html:
            self._analysis_cache[key] = analysis
            return analysis

        snippet = body[:MAX_ANALYSIS_BYTES]
        soup = BeautifulSoup(snippet, "html.parser")
        input_names = []

        for tag in soup.find_all(True):
            analysis['inline_event_handler_count'] += sum(
                1 for attr_name in tag.attrs.keys() if str(attr_name).lower().startswith("on")
            )

        field_tags = soup.find_all(["input", "textarea", "select"])
        for field in field_tags:
            tag_name = field.name.lower()
            field_type = (field.get("type") or tag_name or "text").lower()
            name = (field.get("name") or "").strip()
            field_info = {
                'type': field_type,
                'name': name,
                'id': field.get("id"),
            }
            analysis['inputs'].append(field_info)
            if name:
                input_names.append(name)
            if field_type == "password":
                analysis['password_count'] += 1
            if field_type == "hidden":
                analysis['hidden_count'] += 1
            if field_type == "file":
                analysis['file_upload_count'] += 1
            if field_type == "search" or (name and name.lower() in {"search", "q", "query"}):
                analysis['search_count'] += 1
            if field_type == "email":
                analysis['email_input_count'] += 1
            if field_type == "url":
                analysis['url_input_count'] += 1
            if tag_name == "textarea":
                analysis['textarea_count'] += 1
            if tag_name == "select":
                analysis['select_count'] += 1
            if name and _RE_TOKEN_NAME.search(name):
                analysis['csrf_token_input_count'] += 1

        for form in soup.find_all("form"):
            action_raw = (form.get("action") or "").strip()
            action = _normalize_candidate_url(base_url, action_raw) or base_url
            method = (form.get("method") or "GET").upper()
            form_inputs = []
            has_password = False
            has_file = False
            has_hidden = False

            for field in form.find_all(["input", "textarea", "select"]):
                field_type = (field.get("type") or field.name or "text").lower()
                name = (field.get("name") or "").strip()
                if name:
                    form_inputs.append(name)
                has_password = has_password or field_type == "password"
                has_file = has_file or field_type == "file"
                has_hidden = has_hidden or field_type == "hidden"

            normalized_inputs = _ordered_unique(form_inputs)
            form_entry = {
                'action': action,
                'method': method,
                'inputs': normalized_inputs,
                'has_password': has_password,
                'has_file': has_file,
                'has_hidden': has_hidden,
            }
            analysis['forms'].append(form_entry)
            analysis['endpoints'].append(action)

            if method == "POST":
                analysis['post_form_count'] += 1
                analysis['post_params'].extend(normalized_inputs)
            else:
                analysis['get_form_count'] += 1
                analysis['get_params'].extend(normalized_inputs)

            if _same_scope_url(action, base_url):
                analysis['same_origin_form_count'] += 1
            else:
                analysis['external_form_count'] += 1

            if has_password or any(_RE_LOGIN_HINT.search(item or "") for item in normalized_inputs) or _RE_LOGIN_HINT.search(action_raw or ""):
                analysis['login_form_count'] += 1

        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = (tag.get("href") or "").strip()
            if not href:
                continue
            lowered = href.lower()
            if lowered.startswith("mailto:"):
                analysis['mailto_link_count'] += 1
                continue
            if lowered.startswith("tel:"):
                analysis['tel_link_count'] += 1
                continue
            full_url = _normalize_candidate_url(base_url, href)
            if not full_url:
                continue
            analysis['links'].append(full_url)
            analysis['endpoints'].append(full_url)
            if _same_scope_url(full_url, base_url):
                analysis['internal_link_count'] += 1
            else:
                analysis['external_link_count'] += 1
            if parse_qs(urlparse(full_url).query):
                analysis['parameterized_link_count'] += 1
            path = urlparse(full_url).path.lower()
            if "/api/" in path or path.endswith(".json"):
                analysis['api_like_endpoint_count'] += 1

        for script in soup.find_all("script"):
            src = (script.get("src") or "").strip()
            if src:
                full_src = _normalize_candidate_url(base_url, src)
                if full_src:
                    analysis['endpoints'].append(full_src)
                    if _same_scope_url(full_src, base_url):
                        analysis['internal_script_count'] += 1
                    else:
                        analysis['external_script_count'] += 1
            else:
                analysis['inline_script_count'] += 1

        for button in soup.find_all("button"):
            analysis['buttons'].append({
                'type': (button.get("type") or "button").lower(),
                'content': " ".join(button.stripped_strings),
            })
        for field in soup.find_all("input"):
            if (field.get("type") or "").lower() in {"button", "submit"}:
                analysis['buttons'].append({
                    'type': (field.get("type") or "button").lower(),
                    'value': field.get("value"),
                    'name': field.get("name"),
                })

        analysis['image_count'] = len(soup.find_all("img"))
        analysis['meta_count'] = len(soup.find_all("meta"))
        analysis['stylesheet_count'] = sum(
            1 for link in soup.find_all("link")
            if "stylesheet" in " ".join(link.get("rel", [] if link.get("rel") is None else link.get("rel"))).lower()
        )
        analysis['has_title'] = int(bool(soup.title and soup.title.get_text(strip=True)))
        analysis['script_count'] = analysis['inline_script_count'] + analysis['internal_script_count'] + analysis['external_script_count']
        analysis['button_count'] = len(analysis['buttons'])
        analysis['link_count'] = len(analysis['links'])
        analysis['get_params'] = _ordered_unique(analysis['get_params'])
        analysis['post_params'] = _ordered_unique(analysis['post_params'])
        analysis['links'] = _ordered_unique(analysis['links'])
        analysis['endpoints'] = _ordered_unique(analysis['endpoints'])
        analysis['unique_input_names'] = len(set(name for name in input_names if name))
        analysis['unique_endpoint_count'] = len(analysis['endpoints'])

        self._analysis_cache[key] = analysis
        return analysis

    def extract_recon_features(self, response, url, is_redirect=False):
        try:
            parsed_url = urlparse(url)
            headers = response.headers
            body = response.text or ""
            body_lower = body.lower()
            content_type = headers.get('Content-Type', '')
            dom = self._analyze_html_document(body, url, content_type=content_type)
            waf_found = self._get_waf_matches(response)
            server_header = headers.get('Server', '')
            server_lower = server_header.lower()
            powered_by = headers.get('X-Powered-By', '').lower()
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            reflected_params = sum(
                1 for values in query_params.values() for value in values
                if len(value) > 2 and value.lower() in body_lower
            )

            cookie_headers = headers.get_list('set-cookie') if hasattr(headers, 'get_list') else ([headers.get('set-cookie')] if headers.get('set-cookie') else [])
            num_set_cookies = len(cookie_headers)
            secure_cookies = sum(1 for item in cookie_headers if item and 'secure' in item.lower())
            httponly_cookies = sum(1 for item in cookie_headers if item and 'httponly' in item.lower())
            samesite_cookies = sum(
                1 for item in cookie_headers
                if item and ('samesite=strict' in item.lower() or 'samesite=lax' in item.lower() or 'samesite=none' in item.lower())
            )
            jwt_count = len(_RE_JWT.findall(body))
            api_key_count = len(_RE_API_KEY.findall(body))

            features = {
                'url_length':        len(url),
                'has_https':         int(url.startswith('https')),
                'path_depth':        len([x for x in parsed_url.path.split('/') if x]),
                'has_query_params':  int(bool(parsed_url.query)),
                'num_query_params':  len(query_params),
                'has_fragment':      int(bool(parsed_url.fragment)),
                'has_port':          int(bool(parsed_url.port)),
                'subdomain_count':   max(0, len(parsed_url.netloc.split('.'))-2),
                'is_ip_address':     _is_ip_address(parsed_url.hostname or parsed_url.netloc),
                'domain_length':     len(parsed_url.netloc),
                'domain_has_hyphens':int('-' in parsed_url.netloc),
                'domain_tld':        parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else 'unknown',
                'status_code':       response.status_code,
                'status_category':   response.status_code // 100,
                'response_size':     len(body),
                'response_time_ms':  getattr(response, 'elapsed', None) and response.elapsed.total_seconds()*1000 or 0,
                'is_redirect':       int(is_redirect),
                'redirect_chain_len':len(self.redirect_chain),
                'total_headers':         len(headers),
                'server_header_present': int('Server' in headers),
                'server_header':         server_header.split('/')[0] if server_header else 'unknown',
                'x_powered_by_present':  int('X-Powered-By' in headers),
                'content_type':          self._ct(content_type),
                'has_cookies':           int('Set-Cookie' in headers),
                'num_cookies':           len(response.cookies),
                'has_cors':              int('Access-Control-Allow-Origin' in headers),
                'cache_control':         int('Cache-Control' in headers),
                'security_headers_count':sum(1 for item in _SEC_HEADERS if item in headers),
                'has_csp':               int('Content-Security-Policy' in headers),
                'has_hsts':              int('Strict-Transport-Security' in headers),
                'has_xss_protection':    int('X-XSS-Protection' in headers),
                'has_frame_options':     int('X-Frame-Options' in headers),
                'has_content_type_options': int('X-Content-Type-Options' in headers),
                'has_forms':    int(bool(dom['forms'])),
                'form_count':   len(dom['forms']),
                'has_inputs':   int(bool(dom['inputs'])),
                'input_count':  len(dom['inputs']),
                'has_password_input': int(dom['password_count'] > 0),
                'password_count': dom['password_count'],
                'has_hidden_input': int(dom['hidden_count'] > 0),
                'hidden_count': dom['hidden_count'],
                'has_file_upload': int(dom['file_upload_count'] > 0),
                'file_upload_count': dom['file_upload_count'],
                'has_search_input': int(dom['search_count'] > 0),
                'search_count': dom['search_count'],
                'has_buttons':  int(dom['button_count'] > 0),
                'button_count': dom['button_count'],
                'has_textarea': int(dom['textarea_count'] > 0),
                'textarea_count': dom['textarea_count'],
                'has_select':   int(dom['select_count'] > 0),
                'select_count': dom['select_count'],
                'has_scripts':  int(dom['script_count'] > 0),
                'script_count': dom['script_count'],
                'inline_script_count': dom['inline_script_count'],
                'internal_script_count': dom['internal_script_count'],
                'external_script_count': dom['external_script_count'],
                'has_links':    int(dom['link_count'] > 0),
                'link_count':   dom['link_count'],
                'internal_link_count': dom['internal_link_count'],
                'external_link_count': dom['external_link_count'],
                'has_images':   int(dom['image_count'] > 0),
                'image_count':  dom['image_count'],
                'has_meta_tags':int(dom['meta_count'] > 0),
                'meta_count':   dom['meta_count'],
                'has_stylesheets': int(dom['stylesheet_count'] > 0),
                'stylesheet_count': dom['stylesheet_count'],
                'has_javascript': int(dom['script_count'] > 0 or dom['inline_event_handler_count'] > 0 or 'javascript:' in body_lower),
                'has_comments': int(dom['comment_count'] > 0),
                'comment_count': dom['comment_count'],
                'has_title':    dom['has_title'],
                'server_apache':    int('apache' in server_lower),
                'server_nginx':     int('nginx' in server_lower),
                'server_iis':       int('iis' in server_lower or 'microsoft' in server_lower),
                'tech_php':         int('php' in powered_by or '.php' in body_lower),
                'tech_aspnet':      int('asp.net' in powered_by or '.aspx' in body_lower),
                'tech_jsp':         int('.jsp' in body_lower),
                'tech_wordpress':   int('wp-content' in body_lower or 'wordpress' in body_lower),
                'tech_drupal':      int('drupal' in body_lower),
                'tech_joomla':      int('joomla' in body_lower),
                'has_debug_info':   int(bool(_RE_DEBUG_INFO.search(body_lower))),
                'has_error_messages': int(bool(_RE_ERROR_MSG.search(body_lower))),
                'has_sql_errors':   int(bool(_RE_SQL_ERR.search(body_lower))),
                'has_file_paths':   int(bool(_RE_FILE_PATHS.search(body))),
                'has_waf':          int(bool(waf_found)),
                'waf_cloudflare':   int('Cloudflare' in waf_found),
                'waf_aws':          int('AWS WAF' in waf_found),
                'waf_imperva':      int('Imperva' in waf_found),
                'reflection_detected': int(reflected_params > 0),
                'csp_header_reflection_detected': int(any(
                    value.lower() in headers.get('Content-Security-Policy', '').lower()
                    for values in query_params.values() for value in values if len(value) > 2
                )),
                'has_jwt':          int(jwt_count > 0),
                'jwt_count':        jwt_count,
                'has_api_keys':     int(api_key_count > 0),
                'api_key_count':    api_key_count,
                'cookie_count':    len(self.cookies),
                'session_cookies': sum(1 for k in self.cookies if 'session' in k.get('name','').lower()),
                'secure_cookie_ratio': _safe_ratio(secure_cookies, num_set_cookies),
                'httponly_cookie_ratio': _safe_ratio(httponly_cookies, num_set_cookies),
                'samesite_cookie_ratio': _safe_ratio(samesite_cookies, num_set_cookies),
                'redirect_count':      max(0, len(self.redirect_chain)-1),
                'has_redirect_chain':  int(len(self.redirect_chain) > 1),
                'final_https':         int(bool(self.final_url) and self.final_url.startswith('https')),
                'get_form_count': dom['get_form_count'],
                'post_form_count': dom['post_form_count'],
                'has_login_form': int(dom['login_form_count'] > 0),
                'login_form_count': dom['login_form_count'],
                'csrf_token_input_count': dom['csrf_token_input_count'],
                'has_csrf_token': int(dom['csrf_token_input_count'] > 0),
                'same_origin_form_count': dom['same_origin_form_count'],
                'external_form_count': dom['external_form_count'],
                'unique_input_names': dom['unique_input_names'],
                'unique_endpoint_count': dom['unique_endpoint_count'],
                'parameterized_link_count': dom['parameterized_link_count'],
                'api_like_endpoint_count': dom['api_like_endpoint_count'],
                'inline_event_handler_count': dom['inline_event_handler_count'],
                'email_input_count': dom['email_input_count'],
                'url_input_count': dom['url_input_count'],
                'mailto_link_count': dom['mailto_link_count'],
                'tel_link_count': dom['tel_link_count'],
                'body_truncated_for_analysis': dom['analysis_truncated'],
                'input_to_form_ratio': _safe_ratio(len(dom['inputs']), len(dom['forms'])),
                'script_to_content_ratio': _safe_ratio(dom['script_count'], max(len(body), 1)),
                'security_score': _safe_ratio(sum(1 for item in _SEC_HEADERS if item in headers), len(_SEC_HEADERS)),
                'interactivity_score': _safe_ratio(len(dom['forms']) + len(dom['inputs']) + dom['button_count'], max(len(body) / 1000, 1)),
                'is_vulnerable':      0,
                'vulnerability_type': '',
                'scan_id':    self.scan_id,
                'timestamp':  datetime.now().isoformat(),
                'target_url': url,
                'original_url': self.original_url,
                'is_redirect_response': is_redirect,
                'final_url':  self.final_url or url,
            }

            return features

        except Exception as e:
            print(f"[-] Feature extraction error: {e}")
            return {'scan_id': self.scan_id, 'timestamp': datetime.now().isoformat(),
                    'target_url': url, 'original_url': self.original_url,
                    'status_code': getattr(response, 'status_code', 0), 'error_occurred': 1}

    # ── ML dataset ─────────────────────────────────────────────────────────
    def save_ml_dataset(self, features, update_training=True, target_url=None):
        global _RECON_DATASET_COLUMNS_CACHE

        if features.get('error_occurred'):
            return
        
        # DB: Save features directly via q_features
        _save_features_direct(self.db, features)
        self.stats.add('features', 1)
        print(f"[+] Features saved to DB — status:{features.get('status_code')}")

        try:
            target_dataset = append_target_scan_row(
                features,
                target_url=target_url or self.original_url,
                scan_id=self.scan_id,
                record_type="recon_page",
            )
            if target_dataset:
                print(f"[+] Target scan dataset updated -> {target_dataset}")
        except Exception as e:
            print(f"[-] Target scan dataset update error: {e}")

        if not update_training:
            return

        try:
            with DATASET_LOCK:
                os.makedirs(os.path.dirname(ML_DATASET_FILE), exist_ok=True)
                file_exists = os.path.exists(ML_DATASET_FILE) and os.path.getsize(ML_DATASET_FILE) > 0
                columns = list(_RECON_DATASET_COLUMNS_CACHE or [])

                if not columns:
                    columns = pd.read_csv(ML_DATASET_FILE, nrows=0).columns.tolist() if file_exists else list(features.keys())

                new_columns = [col for col in features.keys() if col not in columns]
                if file_exists and new_columns:
                    existing = pd.read_csv(ML_DATASET_FILE)
                    for col in new_columns:
                        existing[col] = 0
                    columns = columns + new_columns
                    existing.to_csv(ML_DATASET_FILE, index=False)
                elif not file_exists:
                    columns = list(features.keys())

                _RECON_DATASET_COLUMNS_CACHE = columns
                row = {col: features.get(col, 0) for col in columns}
                pd.DataFrame([row], columns=columns).to_csv(
                    ML_DATASET_FILE,
                    mode='a',
                    header=not file_exists,
                    index=False,
                )
            print(f"[+] Recon dataset updated -> {ML_DATASET_FILE}")
        except Exception as e:
            print(f"[-] Recon dataset update error: {e}")

    # ── Request/Response display ───────────────────────────────────────────
    def print_request_response_details(self, response, url, is_final=True):
        try:
            p   = urlparse(url)
            pq  = (p.path or '/') + (f'?{p.query}' if p.query else '')
            tag = "FINAL" if is_final else "REDIRECT"
            print(f"\n{'='*60}\n{tag} REQUEST:\n{'='*60}")
            print(f"{response.request.method} {pq} HTTP/1.1\nHost: {p.hostname}")
            for k, v in response.request.headers.items():
                if k.lower() != 'host': print(f"{k}: {v}")
            print(f"\n{'='*60}\n{tag} RESPONSE {response.status_code}:\n{'='*60}")
            for k, v in response.headers.items(): print(f"{k}: {v}")
            body = response.text or ""
            print(f"\nBody ({len(body)} bytes):\n{body[:500]}{'...' if len(body)>500 else ''}\n{'='*60}")
            
            # DB: Save raw response directly via q_raw_responses
            save_raw_response(self.db, self.scan_id, url, response.status_code, body, response.headers)
            self.stats.add('raw_responses', 1)
            
            if is_final:
                self.Get_Response = response.text
                self.Get_Request  = f"{response.request.method} {pq} HTTP/1.1\nHost: {p.hostname}\n" + \
                                    "\n".join(f"{k}: {v}" for k,v in response.request.headers.items() if k.lower()!='host')
            self.save_ml_dataset(self.extract_recon_features(response, url, is_redirect=not is_final))
        except Exception as e:
            print(f"[-] Display error: {e}")

    def Get_Target_From_Response(self):
        if not self.Get_Response: print("[-] No response yet"); return
        save_report(self.db, self.scan_id, 'response_content', self.Get_Response)
        print(f"[+] Response content saved to DB")

    def Get_Target_From_Request(self):
        if not self.Get_Request: print("[-] No request yet"); return
        save_report(self.db, self.scan_id, 'request_headers', self.Get_Request)
        print(f"[+] Request headers saved to DB")

    # ── Response analysis ──────────────────────────────────────────────────
    def Analyze_Response(self, url):
        if not self.Get_Response: print("[-] No response to analyze"); return None
        html = self.Get_Response
        analysis = self._analyze_html_document(html, url, content_type="text/html")
        params = {
            'url': url,
            'forms': analysis['forms'],
            'get_params': analysis['get_params'],
            'post_params': analysis['post_params'],
            'buttons': analysis['buttons'],
            'links': analysis['links'],
            'inputs': analysis['inputs'],
            'endpoints': analysis['endpoints'],
            'cookies': self.get_cookies_for_requests(),
        }
        print(f"[+] Analysis: {len(params['forms'])} forms, {len(params['links'])} links, "
              f"{len(params['inputs'])} inputs, {len(params['endpoints'])} endpoints")
        self._save_analysis(params, url)
        return params

    def _parse_form(self, html):
        action_match = re.search(r'action\s*=\s*[\'"]([^\'"]*)[\'"]', html, re.I)
        method_match = re.search(r'method\s*=\s*[\'"]\s*(\w+)\s*[\'"]', html, re.I)
        return {
            'action': action_match.group(1) if action_match else '',
            'method': (method_match.group(1) if method_match else 'GET').upper(),
            'inputs': list(set(re.findall(r'<(?:input|textarea|select)[^>]*name\s*=\s*[\'"]([^\'"]+)[\'"]', html, re.I))),
        }

    def _extract_buttons(self, html):
        out = []
        for b in re.findall(r'<button[^>]*>(.*?)</button>', html, re.I|re.S):
            out.append({'type':'button','content':re.sub(r'<[^>]+>','',b).strip()})
        for t in re.findall(r'<input[^>]*type=[\'"](?:button|submit)[\'"][^>]*>', html, re.I):
            out.append({'type': self._attr(t,'type'), 'value': self._attr(t,'value'), 'name': self._attr(t,'name')})
        return out

    @staticmethod
    def _attr(tag, attr):
        m = re.search(rf'{attr}\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        return m.group(1) if m else None

    def Analyze_Request(self):
        if not self.Get_Request: print("[-] No request to analyze"); return
        lines = [line for line in self.Get_Request.splitlines() if line.strip()]
        request_line = lines[0] if lines else ""
        headers = [line for line in lines[1:] if ":" in line]
        interesting = [
            line for line in headers
            if line.lower().startswith(("host:", "cookie:", "authorization:", "referer:", "origin:", "user-agent:", "accept:"))
        ]
        print(f"[+] Request summary: {request_line}")
        print(f"[+] Request headers captured: {len(headers)}")
        for line in interesting[:10]:
            print(f"    {line}")

    def _save_analysis(self, params, url):
        # 1. Response Analysis Summary
        lines = [f"TARGET: {url}", "="*50]
        for form in params['forms']:
            lines.append(f"\nForm [{form['method']}] {form['action']}: {form['inputs']}")
        for link in params['links'][:50]:
            lines.append(f"Link: {link}")
        lines.append("")
        lines.append(f"GET params : {len(params['get_params'])}")
        lines.append(f"POST params: {len(params['post_params'])}")
        lines.append(f"Endpoints  : {len(params['endpoints'])}")
        
        save_report(self.db, self.scan_id, 'response_analysis', "\n".join(lines))

        # 2. XSS Parameters / Endpoints
        content = f"# Target: {url}\nGET: {params['get_params']}\nPOST: {params['post_params']}\n" + "ENDPOINTS:\n" + "\n".join(params['endpoints'])
        save_report(self.db, self.scan_id, 'xss_parameters', content)
        
        # DB: Save findings
        from Data.Queries.q_forms import save_forms
        from Data.Queries.q_endpoints import save_endpoints
        n_forms = save_forms(self.db, self.scan_id, url, params['forms'])
        n_endpoints = save_endpoints(self.db, self.scan_id, url, params['endpoints'], source='response_html')
        self.stats.add('forms', n_forms).add('endpoints', n_endpoints)

        print(f"[+] Analysis saved to DB")

    # ── Shell helpers ──────────────────────────────────────────────────────
    def _run_script(self, script, *args, save_file=None,
                    timeout=180, show_keywords=None):

        if not os.path.exists(script):
            print(f"    [-] Script not found: {script}"); return None

        _DEFAULT_SHOW = ('error', '[-]', '[!]', '[+]', '[*]', 'found',
                         'discovered', 'saved', 'done', 'complete',
                         'url', 'subdomain', 'param')
        kw = show_keywords if show_keywords is not None else _DEFAULT_SHOW

        lines = []
        try:
            # Use 'bash' directly as the user is running in a Linux/WSL environment
            cmd = ['bash', script, *[str(a) for a in args]]
            
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                bufsize=1,
            )
            deadline = time.time() + timeout if timeout else None
            for raw in proc.stdout:
                line = raw.rstrip()
                if line:
                    lines.append(line)
                    ll = line.lower()
                    if kw and any(k in ll for k in kw):
                        print(f"    {line}")
                if deadline and time.time() > deadline:
                    print(f"    [!] Timeout ({timeout}s) — killing script")
                    proc.terminate()
                    break
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception as e:
            print(f"    [-] Script error: {e}")
            return None

        if lines:
            print(f"    [+] Script execution finished ({len(lines)} lines of output)")
        return lines or None

    def _normalize_in_scope_urls(self, values, base_url):
        normalized = []
        for item in values or []:
            text = (item or "").strip()
            if not text:
                continue
            candidate = _normalize_url(text) if text.startswith(("http://", "https://")) else _normalize_candidate_url(base_url, text)
            if candidate and _same_scope_url(candidate, base_url):
                normalized.append(candidate)
        return _ordered_unique(normalized)

    def _get_subdomain(self, url):
        print(f"\n[*] Subdomain discovery: {url}")
        res = self._run_script(os.path.join(SCRIPT_DIR, "get_subdomain.sh"), url, timeout=120)
        if res:
            subs = []
            target_host = urlparse(url).hostname or ""
            for line in res:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                candidate = (parts[-1] if parts else line).strip().strip("[](),").lower()
                if '.' in candidate and not candidate.startswith('-') and len(candidate) > 3 and _same_scope_host(candidate, target_host):
                    subs.append(candidate)
            subs = _ordered_unique(subs)
            if subs:
                print(f"    [+] Saving {len(subs)} subdomains to DB")
                n = save_subdomains(self.db, self.scan_id, subs)
                self.stats.add('subdomains', n)
            else:
                print("    [-] No valid subdomains parsed from script output")
        return res

    def _get_URLs(self, url):
        print(f"\n[*] URL discovery: {url}")
        res = self._run_script(os.path.join(SCRIPT_DIR, "get_URLs.sh"), url, timeout=150)
        if res:
            urls = self._normalize_in_scope_urls(res, url)
            if urls:
                print(f"    [+] Saving {len(urls)} discovered URLs to DB")
                from Data.Queries.q_endpoints import save_endpoints
                n = save_endpoints(self.db, self.scan_id, url, urls, source='wayback/gau')
                self.stats.add('endpoints', n)
        return res

    def _get_Paramtes_xss(self, url):
        print(f"\n[*] Parameter discovery: {url}")
        res = self._run_script(os.path.join(SCRIPT_DIR, "get_parmtras.sh"), url, timeout=90)
        if res:
            from Data.Queries.q_parameters import save_discovered_parameters
            params_to_save = []
            seen = set()
            
            for line in res:
                line = line.strip()
                if not line:
                    continue
                candidate_url = _normalize_url(line) if line.startswith(("http://", "https://")) else _normalize_candidate_url(url, line)
                if not candidate_url or not _same_scope_url(candidate_url, url):
                    continue
                parsed = urllib.parse.urlparse(candidate_url)
                query_map = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if not query_map:
                    continue
                clean_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))
                for param_name in query_map.keys():
                    key = (clean_url, param_name, 'GET')
                    if key in seen:
                        continue
                    seen.add(key)
                    params_to_save.append({
                        'url': clean_url,
                        'parameter': param_name,
                        'method': 'GET',
                        'raw_line': line
                    })
            
            if params_to_save:
                print(f"    [+] Saving {len(params_to_save)} discovered parameters to DB")
                save_discovered_parameters(self.db, self.scan_id, params_to_save, source='get_parmtras.sh')
                self.stats.add('discovered_parameters', len(params_to_save))
            
            save_report(self.db, self.scan_id, 'discovered_parameters_raw', "\n".join(res))
        return res

    # ── Fuzzing ────────────────────────────────────────────────────────────
    def fuzz_url(self, base_url):
        print(f"\n[*] Fuzzing: {base_url}")
        script_path = os.path.join(SCRIPT_DIR, "fuzzing_command_Tools.sh")
        if not os.path.exists(script_path):
            print("[-] fuzzing_command_Tools.sh not found"); return None
            
        # No need to write fuzzing_Target.txt anymore as we pass as argument
        result = subprocess.run(['bash', script_path, base_url], capture_output=True, text=True)
        print(f"[*] Fuzz done (rc={result.returncode})")
        
        fuzzing = self.parse_ffuf_results(base_url)
        if fuzzing and fuzzing.get('raw'):
            # DB: Save fuzz results directly via q_fuzzing
            n = save_fuzz_results(self.db, self.scan_id, fuzzing['raw'])
            self.stats.add('fuzzing_results', n)
            
        if fuzzing and fuzzing.get('found_paths'):
            ans = robust_input("\nCheck found paths? (y/n): ", default='n')
            if ans == 'y':
                self.check_found_paths(base_url, fuzzing['found_paths'])
        return fuzzing

    def parse_ffuf_results(self, base_url, results_file=None):
        canonical_results = os.path.join(DATASET_DIR, "ffuf_results.json")
        search_paths = [results_file, canonical_results, "ffuf_results.json"] if results_file else [canonical_results, "ffuf_results.json"]
        for path in search_paths:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                try:
                    with open(path, encoding="utf-8", errors="ignore") as handle:
                        data = json.load(handle)
                    entries = [{'url': e['url'], 'status': e.get('status',0), 'length': e.get('length',0)}
                               for e in data.get('results', []) if e.get('url')]
                    for e in entries: print(f"    [{e['status']}] {e['url']} ({e['length']} B)")
                    print(f"[+] ffuf: {len(entries)} paths")
                    
                    # Save summary to DB as report
                    summary = f"# {base_url}\n" + "\n".join(f"[{e['status']}] {e['url']}" for e in entries)
                    save_report(self.db, self.scan_id, 'ffuf_summary', summary)
                    print(f"[+] ffuf summary saved to DB")
                    
                    return {'found_paths': [e['url'] for e in entries], 'raw': entries}
                except Exception as ex:
                    print(f"[-] ffuf parse error: {ex}")
        print("[-] No ffuf results found")
        return {'found_paths': [], 'raw': []}

    def check_found_paths(self, base_url, paths):
        paths = self._normalize_in_scope_urls(paths, base_url)
        print(f"\n[*] Verifying {len(paths)} paths...")
        if not paths:
            return

        def _verify(args):
            i, url = args
            try:
                r = client.get(url)
                print(f"  [{i}/{len(paths)}] {r.status_code} | {len(r.text):>8} B | {url}")
            except Exception as ex:
                print(f"  [{i}/{len(paths)}] ERROR: {ex}")

        with self._build_client(follow_redirects=True) as client:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(paths))) as executor:
                list(executor.map(_verify, enumerate(paths, 1)))

    # ── Cookie / header persistence ────────────────────────────────────────
    def save_cookies_and_headers(self):
        if self.cookies:
            save_report(self.db, self.scan_id, 'cookies_full', self.cookies)
            print(f"[+] All cookies saved to DB report")
        if self.headers:
            save_report(self.db, self.scan_id, 'headers_full', self.headers)
            print(f"[+] All headers saved to DB report")

    # ── Dataset stats ──────────────────────────────────────────────────────
    def show_dataset_stats(self):
        try:
            if not (os.path.exists(ML_DATASET_FILE) and os.path.getsize(ML_DATASET_FILE)):
                print("[!] No dataset yet"); return
            df = pd.read_csv(ML_DATASET_FILE)
            print(f"\n[+] Dataset: {len(df)} rows | {df['target_url'].nunique()} targets | "
                  f"avg size {df['response_size'].mean():.0f} B | {df['has_https'].mean():.1%} HTTPS")
        except Exception as e:
            print(f"[-] Dataset stats error: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# Module-level helpers
# ═══════════════════════════════════════════════════════════════════════════

def test_connection(url, cookie=None, scan_id=None, stats=None, recon=None):
    try:
        recon = recon or ReconWebSite(url, cookie=cookie, scan_id=scan_id, stats=stats)
        response = recon.track_redirects(recon.original_url)
        if response:
            print(f"[+] Reached: {recon.final_url}")
            recon.print_redirect_summary()
            recon.save_redirect_analysis()
            return response, recon
        print("[-] Could not reach target")
    except Exception as e:
        print(f"[-] Connection error: {e}")
    return None, None


def _legacy_MainRecon(url, cookie=None, scan_id=None, stats=None):
    try:
        print(f"[*] Starting reconnaissance for: {url}")
        recon = ReconWebSite(url, cookie=cookie, scan_id=scan_id, stats=stats)
        response, recon_obj = test_connection(url, cookie=cookie, scan_id=scan_id, stats=stats, recon=recon)

        if response and recon_obj:
            recon = recon_obj
            if stats:
                recon.stats = stats

            waf_vendors = recon.detect_waf(response)
            present = recon.print_security_summary(response)
            grade = "A" if present >= 7 else "B" if present >= 5 else "C" if present >= 3 else "F"

            print("\n[*] WAF check...")
            recon.print_request_response_details(response, recon.final_url, is_final=True)
            recon.Get_Target_From_Response()
            recon.Get_Target_From_Request()
            recon.Analyze_Response(recon.final_url)
            recon.Analyze_Request()
            recon.save_cookies_and_headers()
            
            _update_scan_status_direct(recon.db, recon.scan_id, 'completed', recon.final_url, 
                                        has_waf=bool(waf_vendors),
                                        waf_vendors=waf_vendors,
                                        grade=grade, score=present)
            recon.stats.update('scans', 1)

            # ── Run discovery tasks in parallel ──────────────────────────
            target = recon.final_url
            jobs = [
                ("subdomain", recon._get_subdomain),
                ("urls", recon._get_URLs),
                ("params", recon._get_Paramtes_xss),
            ]
            print("\n[*] Starting parallel discovery (subdomains + URLs + params)...")
            for t in tasks:
                t.daemon = True
                t.start()
            for t in tasks:
                t.join(timeout=200)
                if t.is_alive():
                    print(f"    [!] Task {t.name} still running — proceeding")
            
            # ── Fuzzing (Optional prompt) ────────────────────────────────
            ans = robust_input("\nFuzz with ffuf? (y/n): ", default='n')
                
            if ans == 'y':
                recon.fuzz_url(recon.final_url or recon.original_url)

            # Print summary ONLY if standalone (stats is None)
            if stats is None:
                recon.stats.print_summary()
                
                # Save stats to DB report (using buffer to capture print output)
                import io, sys
                old_stdout = sys.stdout
                sys.stdout = buf = io.StringIO()
                recon.stats.print_summary()
                sys.stdout = old_stdout
                save_report(recon.db, recon.scan_id, 'scan_stats', buf.getvalue())
                
                print(f"[+] Scan completed. Stats saved to DB.")
            else:
                print(f"[+] Recon phase complete.")

            recon.show_dataset_stats()

    except KeyboardInterrupt:
        print("\n[!] Cancelled")
    except Exception as e:
        import traceback
        print(f"[-] Error: {e}"); traceback.print_exc()
    return True


def MainRecon(url, cookie=None, scan_id=None, stats=None):
    try:
        print(f"[*] Starting reconnaissance for: {url}")
        recon = ReconWebSite(url, cookie=cookie, scan_id=scan_id, stats=stats)
        response, recon_obj = test_connection(url, cookie=cookie, scan_id=scan_id, stats=stats, recon=recon)

        if not response or not recon_obj:
            _update_scan_status_direct(recon.db, recon.scan_id, 'failed', None, has_waf=False, waf_vendors=None, grade=None, score=None)
            return False

        recon = recon_obj
        if stats:
            recon.stats = stats

        print("\n[*] WAF check...")
        waf_vendors = recon.detect_waf(response)
        present = recon.print_security_summary(response)
        grade = "A" if present >= 7 else "B" if present >= 5 else "C" if present >= 3 else "F"

        recon.print_request_response_details(response, recon.final_url, is_final=True)
        recon.Get_Target_From_Response()
        recon.Get_Target_From_Request()
        recon.Analyze_Response(recon.final_url)
        recon.Analyze_Request()
        recon.save_cookies_and_headers()

        _update_scan_status_direct(
            recon.db,
            recon.scan_id,
            'completed',
            recon.final_url,
            has_waf=bool(waf_vendors),
            waf_vendors=waf_vendors,
            grade=grade,
            score=present,
        )
        recon.stats.update('scans', 1)

        target = recon.final_url or recon.original_url
        jobs = [
            ("subdomain", recon._get_subdomain),
            ("urls", recon._get_URLs),
            ("params", recon._get_Paramtes_xss),
        ]
        print("\n[*] Starting parallel discovery (subdomains + URLs + params)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DISCOVERY_WORKERS, len(jobs))) as executor:
            future_map = {executor.submit(handler, target): name for name, handler in jobs}
            for future in concurrent.futures.as_completed(future_map):
                name = future_map[future]
                try:
                    future.result()
                    print(f"    [+] Discovery task complete: {name}")
                except Exception as ex:
                    print(f"    [-] Discovery task failed ({name}): {ex}")

        ans = robust_input("\nFuzz with ffuf? (y/n): ", default='n')
        if ans == 'y':
            recon.fuzz_url(target)

        if stats is None:
            recon.stats.print_summary()

            import io, sys
            old_stdout = sys.stdout
            sys.stdout = buf = io.StringIO()
            recon.stats.print_summary()
            sys.stdout = old_stdout
            save_report(recon.db, recon.scan_id, 'scan_stats', buf.getvalue())

            print(f"[+] Scan completed. Stats saved to DB.")
        else:
            print(f"[+] Recon phase complete.")

        recon.show_dataset_stats()
        return True

    except KeyboardInterrupt:
        print("\n[!] Cancelled")
    except Exception as e:
        import traceback
        print(f"[-] Error: {e}")
        traceback.print_exc()
    return False


if __name__ == "__main__":
    MainRecon(input("Enter URL: "))
