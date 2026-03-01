import re, json, os, time, subprocess, warnings, urllib.parse
import httpx, pandas as pd
from urllib.parse import parse_qs, urlparse, urljoin
from datetime import datetime

warnings.filterwarnings('ignore')

# ── Constants ──────────────────────────────────────────────────────────────
UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36'}
DATASET_DIR      = ""
ML_DATASET_FILE  = os.path.join(DATASET_DIR, "web_recon_ml_dataset.csv")
REQUEST_DELAY    = 0.4   # seconds between redirect hops
MAX_REDIRECTS    = 10

# ── WAF signatures ─────────────────────────────────────────────────────────
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


# ═══════════════════════════════════════════════════════════════════════════
class ReconWebSite:
# ═══════════════════════════════════════════════════════════════════════════

    def __init__(self, url):
        self.original_url = self.url = self.final_url = url
        self.final_url    = None
        self.Get_Response = self.Get_Request = None
        self.scan_id      = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.scan_dir     = os.path.join(DATASET_DIR, f"scan_{self.scan_id}")
        os.makedirs(self.scan_dir, exist_ok=True)
        self.redirect_chain: list = []
        self.cookies:        list = []
        self.headers:        list = []

    # ── Proxy ──────────────────────────────────────────────────────────────
    def _find_proxy(self):
        """Try Burp (8080) then ZAP (8081); return proxy URL or None."""
        for port in (8080, 8081):
            url = f"http://127.0.0.1:{port}"
            try:
                with httpx.Client(proxies=url, timeout=2.0, verify=False) as c:
                    c.get("http://example.com", timeout=2.0)
                print(f"[+] Proxy on port {port}")
                return url
            except Exception:
                pass
        print("[-] No proxy found")
        return None

    # ── WAF detection ──────────────────────────────────────────────────────
    def detect_waf(self, response):
        h    = {k.lower(): v.lower() for k, v in response.headers.items()}
        body = (response.text or "")[:4000].lower()
        found = [p for p, sigs in _WAF_SIGS.items()
                 if any(s in h or s in h.get("set-cookie","") or s in body for s in sigs)]
        print(f"    [!] WAF/CDN: {', '.join(found)}" if found else "    [*] No WAF detected")
        return found

    # ── Security header audit ──────────────────────────────────────────────
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
        proxy    = self._find_proxy()
        current  = url
        count    = 0
        self.redirect_chain = [{'url': url, 'type': 'ORIGINAL'}]
        self.cookies = []
        self.headers = []

        params = dict(timeout=10.0, follow_redirects=False, verify=False)
        if proxy:
            params['proxies'] = proxy
            print(f"[*] Using proxy: {proxy}")

        while count < MAX_REDIRECTS:
            if count:
                time.sleep(REQUEST_DELAY)
            try:
                with httpx.Client(**params) as c:
                    resp = c.get(current, headers=UA)
            except httpx.TimeoutException:
                print(f"    [-] Timeout: {current}"); break
            except Exception as e:
                print(f"    [-] Error: {e}"); break

            self._grab_cookies(resp, current)
            self._grab_headers(resp, current)
            print(f"    [{count+1}] {current} → {resp.status_code}")
            self.save_ml_dataset(self.extract_recon_features(resp, current, is_redirect=True))
            self.redirect_chain.append({'url': current, 'status_code': resp.status_code,
                                        'location': resp.headers.get('location','')})

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get('location')
                if not loc: break
                if loc.startswith('/'):
                    p = urlparse(current)
                    loc = f"{p.scheme}://{p.netloc}{loc}"
                elif not loc.startswith(('http://', 'https://')):
                    loc = urljoin(current, loc)
                current = loc; count += 1
            else:
                self.final_url = current
                self.redirect_chain.append({'url': current, 'type': 'FINAL', 'status': resp.status_code})
                return resp
        return None

    def _grab_cookies(self, response, url):
        for name, val in response.cookies.items():
            self.cookies.append({'name': name, 'value': val,
                                 'domain': urlparse(url).hostname, 'url': url,
                                 'timestamp': datetime.now().isoformat()})
            print(f"  Cookie: {name}={val}")

    def _grab_headers(self, response, url):
        self.headers.append({'url': url, 'status_code': response.status_code,
                             'headers': dict(response.headers),
                             'timestamp': datetime.now().isoformat()})

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

        tf = os.path.join(self.scan_dir, "redirect_analysis.txt")
        with open(tf, "w") as f: f.write("\n".join(lines))
        print(f"[+] Redirect analysis → {tf}")

        jf = os.path.join(self.scan_dir, "redirect_chain.json")
        with open(jf, "w") as f: json.dump(self.redirect_chain, f, indent=2)
        print(f"[+] Redirect JSON → {jf}")

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
    def _count(pattern, text):
        return len(re.findall(pattern, text, re.IGNORECASE))

    def extract_recon_features(self, response, url, is_redirect=False):
        try:
            p   = urlparse(url)
            h   = response.headers
            c   = (response.text or "").lower()
            srv = h.get('Server','').lower()
            pb  = h.get('X-Powered-By','').lower()

            def _has(tag):  return int(f'<{tag}' in c)
            def _cnt(tag):  return self._count(rf'<{tag}[^>]*>', c)

            # WAF detection
            waf_headers = {k.lower(): v.lower() for k, v in h.items()}
            waf_found = [vendor for vendor, sigs in _WAF_SIGS.items()
                         if any(s in waf_headers or s in waf_headers.get("set-cookie","") or s in c[:4000] for s in sigs)]

            # Input types
            password_count = self._count(r'<input[^>]*type=[\'"]password[\'"]', c)
            hidden_count = self._count(r'<input[^>]*type=[\'"]hidden[\'"]', c)
            file_upload_count = self._count(r'<input[^>]*type=[\'"]file[\'"]', c)
            search_count = self._count(r'<input[^>]*type=[\'"]search[\'"]', c) + self._count(r'<input[^>]*name=[\'"](?:search|q|query)[\'"]', c)

            # Internal vs External scripts/links
            scripts = re.findall(r'<script[^>]*src=[\'"]([^\'"]+)[\'"]', c)
            internal_scripts = sum(1 for src in scripts if not src.startswith('http') or p.netloc in src)
            external_scripts = len(scripts) - internal_scripts

            links = re.findall(r'<a[^>]*href=[\'"]([^\'"]+)[\'"]', c)
            internal_links = sum(1 for href in links if not href.startswith('http') or p.netloc in href)
            external_links = len(links) - internal_links

            # Cookies Security
            cookie_headers = getattr(h, 'get_list', lambda x: [h.get(x)] if h.get(x) else [])('set-cookie')
            num_set_cookies = len(cookie_headers)
            secure_cookies = sum(1 for ch in cookie_headers if 'secure' in ch.lower())
            httponly_cookies = sum(1 for ch in cookie_headers if 'httponly' in ch.lower())
            samesite_cookies = sum(1 for ch in cookie_headers if 'samesite=strict' in ch.lower() or 'samesite=lax' in ch.lower())

            secure_cookie_ratio = secure_cookies / num_set_cookies if num_set_cookies else 0.0
            httponly_cookie_ratio = httponly_cookies / num_set_cookies if num_set_cookies else 0.0
            samesite_cookie_ratio = samesite_cookies / num_set_cookies if num_set_cookies else 0.0

            # JWT / Secrets
            jwt_count = len(re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', response.text or ""))
            api_key_count = len(re.findall(r'(?i)(?:api_key|apikey|access_token|secret_key)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?', c))

            # Reflected Params
            query_params = parse_qs(p.query)
            reflected_params = sum(1 for param_vals in query_params.values() for v in param_vals if len(v) > 2 and v.lower() in c)

            features = {
                # URL
                'url_length':        len(url),
                'has_https':         int(url.startswith('https')),
                'path_depth':        len([x for x in p.path.split('/') if x]),
                'has_query_params':  int(bool(p.query)),
                'num_query_params':  len(parse_qs(p.query)),
                'has_fragment':      int(bool(p.fragment)),
                'has_port':          int(bool(p.port)),
                'subdomain_count':   max(0, len(p.netloc.split('.'))-2),
                'is_ip_address':     int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', p.netloc))),
                'domain_length':     len(p.netloc),
                'domain_has_hyphens':int('-' in p.netloc),
                'domain_tld':        p.netloc.split('.')[-1] if '.' in p.netloc else 'unknown',
                # Response
                'status_code':       response.status_code,
                'status_category':   response.status_code // 100,
                'response_size':     len(response.text or ''),
                'response_time_ms':  getattr(response, 'elapsed', None) and response.elapsed.total_seconds()*1000 or 0,
                'is_redirect':       int(is_redirect),
                'redirect_chain_len':len(self.redirect_chain),
                # Headers
                'total_headers':         len(h),
                'server_header_present': int('Server' in h),
                'server_header':         h.get('Server','unknown').split('/')[0],
                'x_powered_by_present':  int('X-Powered-By' in h),
                'content_type':          self._ct(h.get('Content-Type','')),
                'has_cookies':           int('Set-Cookie' in h),
                'num_cookies':           len(response.cookies),
                'has_cors':              int('Access-Control-Allow-Origin' in h),
                'cache_control':         int('Cache-Control' in h),
                'security_headers_count':sum(1 for s in _SEC_HEADERS if s in h),
                'has_csp':               int('Content-Security-Policy' in h),
                'has_hsts':              int('Strict-Transport-Security' in h),
                'has_xss_protection':    int('X-XSS-Protection' in h),
                'has_frame_options':     int('X-Frame-Options' in h),
                'has_content_type_options': int('X-Content-Type-Options' in h),
                # HTML elements
                'has_forms':    _has('form'), 'form_count':     _cnt('form'),
                'has_inputs':   _has('input'),'input_count':    _cnt('input'),
                'has_password_input': int(password_count > 0), 'password_count': password_count,
                'has_hidden_input':   int(hidden_count > 0),   'hidden_count': hidden_count,
                'has_file_upload':    int(file_upload_count > 0), 'file_upload_count': file_upload_count,
                'has_search_input':   int(search_count > 0),   'search_count': search_count,
                'has_buttons':  _has('button'),'button_count':  _cnt('button'),
                'has_textarea': _has('textarea'),'textarea_count':_cnt('textarea'),
                'has_select':   _has('select'),'select_count':  _cnt('select'),
                'has_scripts':  _has('script'),'script_count':  _cnt('script'),
                'internal_script_count': internal_scripts, 'external_script_count': external_scripts,
                'has_links':    int('<a href' in c),'link_count': self._count(r'<a [^>]*href[^>]*>', c),
                'internal_link_count': internal_links, 'external_link_count': external_links,
                'has_images':   _has('img'),  'image_count':   _cnt('img'),
                'has_meta_tags':_has('meta'), 'meta_count':    _cnt('meta'),
                'has_stylesheets': int('stylesheet' in c),
                'stylesheet_count': self._count(r'<link[^>]*rel=[\'"]stylesheet[\'"][^>]*>', c),
                'has_javascript':int('<script' in c or 'javascript:' in c),
                'has_comments': int('<!--' in c), 'comment_count': c.count('<!--'),
                'has_title':    int('<title>' in c),
                # Tech stack
                'server_apache':    int('apache' in srv),
                'server_nginx':     int('nginx' in srv),
                'server_iis':       int('iis' in srv or 'microsoft' in srv),
                'tech_php':         int('php' in pb or '.php' in c),
                'tech_aspnet':      int('asp.net' in pb or '.aspx' in c),
                'tech_jsp':         int('.jsp' in c),
                'tech_wordpress':   int('wp-content' in c or 'wordpress' in c),
                'tech_drupal':      int('drupal' in c),
                'tech_joomla':      int('joomla' in c),
                # Security indicators & WAF
                'has_debug_info':   int(any(w in c for w in ['debug','console.log','var_dump','print_r'])),
                'has_error_messages':int(any(w in c for w in ['error','exception','warning','stack trace'])),
                'has_sql_errors':   int(any(w in c for w in ['sql','database','mysql','postgresql','oracle'])),
                'has_file_paths':   int(any(w in c for w in ['/etc/','c:\\','/var/www/','/home/'])),
                'has_waf':          int(bool(waf_found)),
                'waf_cloudflare':   int('Cloudflare' in waf_found),
                'waf_aws':          int('AWS WAF' in waf_found),
                'waf_imperva':      int('Imperva' in waf_found),
                # Reflected & Secrets
                'reflection_detected': int(reflected_params > 0),
                'has_jwt':          int(jwt_count > 0),
                'has_api_keys':     int(api_key_count > 0),
                # Cookies
                'cookie_count':    len(self.cookies),
                'session_cookies': sum(1 for k in self.cookies if 'session' in k.get('name','').lower()),
                'secure_cookie_ratio': secure_cookie_ratio,
                'httponly_cookie_ratio': httponly_cookie_ratio,
                'samesite_cookie_ratio': samesite_cookie_ratio,
                # Redirect
                'redirect_count':      max(0, len(self.redirect_chain)-1),
                'has_redirect_chain':  int(len(self.redirect_chain) > 1),
                'final_https':         int(bool(self.final_url) and self.final_url.startswith('https')),
                # Derived
                'input_to_form_ratio': 0,
                'script_to_content_ratio': 0,
                'security_score':      0,
                'interactivity_score': 0,
                # Meta
                'is_vulnerable':      0, # Default Target Label
                'scan_id':    self.scan_id,
                'timestamp':  datetime.now().isoformat(),
                'target_url': url,
                'original_url': self.original_url,
                'is_redirect_response': is_redirect,
                'final_url':  self.final_url or url,
            }

            fc = features['form_count']
            features['input_to_form_ratio']      = features['input_count'] / fc if fc else 0
            features['script_to_content_ratio']  = features['script_count'] / max(features['response_size'],1)
            features['security_score']           = features['security_headers_count'] / len(_SEC_HEADERS)
            features['interactivity_score']      = (fc + features['input_count'] + features['button_count']) / max(features['response_size']/1000, 1)
            return features

        except Exception as e:
            print(f"[-] Feature extraction error: {e}")
            return {'scan_id': self.scan_id, 'timestamp': datetime.now().isoformat(),
                    'target_url': url, 'original_url': self.original_url,
                    'status_code': getattr(response, 'status_code', 0), 'error_occurred': 1}

    # ── ML dataset ─────────────────────────────────────────────────────────
    def save_ml_dataset(self, features):
        if features.get('error_occurred'):
            return
        try:
            df_new = pd.DataFrame([features])
            if os.path.exists(ML_DATASET_FILE) and os.path.getsize(ML_DATASET_FILE) > 0:
                try:
                    df_new = pd.concat([pd.read_csv(ML_DATASET_FILE), df_new], ignore_index=True)
                except Exception:
                    pass
            df_new.to_csv(ML_DATASET_FILE, index=False)
            df_new.tail(1).to_csv(os.path.join(self.scan_dir, "scan_ml_data.csv"), index=False)
            print(f"[+] ML data saved — status:{features.get('status_code')} size:{features.get('response_size',0)} forms:{features.get('form_count',0)}")
        except Exception as e:
            print(f"[-] ML save error: {e}")

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
            if is_final:
                self.Get_Response = response.text
                self.Get_Request  = f"{response.request.method} {pq} HTTP/1.1\nHost: {p.hostname}\n" + \
                                    "\n".join(f"{k}: {v}" for k,v in response.request.headers.items() if k.lower()!='host')
            self.save_ml_dataset(self.extract_recon_features(response, url, is_redirect=not is_final))
        except Exception as e:
            print(f"[-] Display error: {e}")

    def Get_Target_From_Response(self):
        if not self.Get_Response: print("[-] No response yet"); return
        f = os.path.join(self.scan_dir, "response_content.txt")
        open(f, "w", encoding='utf-8').write(self.Get_Response)
        print(f"[+] Response saved → {f}")

    def Get_Target_From_Request(self):
        if not self.Get_Request: print("[-] No request yet"); return
        f = os.path.join(self.scan_dir, "request_headers.txt")
        open(f, "w", encoding='utf-8').write(self.Get_Request)
        print(f"[+] Request saved → {f}")

    # ── Response analysis ──────────────────────────────────────────────────
    def Analyze_Response(self, url):
        if not self.Get_Response: print("[-] No response to analyze"); return None
        html = self.Get_Response
        params = {
            'url': url, 'forms': [], 'get_params': [], 'post_params': [],
            'buttons': [], 'links': [], 'inputs': [], 'endpoints': [],
            'cookies': self.get_cookies_for_requests(),
        }
        for fm in re.findall(r'<form[^>]*>(.*?)</form>', html, re.I|re.S):
            fd = self._parse_form(fm)
            if fd['inputs']:
                params['forms'].append(fd)
                (params['post_params'] if fd['method']=='POST' else params['get_params']).extend(fd['inputs'])
        params.update({
            'buttons':   self._extract_buttons(html),
            'links':     re.findall(r'href\s*=\s*["\']([^"\']*)["\']', html, re.I),
            'inputs':    [{'type': self._attr(t,'type') or 'text', 'name': self._attr(t,'name'),
                           'id': self._attr(t,'id')} for t in re.findall(r'<input[^>]*>', html, re.I)],
            'endpoints': list(set(re.findall(r'(?:href|action)\s*=\s*["\']([^"\']*)["\']', html, re.I))),
        })
        params['get_params']  = list(set(params['get_params']))
        params['post_params'] = list(set(params['post_params']))
        print(f"[+] Analysis: {len(params['forms'])} forms, {len(params['links'])} links, "
              f"{len(params['inputs'])} inputs, {len(params['endpoints'])} endpoints")
        self._save_analysis(params, url)
        return params

    def _parse_form(self, html):
        return {
            'action': (re.search(r'action\s*=\s*[\'"]([^\'"]*)[\'"]', html, re.I) or [None,'']).group(1) if re.search(r'action', html, re.I) else '',
            'method': ((re.search(r'method\s*=\s*[\'"]\s*(\w+)\s*[\'"]', html, re.I) or type('',(),{'group':lambda s,i:'GET'})()).group(1) or 'GET').upper(),
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
        found = re.findall(r'^(Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options'
                           r'|X-Frame-Options|X-XSS-Protection): (.*)$', self.Get_Request, re.M)
        print(f"[+] Security headers in request: {len(found)}")
        for h, v in found: print(f"    {h}: {v}")

    def _save_analysis(self, params, url):
        af = os.path.join(self.scan_dir, "response_analysis.txt")
        with open(af, "w", encoding='utf-8') as f:
            f.write(f"TARGET: {url}\n{'='*50}\n")
            for form in params['forms']:
                f.write(f"\nForm [{form['method']}] {form['action']}: {form['inputs']}\n")
            for link in params['links'][:50]:
                f.write(f"Link: {link}\n")

        pf = os.path.join(self.scan_dir, "xss_parameters.txt")
        with open(pf, "w", encoding='utf-8') as f:
            f.write(f"# Target: {url}\nGET: {params['get_params']}\nPOST: {params['post_params']}\n")
            f.write("ENDPOINTS:\n" + "\n".join(params['endpoints']))

        uf = os.path.join(self.scan_dir, "test_urls_with_parameters.txt")
        with open(uf, "w", encoding='utf-8') as f:
            for param in params['get_params']:
                f.write(f"{url}?{param}=TEST_PAYLOAD\n")
            for ep in params['endpoints']:
                if ep.startswith('/') or ep.startswith('http'):
                    f.write(f"{urllib.parse.urljoin(url, ep)}\n")
        print(f"[+] Analysis saved → {self.scan_dir}")

    # ── Shell helpers ──────────────────────────────────────────────────────
    def _run_script(self, script, *args, save_file=None):
        if not os.path.exists(script):
            print(f"[-] Script not found: {script}"); return None
        result = subprocess.run(['bash', script, *args], capture_output=True, text=True)
        lines  = [l.strip() for l in result.stdout.split('\n') if l.strip()]
        print(f"[+] {script}: {len(lines)} lines")
        if save_file and lines:
            with open(save_file, 'w') as f: f.write(result.stdout)
            print(f"[+] Saved → {save_file}")
        return lines or None

    def _get_subdomain(self, url):
        print(f"\n[*] Subdomain discovery: {url}")
        return self._run_script("script/get_subdomain.sh", url, save_file="subdomains.txt")

    def _get_URLs(self, url):
        print(f"\n[*] URL discovery: {url}")
        return self._run_script("script/get_URLs.sh", url, save_file="discovered_urls.txt")

    def _get_Paramtes_xss(self, url):
        print(f"\n[*] Parameter discovery: {url}")
        return self._run_script("script/get_parmtras.sh", url)

    # ── Fuzzing ────────────────────────────────────────────────────────────
    def fuzz_url(self, base_url):
        print(f"\n[*] Fuzzing: {base_url}")
        if not os.path.exists("script/fuzzing_command_Tools.sh"):
            print("[-] fuzzing_command_Tools.sh not found"); return None
        open("fuzzing_Target.txt", "w").write(base_url)
        result = subprocess.run(['bash', "script/fuzzing_command_Tools.sh", base_url], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] Fuzz script failed (rc={result.returncode}):\n{result.stderr}")
        print(f"[*] Fuzz done (rc={result.returncode})")
        fuzzing = self.parse_ffuf_results(base_url)
        if fuzzing and fuzzing.get('found_paths'):
            try:
                ans = input("\nCheck found paths? (y/n): ").strip().lower()
            except UnicodeDecodeError:
                ans = 'n'
            if ans == 'y':
                self.check_found_paths(base_url, fuzzing['found_paths'])
        return fuzzing

    def parse_ffuf_results(self, base_url, results_file="ffuf_results.json"):
        for path in (results_file, os.path.join(self.scan_dir, "ffuf_results.json"), "ffuf_results.json"):
            if os.path.exists(path) and os.path.getsize(path) > 0:
                try:
                    data = json.load(open(path))
                    entries = [{'url': e['url'], 'status': e.get('status',0), 'length': e.get('length',0)}
                               for e in data.get('results', []) if e.get('url')]
                    for e in entries: print(f"    [{e['status']}] {e['url']} ({e['length']} B)")
                    print(f"[+] ffuf: {len(entries)} paths")
                    sf = os.path.join(self.scan_dir, "ffuf_summary.txt")
                    with open(sf, "w") as f:
                        f.write(f"# {base_url}\n" + "\n".join(f"[{e['status']}] {e['url']}" for e in entries))
                    print(f"[+] Summary → {sf}")
                    return {'found_paths': [e['url'] for e in entries], 'raw': entries}
                except Exception as ex:
                    print(f"[-] ffuf parse error: {ex}")
        print("[-] No ffuf results found")
        return {'found_paths': [], 'raw': []}

    def check_found_paths(self, base_url, paths):
        print(f"\n[*] Verifying {len(paths)} paths...")
        import concurrent.futures
        
        def _verify(args):
            i, url = args
            try:
                with httpx.Client(timeout=8.0, verify=False, follow_redirects=True) as c:
                    r = c.get(url, headers=UA)
                print(f"  [{i}/{len(paths)}] {r.status_code} | {len(r.text):>8} B | {url}")
            except Exception as ex:
                print(f"  [{i}/{len(paths)}] ERROR: {ex}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(_verify, enumerate(paths, 1)))

    # ── Cookie / header persistence ────────────────────────────────────────
    def save_cookies_and_headers(self):
        def _save(name, data, fmt):
            if not data: print(f"[-] No {name} captured"); return
            jf = os.path.join(self.scan_dir, f"{name}.json")
            json.dump(data, open(jf,"w"), indent=2)
            print(f"[+] {name} → {jf}")
        _save("cookies", self.cookies, None)
        _save("headers", self.headers, None)

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

def test_connection(url):
    try:
        recon = ReconWebSite(url)
        response = recon.track_redirects(url)
        if response:
            print(f"[+] Reached: {recon.final_url}")
            recon.print_redirect_summary()
            recon.save_redirect_analysis()
            return response, recon
        print("[-] Could not reach target")
    except Exception as e:
        print(f"[-] Connection error: {e}")
    return None, None


def MainRecon(url):
    try:
        print(f"[*] Saving to: {DATASET_DIR or '(current dir)'}\n[*] ML file : {ML_DATASET_FILE}")
        recon = ReconWebSite(url)
        response, recon_obj = test_connection(url)

        if response and recon_obj:
            recon = recon_obj
            print("\n[*] WAF check...")
            recon.detect_waf(response)
            recon.print_security_summary(response)
            recon.print_request_response_details(response, recon.final_url, is_final=True)
            recon.Get_Target_From_Response()
            recon.Get_Target_From_Request()
            recon.Analyze_Response(recon.final_url)
            recon.Analyze_Request()
            recon.save_cookies_and_headers()
            recon._get_subdomain(recon.final_url)
            recon._get_URLs(recon.final_url)
            recon._get_Paramtes_xss(recon.final_url)

        try:
            ans = input("\nFuzz with ffuf? (y/n): ").strip().lower()
        except UnicodeDecodeError:
            ans = 'n'
            
        if ans == 'y':
            recon.fuzz_url(recon.final_url or recon.original_url)

        recon.show_dataset_stats()

    except KeyboardInterrupt:
        print("\n[!] Cancelled")
    except Exception as e:
        import traceback
        print(f"[-] Error: {e}"); traceback.print_exc()
    return True


if __name__ == "__main__":
    MainRecon(input("Enter URL: "))