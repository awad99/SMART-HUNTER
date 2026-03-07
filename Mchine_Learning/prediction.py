import re, time, urllib.parse, requests, httpx
from Mchine_Learning.Ai_model import VulnerabilityCheckerTraining, FEATURE_COLS, MODEL_FILE

# -- Prediction Constants ----------------------------------------------------
PHASE_LABELS = {
    1:  " PHASE 1 - EARLY PREDICTION  (URL structure only, before recon)",
    21: " PHASE 2A - RECON PREDICTION  (live features, after page fetch)",
    22: " PHASE 2B - FINAL PREDICTION  (post-scan, confirmed results)",
}

ATTACK_PATH_MAP = {
    'sql_injection':     ['Enumerate DB tables', 'Dump credentials', 'Bypass auth'],
    'xss':               ['Steal session cookies', 'Phishing / redirect', 'DOM manipulation'],
    'command_injection': ['RCE via OS commands', 'Reverse shell', 'File exfiltration'],
    'path_traversal':    ['Read /etc/passwd', 'Access config files', 'Source code disclosure'],
}

# =============================================================================
class SmartVulnerabilityScanner(VulnerabilityCheckerTraining):
# =============================================================================

    def __init__(self, url, cookie=None):
        super().__init__(url, cookie)
        self.prediction = None

    def extract_recon_features(self):
        print(f"[*] Extracting live recon features: {self.url}")
        try:
            import Recon.url_connection as url_connection
            recon = url_connection.ReconWebSite(self.url, cookie=self.cookie)
            hdr = {'Cookie': self.cookie} if self.cookie else None
            with httpx.Client(timeout=10.0, verify=False, follow_redirects=True) as c:
                resp = c.get(self.url, headers={**url_connection.UA, **(hdr if hdr else {})})
            features = recon.extract_recon_features(resp, self.url)
            out = {}
            for col in FEATURE_COLS:
                val = features.get(col, 0)
                try:    out[col] = float(val)
                except: out[col] = 0.0
            print(f"[+] Extracted {len(out)} live features")
            return out
        except Exception as e:
            print(f"[-] Live extraction failed: {e}, using URL-only features")
            return self._url_only_features()

    def _url_only_features(self):
        p = urllib.parse.urlparse(self.url)
        f = {c: 0 for c in FEATURE_COLS}
        f.update({
            'url_length': len(self.url),
            'has_https': int(self.url.startswith('https')),
            'path_depth': len([x for x in p.path.split('/') if x]),
            'has_query_params': int(bool(p.query)),
            'num_query_params': len(urllib.parse.parse_qs(p.query)),
            'subdomain_count': max(0, len(p.netloc.split('.')) - 2),
            'domain_length': len(p.netloc),
            'domain_has_hyphens': int('-' in p.netloc),
            'is_ip_address': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', p.netloc))),
        })
        return f

    def smart_vulnerability_scan(self, model_path=MODEL_FILE, crawl_results=None):
        print(f"\n{'='*60}\n  SMART VULNERABILITY SCAN\n  Target: {self.url}\n{'='*60}")
        if model_path and not self.model:
            if not self.load_model(model_path):
                self.train_model()
                self.save_model(model_path)

        features = self.extract_recon_features()
        self.prediction = self.predict_vulnerability(features) if self.model else None

        target_list = []
        if crawl_results:
            for f in crawl_results.get('discovered_forms', []):
                method = f.get('method', 'GET').upper()
                url = f['url']
                pname = f['param']
                found = False
                for m, u, ps in target_list:
                    if m == method and u == url:
                        ps[pname] = ['FUZZ']; found = True; break
                if not found: target_list.append((method, url, {pname: ['FUZZ']}))
            for d in crawl_results.get('discovered_params', []):
                method = d.get('method', 'GET').upper()
                url = d['url'].split('?')[0]
                pname = d['param']
                found = False
                for m, u, ps in target_list:
                    if m == method and u == url:
                        ps[pname] = ['FUZZ']; found = True; break
                if not found: target_list.append((method, url, {pname: ['FUZZ']}))

        if not target_list:
            p = urllib.parse.urlparse(self.url)
            params = urllib.parse.parse_qs(p.query) if p.query else {}
            target_list = [('GET', self.url, params)]

        vulns = []
        if self.prediction:
            preds = self.prediction['predictions']
            if preds.get('sql_injection', 0) > 0.15: vulns.extend(self._test_sql_injection())
            if preds.get('xss', 0) > 0.15: vulns.extend(self._test_xss(target_list))
            if preds.get('command_injection', 0) > 0.15: vulns.extend(self._test_command_injection())
            if preds.get('path_traversal', 0) > 0.15:
                import vulnerability_scan.path_Analyze as path_Analyze
                pt_res = path_Analyze.crawl_and_scan(self.url, max_depth=2, cookie=self.cookie)
                if pt_res and pt_res.get('vulns'): vulns.extend(pt_res['vulns'])
            if not vulns and all(v < 0.15 for v in preds.values()):
                vulns.extend(self._test_sql_injection()); vulns.extend(self._test_xss(target_list))
        else:
            vulns.extend(self._test_sql_injection()); vulns.extend(self._test_xss(target_list)); vulns.extend(self._test_command_injection())
        return vulns

    def _test_sql_injection(self):
        vulns = []
        p = urllib.parse.urlparse(self.url)
        params_to_test = urllib.parse.parse_qs(p.query) if p.query else {'id':['test']}
        errors = ['sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite', 'syntax error']
        payloads = [("'", "error-based"), ("' OR '1'='1", "boolean-based")]
        hdr = {'Cookie': self.cookie} if self.cookie else None
        for param in list(params_to_test.keys())[:5]:
            for payload, ptype in payloads:
                test_url = self._inject(self.url, param, payload)
                try:
                    r = requests.get(test_url, timeout=5, verify=False, headers=hdr)
                    if any(re.search(e, r.text, re.I) for e in errors):
                        vulns.append({'type': f'SQL Injection ({ptype})', 'parameter': param, 'payload': payload, 'confidence': 'high'})
                except: pass
        return vulns

    def _test_xss(self, target_list=None):
        vulns = []
        if not target_list:
            p = urllib.parse.urlparse(self.url); params = urllib.parse.parse_qs(p.query) if p.query else {'search':['test']}
            target_list = [('GET', self.url, params)]
        canary = 'xSsT3st'
        payloads = [(f'<script>alert("{canary}")</script>', "script tag")]
        hdr = {'Cookie': self.cookie} if self.cookie else None
        for method, url, params in target_list:
            for target_param in params:
                for payload, ptype in payloads:
                    try:
                        if method == 'POST': r = requests.post(url, data={k:(payload if k==target_param else v[0]) for k,v in params.items()}, timeout=5, verify=False, headers=hdr)
                        else: r = requests.get(self._inject(url, target_param, payload), timeout=5, verify=False, headers=hdr)
                        if canary in r.text: vulns.append({'type': f'XSS ({ptype})', 'url': url, 'parameter': target_param, 'confidence': 'high'})
                    except: pass
        return vulns

    def _test_command_injection(self):
        vulns = []
        p = urllib.parse.urlparse(self.url); params = urllib.parse.parse_qs(p.query) if p.query else {'cmd':['test']}
        payloads = [";ls", "|id", "$(whoami)"]
        hdr = {'Cookie': self.cookie} if self.cookie else None
        for param in list(params.keys())[:4]:
            for payload in payloads:
                try:
                    r = requests.get(self._inject(self.url, param, payload), timeout=5, verify=False, headers=hdr)
                    if any(ind in r.text.lower() for ind in ['uid=', 'root:']):
                        vulns.append({'type': 'Command Injection', 'parameter': param, 'payload': payload, 'confidence': 'high'})
                except: pass
        return vulns

    @staticmethod
    def _inject(url, param, payload):
        p = urllib.parse.urlparse(url); q = urllib.parse.parse_qs(p.query); q[param] = [payload]
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, urllib.parse.urlencode(q, doseq=True), p.fragment))

def show_phase_prediction(scanner, phase: int, url: str, confirmed_vulns=None):
    print(f"\n{'='*64}\n  {PHASE_LABELS.get(phase, f'PHASE {phase}')}\n  Target : {url}\n{'='*64}")
    features = scanner._url_only_features() if phase == 1 else scanner.extract_recon_features()
    prediction = scanner.predict_vulnerability(features) if scanner.model else None
    if not prediction: print(f"  [-] No model available"); return prediction
    preds = prediction['predictions']
    print(f"\n  {'VULNERABILITY':<28} {'CONFIDENCE':>10}   RISK\n  {'-'*56}")
    for name, prob in sorted(preds.items(), key=lambda x: x[1], reverse=True):
        lvl = '🔴 HIGH' if prob > 0.55 else '🟡 MED ' if prob > 0.25 else '🟢 LOW '
        print(f"  {name:<28} {'█'*int(prob*20):<20} {prob:>5.1%}  {lvl}")
    return prediction
