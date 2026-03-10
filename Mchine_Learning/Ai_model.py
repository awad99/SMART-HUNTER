import os, urllib.parse, numpy as np, pandas as pd, joblib, traceback
from sklearn.ensemble import RandomForestClassifier
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler

# -- Constants --------------------------------------------------------------
RECON_FILE = "Data/Datasets/web_recon_ml_dataset.csv"
VULN_FILE  = "Data/Datasets/vulnerability_ml_dataset.csv"
MODEL_FILE = "Data/vulnerability_model.pkl"

# Features used for training (Updated to match data_pipeline.ipynb)
FEATURE_COLS = [
    'button_count', 'cache_control', 'comment_count', 'cookie_count', 'csp_header_reflection_detected', 'domain_has_hyphens',
    'domain_length', 'external_link_count', 'external_script_count', 'file_upload_count', 'final_https',
    'form_count', 'has_api_keys', 'has_buttons', 'has_comments', 'has_content_type_options',
    'has_cookies', 'has_cors', 'has_csp', 'has_debug_info', 'has_error_messages',
    'has_file_paths', 'has_file_upload', 'has_forms', 'has_fragment', 'has_frame_options',
    'has_hidden_input', 'has_hsts', 'has_https', 'has_images', 'has_inputs',
    'has_javascript', 'has_jwt', 'has_links', 'has_meta_tags', 'has_password_input',
    'has_port', 'has_query_params', 'has_redirect_chain', 'has_scripts', 'has_search_input',
    'has_select', 'has_sql_errors', 'has_stylesheets', 'has_textarea', 'has_title',
    'has_waf', 'has_xss_protection', 'hidden_count', 'httponly_cookie_ratio', 'image_count',
    'input_count', 'input_to_form_ratio', 'interactivity_score', 'internal_link_count', 'internal_script_count',
    'is_ip_address', 'is_redirect', 'is_redirect_response', 'link_count', 'meta_count',
    'num_cookies', 'num_query_params', 'password_count', 'path_depth', 'redirect_chain_len',
    'redirect_count', 'reflection_detected', 'response_size', 'response_time_ms', 'samesite_cookie_ratio',
    'script_count', 'script_to_content_ratio', 'search_count', 'secure_cookie_ratio', 'security_headers_count',
    'security_score', 'select_count', 'server_apache', 'server_header_present', 'server_iis',
    'server_nginx', 'session_cookies', 'status_category', 'status_code', 'stylesheet_count',
    'subdomain_count', 'tech_aspnet', 'tech_drupal', 'tech_joomla', 'tech_jsp',
    'tech_php', 'tech_wordpress', 'textarea_count', 'total_headers', 'url_length',
    'waf_aws', 'waf_cloudflare', 'waf_imperva', 'x_powered_by_present'
]

LABEL_COLS = ['has_sql_injection', 'has_xss', 'has_command_injection', 'has_path_traversal', 'has_idor']
VULN_NAMES = {0: 'sql_injection', 1: 'xss', 2: 'command_injection', 3: 'path_traversal', 4: 'idor'}

def deduplicate_recon_dataset(path=RECON_FILE):
    try:
        df = pd.read_csv(path); orig = len(df)
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp', ascending=False)
        df = df.drop_duplicates(subset=['target_url'], keep='first')
        if 'response_size' in df.columns:
            df = df[df['response_size'] > 0]
        df.to_csv(path, index=False)
        print(f"[+] Recon dedup: {orig} -> {len(df)} ({orig-len(df)} removed)")
    except Exception as e:
        print(f"[-] Dedup error: {e}")

def deduplicate_vulnerability_dataset(path=VULN_FILE):
    try:
        df = pd.read_csv(path); orig = len(df)
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp', ascending=False)
        df = df.drop_duplicates(subset=['url'], keep='first')
        df.to_csv(path, index=False)
        print(f"[+] Vuln dedup: {orig} -> {len(df)} ({orig-len(df)} removed)")
    except Exception as e:
        print(f"[-] Dedup error: {e}")

# =============================================================================
class VulnerabilityCheckerTraining:
# =============================================================================

    def __init__(self, target_url="", cookie=None):
        self.url = target_url
        self.cookie = cookie
        self.model = None
        self.scaler = StandardScaler()
        self.trained_feature_columns = []

    def load_data(self, recon_path, vuln_path):
        try:
            r = pd.read_csv(recon_path)
            v = pd.read_csv(vuln_path)
            print(f"[+] Loaded recon: {len(r)} rows x {len(r.columns)} cols")
            print(f"[+] Loaded vuln : {len(v)} rows x {len(v.columns)} cols")
            return r, v
        except Exception as e:
            print(f"[-] Load error: {e}"); return None, None

    def _merge_datasets(self, recon, vuln):
        def _domain(url):
            try:    return urllib.parse.urlparse(str(url)).netloc.lower().replace('www.', '')
            except: return str(url).lower()

        recon = recon.copy(); vuln = vuln.copy()
        recon['_domain'] = recon['target_url'].apply(_domain)
        vuln['_domain']  = vuln['url'].apply(_domain)

        if 'timestamp' in recon.columns:
            recon = recon.sort_values('timestamp', ascending=False).drop_duplicates('_domain', keep='first')
        else:
            recon = recon.drop_duplicates('_domain', keep='first')

        if 'timestamp' in vuln.columns:
            vuln = vuln.sort_values('timestamp', ascending=False).drop_duplicates('_domain', keep='first')

        merged = recon.merge(vuln[['_domain'] + [c for c in LABEL_COLS if c in vuln.columns]],
                             on='_domain', how='inner')
        print(f"[+] Merged dataset: {len(merged)} rows (matched by domain)")

        unmatched = recon[~recon['_domain'].isin(merged['_domain'])].copy()
        for c in LABEL_COLS:
            if c not in unmatched.columns: unmatched[c] = 0
        combined = pd.concat([merged, unmatched], ignore_index=True)
        print(f"[+] Combined dataset: {len(combined)} rows ({len(merged)} matched + {len(unmatched)} unlabeled)")
        return combined

    def _generate_augmented_data(self, n=150):
        np.random.seed(42)
        rows = []
        for _ in range(n):
            profile = np.random.choice(['vuln_sqli', 'vuln_xss', 'vuln_cmdi', 'vuln_pt', 'vuln_idor', 'secure', 'normal'])
            r = {c: 0 for c in FEATURE_COLS}
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
            elif profile == 'vuln_pt':
                r['has_query_params'] = 1; r['num_query_params'] = np.random.randint(1, 4)
                r['has_forms'] = np.random.choice([0,1])
                r['has_inputs'] = 1; r['input_count'] = np.random.randint(1, 5)
                r['has_file_paths'] = np.random.choice([0,1], p=[.3,.7])
                r['has_error_messages'] = np.random.choice([0,1], p=[.4,.6])
                r['tech_php'] = np.random.choice([0,1], p=[.3,.7])
                r['security_headers_count'] = np.random.randint(0, 3)
                r['path_depth'] = np.random.randint(2, 6)
                for lbl in LABEL_COLS: r[lbl] = 0
                r['has_path_traversal'] = 1
            elif profile == 'vuln_idor':
                r['has_query_params'] = 1; r['num_query_params'] = np.random.randint(1, 4)
                r['has_forms'] = np.random.choice([0,1])
                r['has_inputs'] = 1; r['input_count'] = np.random.randint(1, 5)
                # IDOR is more prominent with numeric endpoints / APIs
                r['path_depth'] = np.random.randint(2, 6)
                r['security_headers_count'] = np.random.randint(0, 3)
                r['status_code'] = np.random.choice([200, 401, 403], p=[.6, .2, .2])
                for lbl in LABEL_COLS: r[lbl] = 0
                r['has_idor'] = 1
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

    def train_model(self, recon_path=RECON_FILE, vuln_path=VULN_FILE):
        print("[*] Training vulnerability prediction model...")
        have_recon = os.path.exists(recon_path) and os.path.getsize(recon_path) > 0
        have_vuln  = os.path.exists(vuln_path)  and os.path.getsize(vuln_path) > 0
        frames = []

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

        real_count = sum(len(f) for f in frames)
        aug_count  = max(100, 200 - real_count * 3)
        aug = self._generate_augmented_data(aug_count)
        frames.append(aug)
        print(f"[+] Augmented: {aug_count} synthetic samples (real:{real_count})")

        combined = pd.concat(frames, ignore_index=True)
        for c in FEATURE_COLS + LABEL_COLS:
            if c not in combined.columns: combined[c] = 0

        X = combined[FEATURE_COLS].apply(pd.to_numeric, errors='coerce').fillna(0)
        Y = combined[LABEL_COLS].apply(pd.to_numeric, errors='coerce').fillna(0).astype(int)

        self.trained_feature_columns = FEATURE_COLS
        print(f"[+] Total dataset: {len(X)} samples x {len(FEATURE_COLS)} features -> {len(LABEL_COLS)} labels")

        # Train/Test Split
        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
        print(f"[+] Split: {len(X_train)} train | {len(X_test)} test")

        for i, col in enumerate(LABEL_COLS):
            pos = Y_train[col].sum()
            print(f"    {col} (train): {pos} positive ({pos/len(Y_train):.1%})")

        # Fit scaler on training data ONLY
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model with highly optimized hyperparameters for maximum accuracy
        from sklearn.ensemble import HistGradientBoostingClassifier
        self.model = OneVsRestClassifier(
            HistGradientBoostingClassifier(
                max_iter=300,
                max_depth=15,
                learning_rate=0.08,
                random_state=42,
                class_weight='balanced',
                l2_regularization=0.1
            )
        )
        self.model.fit(X_train_scaled, Y_train)

        # Predict & Evaluate
        Y_train_pred = self.model.predict(X_train_scaled)
        Y_test_pred = self.model.predict(X_test_scaled)
        
        print(f"\n[+] Accuracy Report (per-label):")
        for i, col in enumerate(LABEL_COLS):
            acc_train = accuracy_score(Y_train.iloc[:, i], Y_train_pred[:, i])
            acc_test = accuracy_score(Y_test.iloc[:, i], Y_test_pred[:, i])
            print(f"    {col:<22} Train: {acc_train:>7.2%} | Test: {acc_test:>7.2%}")

        fi = [est.feature_importances_ for est in self.model.estimators_ if hasattr(est, 'feature_importances_')]
        if fi:
            importances = np.mean(fi, axis=0)
            top_idx = np.argsort(importances)[-10:][::-1]
            print(f"\n[+] Top 10 Important Features:")
            for idx in top_idx:
                print(f"    {FEATURE_COLS[idx]}: {importances[idx]:.4f}")
        return True

    def predict_vulnerability(self, features_dict):
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
                p = proba[i][0] if isinstance(proba, list) else proba[0][i]
                conf = float(p) if np.ndim(p) == 0 else (p[1] if len(p) > 1 else p[0])
                name = col.replace('has_', '')
                result['predictions'][name] = round(float(conf), 3)
                if conf > result['top_confidence']:
                    result['top_confidence'] = float(conf)
                    result['top_risk'] = name
            print(f"{'='*55}\n  Top risk: {result['top_risk']} ({result['top_confidence']:.1%})\n{'='*55}\n")
            return result
        except Exception as e:
            print(f"[-] Prediction error: {e}"); traceback.print_exc(); return None

    def save_model(self, path=MODEL_FILE):
        if not self.model: print("[-] No model to save"); return
        joblib.dump({'model': self.model, 'scaler': self.scaler,
                     'feature_columns': self.trained_feature_columns,
                     'label_columns': LABEL_COLS}, path)
        print(f"[+] Model saved -> {path}")

    def load_model(self, path=MODEL_FILE):
        try:
            d = joblib.load(path)
            self.model  = d['model']
            self.scaler = d['scaler']
            self.trained_feature_columns = d['feature_columns']
            print(f"[+] Model loaded <- {path} ({len(self.trained_feature_columns)} features)")
            return True
        except Exception as e:
            print(f"[-] Load error: {e}"); return False
