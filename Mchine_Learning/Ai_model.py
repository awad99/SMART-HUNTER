import os, urllib.parse, numpy as np, pandas as pd, joblib, traceback
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

# -- Constants --------------------------------------------------------------
RECON_FILE = "Data/Datasets/web_recon_ml_dataset.csv"
VULN_FILE  = "Data/Datasets/vulnerability_ml_dataset.csv"
X_TRAIN_FILE = "Data/Datasets/X_train.csv"
X_TEST_FILE  = "Data/Datasets/X_test.csv"
Y_TRAIN_FILE = "Data/Datasets/y_train.csv"
Y_TEST_FILE  = "Data/Datasets/y_test.csv"
FINAL_DATA_FILE = "Data/Datasets/final_training_data.csv"
MODEL_FILE = "Data/vulnerability_model.pkl"

# Features used for training (Updated to match data_pipeline.ipynb output)
FEATURE_COLS = [
    'critical_high_ratio', 'content_type_encoded', 'has_forms', 'response_time_ms_scaled',
    'status_category_encoded', 'waf_detected', 'log_response_size', 'path_depth_scaled',
    'security_score', 'input_count', 'has_inputs', 'subdomain_count', 'num_query_params',
    'total_headers', 'has_frame_options', 'has_comments', 'has_javascript',
    'response_size_scaled', 'has_csp', 'url_length', 'security_headers_count_scaled',
    'params_per_input', 'has_hsts', 'has_https', 'vuln_density_per_kb', 'input_count_scaled',
    'interactivity_score', 'security_headers_count', 'server_header_encoded', 'path_depth',
    'form_count', 'form_count_scaled', 'domain_tld_encoded', 'response_time_ms',
    'response_size', 'has_xss_protection'
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
        self.scaler = MinMaxScaler()
        self.label_encoders = {}
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

    def train_model(self, use_preprocessed=True):
        print("[*] Training vulnerability prediction model...")
        
        X_train, X_test, Y_train, Y_test = None, None, None, None
        loaded_preprocessed = False

        if use_preprocessed:
            try:
                if all(os.path.exists(f) for f in [X_TRAIN_FILE, X_TEST_FILE, Y_TRAIN_FILE, Y_TEST_FILE]):
                    print("[+] Loading pre-processed datasets from pipeline output...")
                    X_train = pd.read_csv(X_TRAIN_FILE).apply(pd.to_numeric, errors='coerce').fillna(0)
                    X_test  = pd.read_csv(X_TEST_FILE).apply(pd.to_numeric, errors='coerce').fillna(0)
                    Y_train = pd.read_csv(Y_TRAIN_FILE).apply(pd.to_numeric, errors='coerce').fillna(0).astype(int)
                    Y_test  = pd.read_csv(Y_TEST_FILE).apply(pd.to_numeric, errors='coerce').fillna(0).astype(int)
                    
                    # Align features and labels
                    self.trained_feature_columns = X_train.columns.tolist()
                    loaded_preprocessed = True
                    print(f"[+] Loaded: {len(X_train)} train | {len(X_test)} test")
            except Exception as e:
                print(f"[-] Error loading pre-processed data: {e}")

        if not loaded_preprocessed:
            print("[!] Pre-processed files missing or failed to load. Falling back to raw CSV merge...")
            recon_path = RECON_FILE
            vuln_path = VULN_FILE
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
            elif have_recon:
                recon = pd.read_csv(recon_path)
                frames.append(recon)

            real_count = sum(len(f) for f in frames)
            aug_count  = max(100, 200 - real_count * 3)
            aug = self._generate_augmented_data(aug_count)
            frames.append(aug)
            print(f"[+] Combined data (real:{real_count}, aug:{aug_count})")

            combined = pd.concat(frames, ignore_index=True)
            # Ensure target labels exist in combined data for fallback
            available_labels = [c for c in LABEL_COLS if c in combined.columns]
            
            for c in FEATURE_COLS + LABEL_COLS:
                if c not in combined.columns: combined[c] = 0

            X = combined[FEATURE_COLS].apply(pd.to_numeric, errors='coerce').fillna(0)
            Y = combined[LABEL_COLS].apply(pd.to_numeric, errors='coerce').fillna(0).astype(int)
            
            self.trained_feature_columns = FEATURE_COLS
            X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

        print(f"[+] Total training features: {len(self.trained_feature_columns)}")
        print(f"[+] Split: {len(X_train)} train | {len(X_test)} test")

        for i, col in enumerate(Y_train.columns):
            pos = Y_train[col].sum()
            print(f"    {col} (train): {pos} positive ({pos/len(Y_train):.1%})")

        # Fit scaler on training data ONLY
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model with highly optimized hyperparameters for maximum accuracy
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
        self.trained_label_columns = Y_train.columns.tolist()

        # Predict & Evaluate
        Y_train_pred = self.model.predict(X_train_scaled)
        Y_test_pred = self.model.predict(X_test_scaled)
        
        print(f"\n[+] Accuracy Report (per-label):")
        labels_to_show = Y_train.columns
        for i, col in enumerate(labels_to_show):
            # Handle 1D/2D arrays safely
            y_train_true = Y_train.iloc[:, i]
            y_test_true  = Y_test.iloc[:, i]
            
            y_train_pred_slice = Y_train_pred[:, i] if Y_train_pred.ndim > 1 else Y_train_pred
            y_test_pred_slice  = Y_test_pred[:, i]  if Y_test_pred.ndim > 1 else Y_test_pred

            acc_train = accuracy_score(y_train_true, y_train_pred_slice)
            acc_test = accuracy_score(y_test_true, y_test_pred_slice)
            print(f"    {col:<22} Train: {acc_train:>7.2%} | Test: {acc_test:>7.2%}")

        fi = [est.feature_importances_ for est in self.model.estimators_ if hasattr(est, 'feature_importances_')]
        if fi:
            importances = np.mean(fi, axis=0)
            top_idx = np.argsort(importances)[-10:][::-1]
            print(f"\n[+] Top 10 Important Features:")
            for idx in top_idx:
                print(f"    {FEATURE_COLS[idx]}: {importances[idx]:.4f}")
        return True

    def preprocess_features(self, features_dict):
        """Replicate the feature engineering from data_pipeline.ipynb for inference."""
        # Create a DataFrame from the dictionary
        df = pd.DataFrame([features_dict])
        
        # Ensure base columns exist (even if 0) to avoid key errors during scoring
        base_cols = [
            'has_forms', 'has_inputs', 'has_javascript', 
            'form_count', 'input_count', 'response_size', 
            'num_query_params', 'security_headers_count',
            'has_https', 'has_csp', 'has_hsts', 'has_frame_options', 
            'has_xss_protection', 'has_content_type_options'
        ]
        for c in base_cols:
            if c not in df.columns: df[c] = features_dict.get(c, 0)

        # 1. Feature Engineering (Matches data_pipeline.ipynb logic)
        has_forms = 1 if df['has_forms'].iloc[0] else 0
        has_inputs = 1 if df['has_inputs'].iloc[0] else 0
        has_js = 1 if df['has_javascript'].iloc[0] else 0
        f_count = float(df['form_count'].iloc[0])
        i_count = float(df['input_count'].iloc[0])
        
        # interactivity_score
        df['interactivity_score'] = (
            has_forms * 0.3 + has_inputs * 0.3 + has_js * 0.2 +
            (f_count / (f_count + 1)) * 0.1 + (i_count / (i_count + 1)) * 0.1
        )
        
        # security_score
        security_cols = ['has_https', 'has_csp', 'has_hsts', 'has_frame_options', 
                         'has_xss_protection', 'has_content_type_options']
        sec_score = 0
        for col in security_cols:
            sec_score += 1 if df[col].iloc[0] else 0
        sec_score *= 0.2
        if 'security_headers_count' in df.columns:
            sec_score += (float(df['security_headers_count'].iloc[0]) / 10) * 0.2
        df['security_score'] = sec_score

        # log_response_size
        if 'response_size' in df.columns:
            size = float(df['response_size'].iloc[0])
            df['log_response_size'] = np.log1p(size)
        
        # params_per_input
        if i_count > 0:
            df['params_per_input'] = float(df['num_query_params'].iloc[0]) / i_count
        else:
            df['params_per_input'] = 0

        # WAF detection
        waf_detected = 0
        for k in features_dict:
            if 'waf_' in k and features_dict[k]:
                waf_detected = 1; break
        df['waf_detected'] = waf_detected

        # 2. Categorical Encoding (Reuse saved encoders from training)
        categorical_cols = ['domain_tld', 'server_header', 'content_type', 'status_category']
        for col in categorical_cols:
            enc_col = f"{col}_encoded"
            if col in self.label_encoders:
                val = str(features_dict.get(col, 'unknown')).lower()
                try: 
                    df[enc_col] = self.label_encoders[col].transform([val])[0]
                except:
                    df[enc_col] = 0 # unknown or new category
            else:
                df[enc_col] = 0

        # 3. Default values for features not easily calculated at inference
        df['critical_high_ratio'] = 0
        df['vuln_density_per_kb'] = 0

        # 4. Handle Scaled Features
        # The model's scaler (MinMaxScaler) expects these raw values in the correct column positions.
        scaled_feature_map = {
            'response_time_ms_scaled': 'response_time_ms',
            'path_depth_scaled': 'path_depth',
            'response_size_scaled': 'response_size',
            'security_headers_count_scaled': 'security_headers_count',
            'input_count_scaled': 'input_count',
            'form_count_scaled': 'form_count'
        }
        for s_col, r_col in scaled_feature_map.items():
            if s_col in self.trained_feature_columns:
                df[s_col] = df.get(r_col, 0)

        # Ensure all trained features exist in the resulting DataFrame
        for c in self.trained_feature_columns:
            if c not in df.columns: df[c] = 0

        # Final selection and numeric conversion to match training order
        X = df[self.trained_feature_columns].apply(pd.to_numeric, errors='coerce').fillna(0)
        return X

    def predict_vulnerability(self, features_dict):
        if not self.model:
            print("[-] Model not trained"); return None
        try:
            X = self.preprocess_features(features_dict)
            X_scaled = self.scaler.transform(X)
            proba = self.model.predict_proba(X_scaled)
            
            result = {'predictions': {}, 'top_risk': 'none', 'top_confidence': 0.0}
            
            # Label names from training
            labels = self.trained_label_columns if hasattr(self, 'trained_label_columns') else LABEL_COLS

            for i, col in enumerate(labels):
                p = proba[i][0] if isinstance(proba, list) else proba[0][i]
                conf = float(p) if np.ndim(p) == 0 else (p[1] if len(p) > 1 else p[0])
                name = col.replace('has_', '')
                result['predictions'][name] = round(float(conf), 3)
                if conf > result['top_confidence']:
                    result['top_confidence'] = float(conf)
                    result['top_risk'] = name
            
            print(f"{'='*55}\n  Prediction: {result['top_risk']} (Conf: {result['top_confidence']:.1%})\n{'='*55}\n")
            return result
        except Exception as e:
            print(f"[-] Prediction error: {e}"); traceback.print_exc(); return None

    def save_model(self, path=MODEL_FILE):
        if not self.model: print("[-] No model to save"); return
        data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_columns': self.trained_feature_columns,
            'label_columns': getattr(self, 'trained_label_columns', LABEL_COLS)
        }
        joblib.dump(data, path)
        print(f"[+] Model saved -> {path} ({len(self.trained_feature_columns)} features)")

    def load_model(self, path=MODEL_FILE):
        try:
            d = joblib.load(path)
            self.model  = d['model']
            self.scaler = d['scaler']
            self.label_encoders = d.get('label_encoders', {})
            self.trained_feature_columns = d['feature_columns']
            self.trained_label_columns = d.get('label_columns', LABEL_COLS)
            print(f"[+] Model loaded <- {path} ({len(self.trained_feature_columns)} features)")
            return True
        except Exception as e:
            print(f"[-] Load error: {e}"); return False
