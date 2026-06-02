import os
import threading
import concurrent.futures
from datetime import datetime
import pandas as pd

from database_manager import DatabaseManager
from Data.Queries.q_scans import create_scan as _create_scan_direct, update_scan_status as _update_scan_status_direct
from Data.Queries.q_features import save_features as _save_features_direct
from Data.Queries.q_raw_responses import save_raw_response
from Data.Queries.scan_stats import ScanStats
from Data.Queries.q_reports import save_report
from Data.Queries.q_forms import save_forms
from Data.Queries.q_endpoints import save_endpoints
from Data.Update_Data.nlp_trace_writer import NLPTraceWriter
from Data.Update_Data.target_scan_dataset import append_target_scan_row
from Logic.NLP.http_trace_builder import HTTPTraceBuilder
from Logic.NLP.route_decider import RouteDecider
from Logic.Recon.framework_detector import FrameworkDetector

# Internal SOLID imports
from Logic.Recon.utils import normalize_url, ordered_unique, robust_input
from Logic.Recon.http_client import ReconHttpClient, UA, HTTP_TIMEOUT
from Logic.Recon.redirect_tracker import RedirectTracker
from Logic.Recon.waf_detector import WafDetector
from Logic.Recon.waf_bypass import create_bypass_client, is_bypass_available
from Logic.Recon.feature_extractor import FeatureExtractor, _SEC_HEADERS
from Logic.Recon.discovery_runner import DiscoveryRunner

DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "Data")
ML_DATASET_FILE = os.path.join(DATASET_DIR, "Datasets", "Datasets_for_Model_Evaluation", "recon", "web_recon_ml_dataset.csv")
DATASET_LOCK = threading.Lock()
_RECON_DATASET_COLUMNS_CACHE = None
DISCOVERY_WORKERS = max(1, int(os.getenv("SMART_HUNTER_RECON_DISCOVERY_WORKERS", "3")))

class ReconWebSite:
    def __init__(self, url, cookie=None, scan_id=None, stats=None):
        self.original_url = normalize_url(url)
        self.cookie = cookie
        self.scan_id = scan_id or datetime.now().strftime('%Y%m%d_%H%M%S')
        
        self.db = DatabaseManager()
        _create_scan_direct(self.db, self.scan_id, self.original_url, UA['User-Agent'], self.cookie)
        self.stats = stats if stats else ScanStats(self.scan_id)
        if not stats: self.stats.add('scans', 1)

        self.latest_recon_features = {}
        self._captured_response_ids = set()
        self._latest_trace_id = ""
        self.trace_writer = NLPTraceWriter()
        self.trace_builder = HTTPTraceBuilder()
        self.route_decider = RouteDecider()
        
        self.tracker = RedirectTracker(self.db, self.scan_id, self.stats)
        self.waf_detector = WafDetector()
        self.extractor = FeatureExtractor(self.scan_id, self.waf_detector)
        self.discovery = DiscoveryRunner(self.db, self.scan_id, self.stats, lambda: ReconHttpClient.build_client(cookie=self.cookie, follow_redirects=True))
        
        self.Get_Response = None
        self.Get_Request = None
        self.waf_bypass_client = None
        self.waf_bypass_cookies = {}

    def _write_nlp_trace_bundle(self, trace_bundle):
        if not trace_bundle: return None
        decision = self.route_decider.decide(trace_bundle) if self.route_decider else None
        if decision:
            valuable_target = decision.get("valuable_target", 0)
            trace_bundle["request"]["label_is_valuable_target"] = valuable_target
            trace_bundle["response"]["label_is_valuable_target"] = valuable_target
            trace_bundle["label"].update({
                "label_target_value": valuable_target,
                "label_candidate_family": decision.get("candidate_family", ""),
                "label_confidence": decision.get("confidence", 0.0),
                "analyzer_route": decision.get("analyzer_route", ""),
                "analyzer_reason": decision.get("reason", ""),
            })
        self.trace_writer.write_trace_bundle(trace_bundle, db=self.db)
        self._latest_trace_id = trace_bundle["request"].get("trace_id", self._latest_trace_id)
        return decision

    def _capture_response_trace(self, response, fallback_url, source_module, label_source="passive_trace", input_names=None):
        if response is None: return None
        response_id = id(response)
        if response_id in self._captured_response_ids: return None
        self._captured_response_ids.add(response_id)
        bundle = self.trace_builder.build_from_response_object(
            scan_id=self.scan_id, source_module=source_module, response=response,
            fallback_url=fallback_url, parent_trace_id=self._latest_trace_id,
            label_source=label_source, input_names=input_names or [],
        )
        return self._write_nlp_trace_bundle(bundle)

    def _capture_analysis_trace(self, url, params):
        input_names = []
        for item in params.get("inputs", []):
            if (item or {}).get("name"): input_names.append(item["name"])
        input_names.extend(params.get("get_params", []))
        input_names.extend(params.get("post_params", []))
        bundle = self.trace_builder.build_candidate_trace(
            scan_id=self.scan_id, source_module="recon.response_analysis", page_url=url,
            request_method="GET", request_headers={**UA, **({'Cookie': self.cookie} if self.cookie else {})},
            input_names=ordered_unique(input_names), parent_trace_id=self._latest_trace_id, label_source="response_analysis",
        )
        return self._write_nlp_trace_bundle(bundle)

    def on_redirect_hop(self, resp, current, count):
        self._capture_response_trace(resp, current, "recon.track_redirects", label_source="passive_trace")
        features = self.extractor.extract_recon_features(resp, self.original_url, self.tracker.final_url, self.tracker.redirect_chain, self.tracker.cookies, is_redirect=True)
        _save_features_direct(self.db, features)
        self.stats.add('features', 1)
        try:
            append_target_scan_row(features, target_url=self.original_url, scan_id=self.scan_id, record_type="recon_redirect_hop")
        except Exception as e:
            print(f"    [-] Target scan dataset update skipped: {e}")

    def track_redirects(self):
        return self.tracker.track(self.original_url, self.cookie, on_hop_callback=self.on_redirect_hop)

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

    def save_ml_dataset(self, features, update_training=True, target_url=None):
        global _RECON_DATASET_COLUMNS_CACHE
        if features.get('error_occurred'): return
        self.latest_recon_features = dict(features)
        
        _save_features_direct(self.db, features)
        self.stats.add('features', 1)
        print(f"[+] Features saved to DB — status:{features.get('status_code')}")

        try:
            append_target_scan_row(features, target_url=target_url or self.original_url, scan_id=self.scan_id, record_type="recon_page")
        except Exception as e: pass

        if not update_training: return
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
                    for col in new_columns: existing[col] = 0
                    columns = columns + new_columns
                    existing.to_csv(ML_DATASET_FILE, index=False)
                elif not file_exists:
                    columns = list(features.keys())
                _RECON_DATASET_COLUMNS_CACHE = columns
                row = {col: features.get(col, 0) for col in columns}
                pd.DataFrame([row], columns=columns).to_csv(ML_DATASET_FILE, mode='a', header=not file_exists, index=False)
        except Exception as e:
            print(f"[-] Recon dataset update error: {e}")

    def print_request_response_details(self, response, url, is_final=True):
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            pq = (p.path or '/') + (f'?{p.query}' if p.query else '')
            tag = "FINAL" if is_final else "REDIRECT"
            print(f"\n{'='*60}\n{tag} REQUEST:\n{'='*60}")
            print(f"{response.request.method} {pq} HTTP/1.1\nHost: {p.hostname}")
            for k, v in response.request.headers.items():
                if k.lower() != 'host': print(f"{k}: {v}")
            print(f"\n{'='*60}\n{tag} RESPONSE {response.status_code}:\n{'='*60}")
            for k, v in response.headers.items(): print(f"{k}: {v}")
            body = response.text or ""
            print(f"\nBody ({len(body)} bytes):\n{body[:500]}{'...' if len(body)>500 else ''}\n{'='*60}")
            
            save_raw_response(self.db, self.scan_id, url, response.status_code, body, response.headers)
            self.stats.add('raw_responses', 1)
            self._capture_response_trace(response, url, "recon.final_response", label_source="passive_trace")
            
            if is_final:
                self.Get_Response = response.text
                self.Get_Request = f"{response.request.method} {pq} HTTP/1.1\nHost: {p.hostname}\n" + \
                                   "\n".join(f"{k}: {v}" for k,v in response.request.headers.items() if k.lower()!='host')
            
            features = self.extractor.extract_recon_features(response, self.original_url, self.tracker.final_url, self.tracker.redirect_chain, self.tracker.cookies, is_redirect=not is_final)
            self.save_ml_dataset(features)
        except Exception as e:
            print(f"[-] Display error: {e}")

    def Analyze_Response(self, url):
        if not self.Get_Response: return None
        html = self.Get_Response
        analysis = self.extractor.analyze_html_document(html, url, content_type="text/html")
        params = {
            'url': url, 'forms': analysis['forms'], 'get_params': analysis['get_params'], 'post_params': analysis['post_params'],
            'buttons': analysis['buttons'], 'links': analysis['links'], 'inputs': analysis['inputs'], 'endpoints': analysis['endpoints'],
            'cookies': self.tracker.get_cookies_for_requests(),
        }
        print(f"[+] Analysis: {len(params['forms'])} forms, {len(params['links'])} links, {len(params['inputs'])} inputs, {len(params['endpoints'])} endpoints")
        self._save_analysis(params, url)
        self._capture_analysis_trace(url, params)
        return params

    def Analyze_Request(self):
        if not self.Get_Request: return
        lines = [line for line in self.Get_Request.splitlines() if line.strip()]
        request_line = lines[0] if lines else ""
        headers = [line for line in lines[1:] if ":" in line]
        interesting = [line for line in headers if line.lower().startswith(("host:", "cookie:", "authorization:", "referer:", "origin:", "user-agent:", "accept:"))]
        print(f"[+] Request summary: {request_line}")
        print(f"[+] Request headers captured: {len(headers)}")
        for line in interesting[:10]: print(f"    {line}")

    def _save_analysis(self, params, url):
        lines = [f"TARGET: {url}", "="*50]
        for form in params['forms']: lines.append(f"\nForm [{form['method']}] {form['action']}: {form['inputs']}")
        for link in params['links'][:50]: lines.append(f"Link: {link}")
        lines.append("")
        lines.append(f"GET params : {len(params['get_params'])}")
        lines.append(f"POST params: {len(params['post_params'])}")
        lines.append(f"Endpoints  : {len(params['endpoints'])}")
        
        save_report(self.db, self.scan_id, 'response_analysis', "\n".join(lines))
        content = f"# Target: {url}\nGET: {params['get_params']}\nPOST: {params['post_params']}\nENDPOINTS:\n" + "\n".join(params['endpoints'])
        save_report(self.db, self.scan_id, 'xss_parameters', content)
        
        n_forms = save_forms(self.db, self.scan_id, url, params['forms'])
        n_endpoints = save_endpoints(self.db, self.scan_id, url, params['endpoints'], source='response_html')
        self.stats.add('forms', n_forms).add('endpoints', n_endpoints)

    def show_dataset_stats(self):
        try:
            if not (os.path.exists(ML_DATASET_FILE) and os.path.getsize(ML_DATASET_FILE)):
                print("[!] No dataset yet"); return
            df = pd.read_csv(ML_DATASET_FILE)
            print(f"\n[+] Dataset: {len(df)} rows | {df['target_url'].nunique()} targets | "
                  f"avg size {df['response_size'].mean():.0f} B | {df['has_https'].mean():.1%} HTTPS")
        except Exception as e:
            print(f"[-] Dataset stats error: {e}")

def test_connection(url, cookie=None, scan_id=None, stats=None, recon=None):
    try:
        recon = recon or ReconWebSite(url, cookie=cookie, scan_id=scan_id, stats=stats)
        response = recon.track_redirects()
        if response:
            print(f"[+] Reached: {recon.tracker.final_url}")
            recon.tracker.print_redirect_summary(recon.original_url)
            recon.tracker.save_redirect_analysis(recon.original_url)
            return response, recon
        print("[-] Could not reach target")
    except Exception as e:
        print(f"[-] Connection error: {e}")
    return None, None

def _scan_stats_snapshot(stats):
    snapshot = {}
    counts = getattr(stats, "_counts", {}) if stats else {}
    for table, values in counts.items():
        snapshot[table] = {"added": int(values.get("added", 0)), "modified": int(values.get("modified", 0)), "deleted": int(values.get("deleted", 0))}
    return snapshot

def MainRecon(url, cookie=None, scan_id=None, stats=None, interactive=True, enable_fuzz=None, return_details=False):
    details = {
        "ok": False, "original_url": url, "final_url": None, "status_code": None,
        "has_waf": False, "waf_vendors": [], "security_score": None, "security_grade": None,
        "stats": _scan_stats_snapshot(stats), "error": None, "feature_snapshot": {},
        "waf_bypass_cookies": {},
    }
    recon = None
    try:
        print(f"[*] Starting reconnaissance for: {url}")
        recon = ReconWebSite(url, cookie=cookie, scan_id=scan_id, stats=stats)
        response, recon_obj = test_connection(url, cookie=cookie, scan_id=scan_id, stats=stats, recon=recon)

        if not response or not recon_obj:
            _update_scan_status_direct(recon.db, recon.scan_id, 'failed', None, has_waf=False, waf_vendors=None, grade=None, score=None)
            details["error"] = "Could not reach target"
            details["stats"] = _scan_stats_snapshot(getattr(recon, "stats", stats))
            details["feature_snapshot"] = dict(getattr(recon, "latest_recon_features", {}) or {})
            return details if return_details else False

        recon = recon_obj
        if stats: recon.stats = stats

        print("\n[*] WAF check...")
        waf_result = recon.waf_detector.detect_waf(recon.tracker.final_url or url, response)
        waf_vendors = waf_result["vendors"]
        present = recon.print_security_summary(response)
        grade = "A" if present >= 7 else "B" if present >= 5 else "C" if present >= 3 else "F"
        
        details.update({
            "final_url": recon.tracker.final_url, "status_code": getattr(response, "status_code", None),
            "has_waf": waf_result["detected"], "waf_vendors": waf_vendors,
            "security_score": present, "security_grade": grade,
        })

        # ── WAF BYPASS: if WAF detected, try Botasaurus bypass ──
        if waf_result["detected"]:
            print(f"\n[*] WAF detected ({', '.join(waf_vendors)}) — attempting bypass...")
            bypass_client = create_bypass_client(waf_result, cookie=cookie)
            if bypass_client and bypass_client.available:
                recon.waf_bypass_client = bypass_client
                bypass_target = recon.tracker.final_url or url
                bypass_resp = bypass_client.get(bypass_target)
                if bypass_resp and bypass_resp.status_code and bypass_resp.status_code < 400:
                    print(f"[+] WAF bypass successful! Got {len(bypass_resp.text or '')} bytes")
                    # Harvest cookies for downstream scanners
                    recon.waf_bypass_cookies = bypass_client.get_harvested_cookies()
                    details["waf_bypass_cookies"] = dict(recon.waf_bypass_cookies)
                    # Update the response with bypassed content
                    response = bypass_resp
                else:
                    print("[-] WAF bypass did not return a clean response — continuing with original")
            elif not is_bypass_available():
                print("[!] Botasaurus not installed. Install with: pip install botasaurus")
                print("[!] Continuing scan without WAF bypass...")

        recon.print_request_response_details(response, recon.tracker.final_url, is_final=True)

        print("\n[*] Framework detection...")
        try:
            fw_detector = FrameworkDetector(session=None, cookie=cookie, timeout=HTTP_TIMEOUT)
            fw_results = fw_detector.detect(recon.tracker.final_url or url)
            fw_detector.save_results(recon.tracker.final_url or url, fw_results)
            print(f"    [+] Detected framework: {fw_results.get('framework', 'unknown')} (confidence: {fw_results.get('confidence', 'none')})")
        except Exception as e:
            print(f"    [-] Framework detection skipped: {e}")

        if recon.Get_Response:
            save_report(recon.db, recon.scan_id, 'response_content', recon.Get_Response)
        if recon.Get_Request:
            save_report(recon.db, recon.scan_id, 'request_headers', recon.Get_Request)
            
        recon.Analyze_Response(recon.tracker.final_url)
        recon.Analyze_Request()
        
        if recon.tracker.cookies: save_report(recon.db, recon.scan_id, 'cookies_full', recon.tracker.cookies)
        if recon.tracker.headers: save_report(recon.db, recon.scan_id, 'headers_full', recon.tracker.headers)

        _update_scan_status_direct(recon.db, recon.scan_id, 'completed', recon.tracker.final_url, has_waf=bool(waf_vendors), waf_vendors=waf_vendors, grade=grade, score=present)
        recon.stats.update('scans', 1)

        target = recon.tracker.final_url or recon.original_url
        jobs = [("subdomain", recon.discovery.get_subdomain), ("urls", recon.discovery.get_urls), ("params", recon.discovery.get_parameters)]
        
        print("\n[*] Starting parallel discovery (subdomains + URLs + params)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DISCOVERY_WORKERS, len(jobs))) as executor:
            future_map = {executor.submit(handler, target): name for name, handler in jobs}
            for future in concurrent.futures.as_completed(future_map):
                try: future.result(); print(f"    [+] Discovery task complete: {future_map[future]}")
                except Exception as ex: print(f"    [-] Discovery task failed ({future_map[future]}): {ex}")

        should_fuzz = False
        if enable_fuzz is None:
            if interactive: should_fuzz = robust_input("\nFuzz with ffuf? (y/n): ", default='n') == 'y'
        else: should_fuzz = bool(enable_fuzz)

        if should_fuzz: recon.discovery.fuzz_url(target)
        elif not interactive or enable_fuzz is not None: print("[*] Fuzzing skipped for this run.")

        if stats is None:
            recon.stats.print_summary()
            import io, sys
            old_stdout, sys.stdout = sys.stdout, io.StringIO()
            recon.stats.print_summary()
            sys.stdout, buf_val = old_stdout, sys.stdout.getvalue()
            save_report(recon.db, recon.scan_id, 'scan_stats', buf_val)
            print(f"[+] Scan completed. Stats saved to DB.")
        else:
            print(f"[+] Recon phase complete.")

        recon.show_dataset_stats()
        details["ok"] = True
        details["stats"] = _scan_stats_snapshot(recon.stats)
        details["feature_snapshot"] = dict(getattr(recon, "latest_recon_features", {}) or {})
        details["waf_bypass_cookies"] = dict(getattr(recon, "waf_bypass_cookies", {}) or {})
        return details if return_details else True

    except Exception as e:
        import traceback
        print(f"[-] Error: {e}"); traceback.print_exc()
        details["error"] = str(e)
    details["stats"] = _scan_stats_snapshot(getattr(recon, "stats", stats))
    details["feature_snapshot"] = dict(getattr(recon, "latest_recon_features", {}) or {}) if recon else {}
    return details if return_details else False

if __name__ == "__main__":
    MainRecon(input("Enter URL: "))
