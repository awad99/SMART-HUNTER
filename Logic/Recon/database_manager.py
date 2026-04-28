import psycopg2
from psycopg2.extras import execute_values
import json, os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ── استيراد دوال Queries ──────────────────────────────────────
from Data.Queries.q_scans          import create_scan          as _q_create_scan
from Data.Queries.q_scans          import update_scan_status   as _q_update_scan
from Data.Queries.q_vulnerabilities import save_vulnerability       as _q_vuln_one
from Data.Queries.q_vulnerabilities import save_vulnerabilities_batch as _q_vuln_batch
from Data.Queries.q_features        import save_features        as _q_features
from Data.Queries.q_fuzzing         import save_fuzz_results    as _q_fuzzing
from Data.Queries.q_subdomains      import save_subdomains      as _q_subdomains
from Data.Queries.q_raw_responses   import save_raw_response    as _q_raw
from Data.Queries.q_redirects       import save_redirect_hop    as _q_redirect
from Data.Queries.q_headers         import save_headers         as _q_headers
from Data.Queries.q_cookies         import save_cookies         as _q_cookies
from Data.Queries.q_endpoints       import save_endpoints       as _q_endpoints
from Data.Queries.q_forms           import save_forms           as _q_forms
from Data.Queries.q_reports         import save_report         as _q_reports


class DatabaseManager:
    def __init__(self, host=None, database=None, user=None, password=None, port=None):
        self.conn_params = {
            "host": host or os.getenv("DB_HOST", "localhost"),
            "database": database or os.getenv("DB_DATABASE", "smart_hunter"),
            "user": user or os.getenv("DB_USER", "postgres"),
            "password": password or os.getenv("DB_PASSWORD", "2002"),
            "port": port or os.getenv("DB_PORT", "5432"),
        }
        self.conn = None

    # ── Connection ────────────────────────────────────────────
    def connect(self):
        try:
            if not self.conn or self.conn.closed:
                self.conn = psycopg2.connect(**self.conn_params)
            return True
        except Exception as e:
            print(f"[-] Database connection error: {e}")
            return False

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()

    # ── Internal helpers ──────────────────────────────────────
    def _execute(self, query, params=None, commit=True):
        if not self.connect(): return None
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if commit:
                    self.conn.commit()
                if cur.description:
                    return cur.fetchone()
            return True
        except Exception as e:
            print(f"[-] DB execution error: {e}")
            self.conn.rollback()
            return None

    def _execute_all(self, query, params=None):
        if not self.connect(): return []
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall()
        except Exception as e:
            print(f"[-] DB fetch all error: {e}")
            return []

    def _execute_batch(self, query, data):
        if not self.connect(): return
        try:
            with self.conn.cursor() as cur:
                execute_values(cur, query, data)
                self.conn.commit()
        except Exception as e:
            print(f"[-] DB Batch insert error: {e}")
            self.conn.rollback()

    # =========================================================================
    # Scans — delegate to q_scans.py
    # =========================================================================
    def create_scan(self, scan_id, original_url, user_agent=None, cookie=None, proxy=None):
        return _q_create_scan(self, scan_id, original_url, user_agent, cookie, proxy)

    def update_scan_status(self, scan_id, status='completed', final_url=None,
                           has_waf=False, waf_vendors=None, grade=None, score=None):
        return _q_update_scan(self, scan_id, status, final_url, has_waf, waf_vendors, grade, score)

    # =========================================================================
    # Vulnerabilities — delegate to q_vulnerabilities.py
    # =========================================================================
    def add_vulnerability(self, scan_id, vuln_dict):
        return _q_vuln_one(self, scan_id, vuln_dict)

    def add_vulnerabilities(self, scan_id, vulns_list):
        return _q_vuln_batch(self, scan_id, vulns_list)

    # =========================================================================
    # Features — delegate to q_features.py
    # =========================================================================
    def add_features(self, features):
        return _q_features(self, features)

    # =========================================================================
    # Redirects, Headers, Cookies — delegate
    # =========================================================================
    def add_redirect_hop(self, scan_id, hop_number, url, status_code, location, hop_type):
        return _q_redirect(self, scan_id, hop_number, url, status_code, location, hop_type)

    def add_headers(self, scan_id, url, status_code, headers_dict):
        return _q_headers(self, scan_id, url, status_code, headers_dict)

    def add_cookies(self, scan_id, url, cookies_list):
        return _q_cookies(self, scan_id, url, cookies_list)

    # =========================================================================
    # Forms, Endpoints, Fuzzing, Subdomains — delegate
    # =========================================================================
    def add_forms(self, scan_id, url, forms_list):
        return _q_forms(self, scan_id, url, forms_list)

    def add_endpoints(self, scan_id, url, endpoints_list, source="crawler"):
        return _q_endpoints(self, scan_id, url, endpoints_list, source)

    def add_fuzz_results(self, scan_id, results_list):
        return _q_fuzzing(self, scan_id, results_list)

    def add_subdomains(self, scan_id, subdomains_list, source="script"):
        return _q_subdomains(self, scan_id, subdomains_list, source)

    # =========================================================================
    # Raw Responses — delegate to q_raw_responses.py
    # =========================================================================
    def add_raw_response(self, scan_id, url, status_code, body, headers):
        return _q_raw(self, scan_id, url, status_code, body, headers)

    # =========================================================================
    # Reports — delegate to q_reports.py
    # =========================================================================
    def add_report(self, scan_id, report_type, content):
        return _q_reports(self, scan_id, report_type, content)
