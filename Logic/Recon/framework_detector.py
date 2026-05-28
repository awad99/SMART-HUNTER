import os
import json
import requests
from urllib.parse import urlparse

# Go up 3 levels from Logic/Recon/framework_detector.py to reach SMART-HUNTER-main
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_DIR = os.path.join(BASE_DIR, 'Data')
SIGNATURES_FILE = os.path.join(DATASET_DIR, 'Payloads', 'csrf_payloads', 'framework_signatures.json')
RESULTS_DIR = os.path.join(DATASET_DIR, 'csrf_scan_results')
RESULTS_FILE = os.path.join(RESULTS_DIR, 'framework_recon.json')

class FrameworkDetector:
    def __init__(self, session=None, cookie=None, timeout=10):
        self.session = session or requests.Session()
        self.cookie = cookie
        self.timeout = timeout
        if self.cookie:
            self.session.headers.update({"Cookie": self.cookie})
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        self.signatures = self._load_signatures()

    def _load_signatures(self):
        if not os.path.exists(SIGNATURES_FILE):
            print(f"[-] Signatures file not found: {SIGNATURES_FILE}")
            return {}
        try:
            with open(SIGNATURES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('frameworks', {})
        except Exception as e:
            print(f"[-] Error loading signatures: {e}")
            return {}

    def detect(self, url):
        print(f"[*] Detecting framework for {url}...")
        results = {'framework': 'unknown', 'confidence': 'none', 'evidence': []}
        
        if not self.signatures:
            return results

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
        except Exception as e:
            print(f"[-] Request failed during framework detection: {e}")
            return results

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = response.cookies.get_dict()
        html = response.text.lower()
        
        scores = {}
        evidence_map = {}

        for fw, sigs in self.signatures.items():
            scores[fw] = 0
            evidence_map[fw] = []
            
            # Check Headers
            for h in sigs.get('headers', []):
                h_name = h.get('name', '').lower()
                h_pattern = h.get('pattern', '').lower()
                if h_name in headers and (not h_pattern or h_pattern in headers[h_name]):
                    scores[fw] += 1
                    evidence_map[fw].append(f"Header match: {h_name}")
            
            # Check Cookies
            for c in sigs.get('cookies', []):
                c_name = c.get('name', '')
                if any(c_name.lower() in k.lower() for k in cookies.keys()):
                    scores[fw] += 1
                    evidence_map[fw].append(f"Cookie match: {c_name}")
            
            # Check HTML patterns
            for hp in sigs.get('html_patterns', []):
                if hp.lower() in html:
                    scores[fw] += 1
                    evidence_map[fw].append(f"HTML pattern match: {hp}")
                    
        # Determine best match
        best_fw = 'unknown'
        max_score = 0
        for fw, score in scores.items():
            if score > max_score:
                max_score = score
                best_fw = fw
                
        if max_score > 0:
            confidence = 'low'
            if max_score >= 3:
                confidence = 'high'
            elif max_score == 2:
                confidence = 'medium'
                
            results = {
                'framework': best_fw,
                'confidence': confidence,
                'evidence': evidence_map[best_fw]
            }
        
        return results

    def save_results(self, url, results):
        os.makedirs(RESULTS_DIR, exist_ok=True)
        try:
            # load existing
            existing = {}
            if os.path.exists(RESULTS_FILE):
                with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
            
            domain = urlparse(url).netloc
            existing[domain] = results
            
            with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(existing, f, indent=4)
        except Exception as e:
            print(f"[-] Error saving framework results: {e}")

    @staticmethod
    def load_results(url):
        if not os.path.exists(RESULTS_FILE):
            return None
        try:
            with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
                existing = json.load(f)
                domain = urlparse(url).netloc
                return existing.get(domain)
        except Exception as e:
            print(f"[-] Error loading framework results: {e}")
            return None

def detect_framework(url, session=None, cookie=None):
    detector = FrameworkDetector(session=session, cookie=cookie)
    results = detector.detect(url)
    detector.save_results(url, results)
    return results
