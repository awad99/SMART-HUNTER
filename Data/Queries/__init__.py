# Data/Queries/__init__.py
# نقطة دخول موحدة - استورد الدوال مباشرة من الملفات الفرعية
from Data.Queries.q_scans          import create_scan, update_scan_status, update_scan_original_url
from Data.Queries.q_vulnerabilities import save_vulnerability, save_vulnerabilities_batch
from Data.Queries.q_features        import save_features
from Data.Queries.q_fuzzing         import save_fuzz_results
from Data.Queries.q_subdomains      import save_subdomains
from Data.Queries.q_raw_responses   import save_raw_response
from Data.Queries.q_redirects       import save_redirect_hop
from Data.Queries.q_headers         import save_headers
from Data.Queries.q_cookies         import save_cookies
from Data.Queries.q_endpoints       import save_endpoints
from Data.Queries.q_forms           import save_forms
from Data.Queries.scan_stats        import ScanStats

__all__ = [
    'create_scan', 'update_scan_status',
    'save_vulnerability', 'save_vulnerabilities_batch',
    'save_features', 'save_fuzz_results', 'save_subdomains',
    'save_raw_response', 'save_redirect_hop', 'save_headers',
    'save_cookies', 'save_endpoints', 'save_forms',
    'ScanStats',
]
