#!/usr/bin/env python3
import os
import re
import pandas as pd
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime

# -- Constants --------------------------------------------------------------
DATA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_EVAL_DIR = os.path.join(DATA_DIR, "Datasets", "Datasets_for_Model_Evaluation")
VULN_DATASET = os.path.join(MODEL_EVAL_DIR, "vulnerability", "vulnerability_ml_dataset.csv")

CANONICAL_VULN_COLUMNS = [
    'scan_id', 'url', 'domain', 'timestamp', 'total_vulnerabilities',
    'has_sql_injection', 'has_xss', 'has_command_injection', 'has_path_traversal',
    'has_file_inclusion', 'vulnerability_score', 'critical_vuln_count',
    'high_vuln_count', 'sqlmap_vulns_found', 'dalfox_vulns_found',
    'commix_vulns_found', 'tools_used_count', 'sqlmap_confidence_avg',
    'dalfox_confidence_avg', 'commix_confidence_avg', 'used_previous_scan',
    'previous_scan_indicators', 'scan_hour', 'scan_day_of_week', 'url_length',
    'has_https', 'path_depth', 'has_query_params', 'num_query_params',
    'subdomain_count', 'prev_has_forms', 'prev_has_inputs', 'prev_form_count',
    'prev_input_count', 'prev_has_debug_info', 'prev_has_error_messages',
    'prev_technology_php', 'prev_technology_aspnet', 'prev_technology_wordpress',
    'prev_security_headers_count', 'prev_response_size', 'days_since_last_scan',
    'vuln_density', 'tool_effectiveness', 'security_risk_score',
    'input_vulnerability_ratio', 'previous_scan_accuracy', 'total_issues',
    'issue_density', 'has_idor'
]

TRUTHY_ENV_VALUES = {"1", "true", "yes", "on", "enable", "enabled"}
FALSY_ENV_VALUES = {"0", "false", "no", "off", "disable", "disabled"}


def training_dataset_updates_enabled(default=True):
    raw = str(os.getenv("SMART_HUNTER_UPDATE_DATASET", "")).strip().lower()
    if not raw:
        return default
    if raw in TRUTHY_ENV_VALUES:
        return True
    if raw in FALSY_ENV_VALUES:
        return False
    return default

def extract_vulnerability_features(url, response, vulnerabilities_found):
    features = {'url': url}
    content = (response.text or "").lower()
    
    # Use BeautifulSoup for structural analysis
    try:
        soup = BeautifulSoup(content, 'html.parser')
    except Exception:
        soup = None

    parsed = urlparse(url)

    # 1. Base Structure Features
    features['has_parameters'] = int(bool(parsed.query))
    features['has_forms'] = int(bool(soup.find('form'))) if soup else 0
    
    # 2. Cookies
    has_cookies = 0
    if response and hasattr(response, 'headers'):
        if 'set-cookie' in [k.lower() for k in response.headers.keys()]:
            has_cookies = 1
    features['has_cookies'] = has_cookies

    # 3. Security Indicators
    error_indicators = ['error', 'exception', 'warning', 'stack trace', 'fatal error', 'unexpected token']
    features['has_error_messages'] = int(any(indicator in content for indicator in error_indicators))
    
    db_indicators = ['sql', 'database', 'mysql', 'postgresql', 'oracle', 'sqlite', 'mariadb', 'mongodb', 'syntax error']
    features['has_database_errors'] = int(any(indicator in content for indicator in db_indicators))
    
    login_indicators = ['login', 'signin', 'auth', 'account', 'register', 'signup']
    has_login = int(any(indicator in content for indicator in login_indicators))
    if soup:
        if soup.find('input', {'type': 'password'}) or soup.find('input', {'name': re.compile(r'pass|pwd|login|user', re.I)}):
            has_login = 1
    features['has_login'] = has_login
    
    # 4. Inputs & Uploads
    if soup:
        features['has_upload'] = int(bool(soup.find('input', {'type': 'file'})))
        features['has_hidden_inputs'] = int(bool(soup.find('input', {'type': 'hidden'})))
        features['has_script_tags'] = int(bool(soup.find('script')))
    else:
        features['has_upload'] = 0
        features['has_hidden_inputs'] = 0
        features['has_script_tags'] = int('<script' in content)

    # 5. File Inclusion & Reflection
    file_include_indicators = ['include', 'require', '/etc/passwd', 'c:\\windows', 'file=', 'path=', 'src=']
    features['has_file_includes'] = int(any(indicator in content or indicator in url.lower() for indicator in file_include_indicators))
    
    query_params = parse_qs(parsed.query)
    reflected = False
    for vals in query_params.values():
        for v in vals:
            if len(v) > 2 and v.lower() in content:
                reflected = True
                break
        if reflected: break
    features['has_reflection'] = int(reflected)
    
    # 6. Sensitive Functions (JS or Backend indications)
    features['has_eval'] = int('eval(' in content)
    features['has_exec'] = int('exec(' in content)
    features['has_system'] = int('system(' in content)

    # 7. Vulnerability Labels (Labels: 0 or 1 based on HIGH confidence scan results)
    label_cols = [
        'sqli_vuln', 'xss_vuln', 'cmdi_vuln', 'pt_vuln', 
        'lfi_vuln', 'rfi_vuln', 'idor_vuln'
    ]
    for lbl in label_cols:
        features[lbl] = 0
    
    type_mapping = {
        'sql injection': 'sqli_vuln',
        'cross-site scripting': 'xss_vuln',
        'xss': 'xss_vuln',
        'command injection': 'cmdi_vuln',
        'path traversal': 'pt_vuln',
        'directory traversal': 'pt_vuln',
        'local file inclusion': 'lfi_vuln',
        'lfi': 'lfi_vuln',
        'remote file inclusion': 'rfi_vuln',
        'rfi': 'rfi_vuln',
        'idor': 'idor_vuln'
    }
    
    for finding in vulnerabilities_found:
        ftype = finding.get('type', '').lower()
        conf = finding.get('confidence', 'unknown').lower()
        if conf == 'high':
            for key, val in type_mapping.items():
                if key in ftype:
                    features[val] = 1
                    break

    # 8. Ensure Column Order (per user request)
    columns = [
        'url','has_parameters','has_forms','has_cookies','has_error_messages','has_database_errors','has_login',
        'has_upload','has_hidden_inputs','has_script_tags','has_file_includes','has_reflection',
        'has_eval','has_exec','has_system','sqli_vuln','xss_vuln','cmdi_vuln','pt_vuln','lfi_vuln','rfi_vuln','idor_vuln'
    ]
    
    ordered_features = {}
    for col in columns:
        ordered_features[col] = features.get(col, 0)
        
    return ordered_features

def _to_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except Exception:
        return default

def _domain_for(url):
    try:
        return urlparse(str(url)).netloc.lower()
    except Exception:
        return ""

def _has_any(features, *names):
    return int(any(_to_int(features.get(name, 0)) for name in names))

def _build_canonical_vulnerability_row(features):
    url = features.get('target_url') or features.get('url') or ''
    now = datetime.now()
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    path_parts = [part for part in parsed.path.split('/') if part]

    has_sql_injection = _has_any(features, 'has_sql_injection', 'sqli_vuln')
    has_xss = _has_any(features, 'has_xss', 'xss_vuln')
    has_command_injection = _has_any(features, 'has_command_injection', 'cmdi_vuln')
    has_path_traversal = _has_any(features, 'has_path_traversal', 'pt_vuln')
    has_file_inclusion = _has_any(features, 'has_file_inclusion', 'lfi_vuln', 'rfi_vuln')
    has_idor = _has_any(features, 'has_idor', 'idor_vuln')

    total_vulns = (
        has_sql_injection +
        has_xss +
        has_command_injection +
        has_path_traversal +
        has_file_inclusion +
        has_idor
    )

    row = {col: 0 for col in CANONICAL_VULN_COLUMNS}
    row.update({
        'scan_id': features.get('scan_id', ''),
        'url': url,
        'domain': _domain_for(url),
        'timestamp': features.get('timestamp') or now.isoformat(),
        'total_vulnerabilities': total_vulns,
        'has_sql_injection': has_sql_injection,
        'has_xss': has_xss,
        'has_command_injection': has_command_injection,
        'has_path_traversal': has_path_traversal,
        'has_file_inclusion': has_file_inclusion,
        'vulnerability_score': float(total_vulns),
        'critical_vuln_count': total_vulns,
        'high_vuln_count': total_vulns,
        'sqlmap_vulns_found': has_sql_injection,
        'dalfox_vulns_found': has_xss,
        'commix_vulns_found': has_command_injection,
        'tools_used_count': int(has_sql_injection + has_xss + has_command_injection),
        'sqlmap_confidence_avg': float(has_sql_injection),
        'dalfox_confidence_avg': float(has_xss),
        'commix_confidence_avg': float(has_command_injection),
        'used_previous_scan': 0,
        'previous_scan_indicators': '',
        'scan_hour': now.hour,
        'scan_day_of_week': now.weekday(),
        'url_length': len(url),
        'has_https': int(parsed.scheme.lower() == 'https'),
        'path_depth': len(path_parts),
        'has_query_params': int(bool(parsed.query)),
        'num_query_params': len(query_params),
        'subdomain_count': max(0, len(parsed.netloc.split('.')) - 2) if parsed.netloc else 0,
        'prev_has_forms': _to_int(features.get('has_forms', 0)),
        'prev_has_inputs': 0,
        'prev_form_count': _to_int(features.get('has_forms', 0)),
        'prev_input_count': 0,
        'prev_has_debug_info': 0,
        'prev_has_error_messages': _to_int(features.get('has_error_messages', 0)),
        'prev_technology_php': 0,
        'prev_technology_aspnet': 0,
        'prev_technology_wordpress': 0,
        'prev_security_headers_count': 0,
        'prev_response_size': 0,
        'days_since_last_scan': 0,
        'vuln_density': float(total_vulns),
        'tool_effectiveness': float(total_vulns),
        'security_risk_score': float(total_vulns),
        'input_vulnerability_ratio': float(total_vulns),
        'previous_scan_accuracy': 0,
        'total_issues': total_vulns,
        'issue_density': float(total_vulns),
        'has_idor': has_idor,
    })
    return row

def update_dataset(features):
    if not features:
        return

    os.makedirs(os.path.dirname(VULN_DATASET), exist_ok=True)
    
    try:
        row = _build_canonical_vulnerability_row(features)
        df = pd.DataFrame([row], columns=CANONICAL_VULN_COLUMNS)
        file_exists = os.path.exists(VULN_DATASET) and os.path.getsize(VULN_DATASET) > 0
        df.to_csv(VULN_DATASET, mode='a', header=not file_exists, index=False)
        print(f"    [+] Vulnerability dataset updated for {row.get('url')} -> {VULN_DATASET}")
        return True
    except Exception as e:
        print(f"    [-] Error updating dataset: {e}")
        return False

if __name__ == "__main__":
    print("[*] Dataset System Utility Loaded")
