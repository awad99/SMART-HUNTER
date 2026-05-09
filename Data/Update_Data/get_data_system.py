#!/usr/bin/env python3
import os
import re
import pandas as pd
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
from Data.Update_Data.target_scan_dataset import append_target_scan_row

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

def _to_float(value, default=0.0):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default

def _safe_div(numerator, denominator, default=0.0):
    try:
        if not denominator:
            return default
        return float(numerator) / float(denominator)
    except Exception:
        return default

def _domain_for(url):
    try:
        return urlparse(str(url)).netloc.lower()
    except Exception:
        return ""

def _has_any(features, *names):
    return int(any(_to_int(features.get(name, 0)) for name in names))

def _finding_terms(features):
    terms = []
    for key in (
        'vulnerability_type',
        'finding_types',
        'confirmed_vulnerability_types',
        'candidate_vulnerability_types',
    ):
        value = features.get(key)
        if isinstance(value, (list, tuple, set)):
            terms.extend(str(item) for item in value if item)
        elif value:
            parts = [part.strip() for part in re.split(r"[|,;/]+", str(value)) if part.strip()]
            terms.extend(parts)

    for key in ('confirmed_findings', 'vulnerabilities_found', 'findings'):
        value = features.get(key)
        if not isinstance(value, (list, tuple)):
            continue
        for item in value:
            if isinstance(item, dict):
                finding_type = item.get('type') or item.get('vulnerability_type') or item.get('name')
                if finding_type:
                    terms.append(str(finding_type))
            elif item:
                terms.append(str(item))

    return " | ".join(terms).lower()

def _has_term(text, *needles):
    haystack = str(text or "").lower()
    return int(any(needle in haystack for needle in needles))

def _build_indicator_summary(features):
    if features.get('previous_scan_indicators'):
        return str(features.get('previous_scan_indicators'))

    parts = []
    for key, label in (
        ('pages_crawled', 'pages'),
        ('forms_found', 'form_params'),
        ('params_found', 'params'),
        ('recon_params_found', 'recon_params'),
        ('subdomains_found', 'subdomains'),
        ('endpoints_found', 'endpoints'),
    ):
        value = _to_int(features.get(key, 0))
        if value > 0:
            parts.append(f"{label}={value}")

    for key, label in (
        ('has_waf', 'waf'),
        ('has_error_messages', 'errors'),
        ('has_sql_errors', 'sql_errors'),
        ('has_database_errors', 'db_errors'),
        ('has_debug_info', 'debug'),
        ('has_login_form', 'login_form'),
        ('has_api_keys', 'api_keys'),
        ('has_jwt', 'jwt'),
        ('body_truncated_for_analysis', 'truncated_body'),
    ):
        if _to_int(features.get(key, 0)):
            parts.append(label)

    status_code = _to_int(features.get('status_code', 0))
    if status_code:
        parts.append(f"status={status_code}")

    content_type = str(features.get('content_type', '') or '').strip()
    if content_type:
        parts.append(f"content={content_type}")

    return "|".join(parts)

def _build_canonical_vulnerability_row(features):
    url = features.get('target_url') or features.get('url') or ''
    now = datetime.now()
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    path_parts = [part for part in parsed.path.split('/') if part]
    finding_terms = _finding_terms(features)

    has_sql_injection = max(
        _has_any(features, 'has_sql_injection', 'sqli_vuln'),
        _has_term(finding_terms, 'sql injection', 'sqli'),
    )
    has_xss = max(
        _has_any(features, 'has_xss', 'xss_vuln'),
        _has_term(finding_terms, 'cross-site scripting', 'xss'),
    )
    has_command_injection = max(
        _has_any(features, 'has_command_injection', 'cmdi_vuln'),
        _has_term(finding_terms, 'command injection', 'cmdi', 'rce'),
    )
    has_path_traversal = max(
        _has_any(features, 'has_path_traversal', 'pt_vuln'),
        _has_term(finding_terms, 'path traversal', 'directory traversal'),
    )
    has_file_inclusion = max(
        _has_any(features, 'has_file_inclusion', 'lfi_vuln', 'rfi_vuln'),
        _has_term(finding_terms, 'file inclusion', 'lfi', 'rfi'),
    )
    has_idor = max(
        _has_any(features, 'has_idor', 'idor_vuln'),
        _has_term(finding_terms, 'idor'),
    )

    detected_total_vulns = (
        has_sql_injection +
        has_xss +
        has_command_injection +
        has_path_traversal +
        has_file_inclusion +
        has_idor
    )
    provided_total_vulns = max(
        _to_int(features.get('total_vulnerabilities', -1), -1),
        _to_int(features.get('confirmed_vulnerabilities', -1), -1),
        _to_int(features.get('confirmed_vuln_count', -1), -1),
    )
    total_vulns = max(detected_total_vulns, provided_total_vulns, 0)

    prev_has_forms = _to_int(features.get('prev_has_forms', features.get('has_forms', 0)))
    prev_has_inputs = _to_int(features.get('prev_has_inputs', features.get('has_inputs', 0)))
    prev_form_count = max(
        _to_int(features.get('prev_form_count', features.get('form_count', 0))),
        prev_has_forms,
    )
    prev_input_count = max(
        _to_int(features.get('prev_input_count', features.get('input_count', 0))),
        _to_int(features.get('forms_found', 0)),
        prev_has_inputs,
    )
    prev_has_debug_info = _to_int(features.get('prev_has_debug_info', features.get('has_debug_info', 0)))
    prev_has_error_messages = _to_int(
        features.get('prev_has_error_messages', features.get('has_error_messages', features.get('has_database_errors', 0)))
    )
    prev_technology_php = _to_int(features.get('prev_technology_php', features.get('tech_php', 0)))
    prev_technology_aspnet = _to_int(features.get('prev_technology_aspnet', features.get('tech_aspnet', 0)))
    prev_technology_wordpress = _to_int(features.get('prev_technology_wordpress', features.get('tech_wordpress', 0)))
    prev_security_headers_count = _to_int(
        features.get('prev_security_headers_count', features.get('security_headers_count', 0))
    )
    prev_response_size = _to_int(features.get('prev_response_size', features.get('response_size', 0)))
    scan_tools_used_count = _to_int(features.get('scan_tools_used_count', features.get('tools_used_count', 0)))
    tools_used_count = max(scan_tools_used_count, int(has_sql_injection + has_xss + has_command_injection))
    total_issues = max(
        total_vulns,
        _to_int(features.get('total_issues', 0)),
        _to_int(features.get('candidate_issue_count', 0)),
    )
    attack_surface = max(
        1,
        prev_input_count +
        _to_int(features.get('params_found', 0)) +
        _to_int(features.get('recon_params_found', 0)) +
        _to_int(features.get('num_query_params', len(query_params))),
    )
    vuln_density = _to_float(features.get('vuln_density', _safe_div(total_vulns, attack_surface)))
    tool_effectiveness = _to_float(
        features.get(
            'tool_effectiveness',
            _safe_div(total_vulns, tools_used_count, default=0.0),
        )
    )
    issue_density = _to_float(
        features.get(
            'issue_density',
            _safe_div(total_issues, max(prev_response_size / 1024.0, 1.0)),
        )
    )
    security_risk_score = _to_float(
        features.get(
            'security_risk_score',
            (
                total_vulns * 3.0 +
                prev_has_debug_info * 0.75 +
                prev_has_error_messages * 0.75 +
                _to_int(features.get('has_sql_errors', features.get('has_database_errors', 0))) * 0.75 +
                _to_int(features.get('has_file_paths', 0)) * 0.5 +
                _to_int(features.get('has_query_params', int(bool(parsed.query)))) * 0.3 +
                prev_has_forms * 0.25 +
                prev_has_inputs * 0.25 +
                max(0, 5 - prev_security_headers_count) * 0.2
            ),
        )
    )
    input_vulnerability_ratio = _to_float(
        features.get('input_vulnerability_ratio', _safe_div(total_vulns, max(prev_input_count, 1)))
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
        'critical_vuln_count': max(_to_int(features.get('critical_vuln_count', 0)), total_vulns),
        'high_vuln_count': max(_to_int(features.get('high_vuln_count', 0)), total_vulns),
        'sqlmap_vulns_found': max(_to_int(features.get('sqlmap_vulns_found', 0)), has_sql_injection),
        'dalfox_vulns_found': max(_to_int(features.get('dalfox_vulns_found', 0)), has_xss),
        'commix_vulns_found': max(_to_int(features.get('commix_vulns_found', 0)), has_command_injection),
        'tools_used_count': tools_used_count,
        'sqlmap_confidence_avg': _to_float(features.get('sqlmap_confidence_avg', float(has_sql_injection))),
        'dalfox_confidence_avg': _to_float(features.get('dalfox_confidence_avg', float(has_xss))),
        'commix_confidence_avg': _to_float(features.get('commix_confidence_avg', float(has_command_injection))),
        'used_previous_scan': _to_int(features.get('used_previous_scan', 0)),
        'previous_scan_indicators': _build_indicator_summary(features),
        'scan_hour': _to_int(features.get('scan_hour', now.hour)),
        'scan_day_of_week': _to_int(features.get('scan_day_of_week', now.weekday())),
        'url_length': _to_int(features.get('url_length', len(url))),
        'has_https': _to_int(features.get('has_https', int(parsed.scheme.lower() == 'https'))),
        'path_depth': _to_int(features.get('path_depth', len(path_parts))),
        'has_query_params': _to_int(features.get('has_query_params', int(bool(parsed.query)))),
        'num_query_params': _to_int(features.get('num_query_params', len(query_params))),
        'subdomain_count': _to_int(
            features.get('subdomain_count', max(0, len(parsed.netloc.split('.')) - 2) if parsed.netloc else 0)
        ),
        'prev_has_forms': prev_has_forms,
        'prev_has_inputs': prev_has_inputs,
        'prev_form_count': prev_form_count,
        'prev_input_count': prev_input_count,
        'prev_has_debug_info': prev_has_debug_info,
        'prev_has_error_messages': prev_has_error_messages,
        'prev_technology_php': prev_technology_php,
        'prev_technology_aspnet': prev_technology_aspnet,
        'prev_technology_wordpress': prev_technology_wordpress,
        'prev_security_headers_count': prev_security_headers_count,
        'prev_response_size': prev_response_size,
        'days_since_last_scan': _to_int(features.get('days_since_last_scan', 0)),
        'vuln_density': vuln_density,
        'tool_effectiveness': tool_effectiveness,
        'security_risk_score': security_risk_score,
        'input_vulnerability_ratio': input_vulnerability_ratio,
        'previous_scan_accuracy': _to_float(features.get('previous_scan_accuracy', 0)),
        'total_issues': total_issues,
        'issue_density': issue_density,
        'has_idor': has_idor,
    })
    return row

def _append_vulnerability_rows(rows, quiet=False):
    if not rows:
        return 0

    os.makedirs(os.path.dirname(VULN_DATASET), exist_ok=True)
    df = pd.DataFrame(rows, columns=CANONICAL_VULN_COLUMNS)
    file_exists = os.path.exists(VULN_DATASET) and os.path.getsize(VULN_DATASET) > 0
    df.to_csv(VULN_DATASET, mode='a', header=not file_exists, index=False)
    if not quiet:
        print(f"    [+] Vulnerability dataset updated with {len(rows)} row(s) -> {VULN_DATASET}")
    
    # --- Cloud Sync Integration ---
    try:
        from Logic.hf_integration import upload_data_to_cloud
        # Path: Datasets_for_Model_Evaluation/vulnerability
        rel_path = "Datasets_for_Model_Evaluation/vulnerability"
        filename = os.path.basename(VULN_DATASET)
        upload_data_to_cloud(
            relative_path=rel_path,
            filename=filename,
            records=rows
        )
    except Exception:
        pass
    # ------------------------------

    return len(rows)


def update_dataset(features, quiet=False):
    if not features:
        return

    try:
        row = _build_canonical_vulnerability_row(features)
        try:
            append_target_scan_row(
                row,
                target_url=row.get('url'),
                scan_id=row.get('scan_id'),
                record_type="vulnerability_summary",
            )
        except Exception as e:
            if not quiet:
                print(f"    [-] Target scan dataset update skipped: {e}")
        _append_vulnerability_rows([row], quiet=quiet)
        return True
    except Exception as e:
        if not quiet:
            print(f"    [-] Error updating dataset: {e}")
        return False


def update_dataset_batch(features_list, quiet=False):
    if not features_list:
        return 0

    rows = []
    for features in features_list:
        if not features:
            continue
        try:
            row = _build_canonical_vulnerability_row(features)
            rows.append(row)
            try:
                append_target_scan_row(
                    row,
                    target_url=row.get('url'),
                    scan_id=row.get('scan_id'),
                    record_type="vulnerability_summary",
                )
            except Exception as e:
                if not quiet:
                    print(f"    [-] Target scan dataset update skipped: {e}")
        except Exception as e:
            if not quiet:
                print(f"    [-] Error preparing dataset row: {e}")

    try:
        return _append_vulnerability_rows(rows, quiet=quiet)
    except Exception as e:
        if not quiet:
            print(f"    [-] Error updating dataset batch: {e}")
        return 0

if __name__ == "__main__":
    print("[*] Dataset System Utility Loaded")
