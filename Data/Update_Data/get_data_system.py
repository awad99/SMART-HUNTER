#!/usr/bin/env python3
import os
import re
import pandas as pd
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime

# -- Constants --------------------------------------------------------------
# Adjusted path since it's now in Data/Update_Data/
MASTER_DATASET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Datasets", "master_vulnerability_data.csv")

def extract_vulnerability_features(url, response, vulnerabilities_found):
    """
    Extracts specialized vulnerability features for machine learning training.
    Maps results based on the columns requested.
    """
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

def update_dataset(features):
    """
    Appends the extracted features to the master dataset CSV file.
    """
    if not features:
        return
        
    os.makedirs(os.path.dirname(MASTER_DATASET), exist_ok=True)
    
    try:
        df = pd.DataFrame([features])
        file_exists = os.path.exists(MASTER_DATASET) and os.path.getsize(MASTER_DATASET) > 0
        
        # Save to CSV
        df.to_csv(MASTER_DATASET, mode='a', header=not file_exists, index=False)
        print(f"    [+] Dataset updated for {features.get('url')} -> {MASTER_DATASET}")
        return True
    except Exception as e:
        print(f"    [-] Error updating dataset: {e}")
        return False

if __name__ == "__main__":
    print("[*] Dataset System Utility Loaded")
