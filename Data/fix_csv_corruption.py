#!/usr/bin/env python3
import os
import sys
import csv
import re
from datetime import datetime

# -- Paths -------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = SCRIPT_DIR  # This script lives in Data/
MODEL_EVAL_DIR = os.path.join(DATA_DIR, "Datasets", "Datasets_for_Model_Evaluation")
RECON_CSV = os.path.join(MODEL_EVAL_DIR, "recon", "web_recon_ml_dataset.csv")
VULN_CSV = os.path.join(MODEL_EVAL_DIR, "vulnerability", "vulnerability_ml_dataset.csv")
BACKUP_SUFFIX = f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# -- Known canonical headers -------------------------------------------------
RECON_CANONICAL_HEADER = [
    'target_url', 'url_length', 'has_https', 'path_depth', 'has_query_params',
    'num_query_params', 'has_fragment', 'has_port', 'subdomain_count',
    'is_ip_address', 'domain_tld', 'domain_has_hyphens', 'domain_length',
    'status_code', 'status_category', 'response_size', 'response_time_ms',
    'is_redirect', 'redirect_chain_length', 'total_headers',
    'server_header_present', 'server_header', 'x_powered_by_present',
    'content_type', 'has_cookies', 'num_cookies', 'has_cors', 'cache_control',
    'security_headers_count', 'has_csp', 'has_hsts', 'has_xss_protection',
    'has_frame_options', 'has_content_type_options', 'has_forms', 'form_count',
    'has_inputs', 'input_count', 'has_buttons', 'button_count', 'has_textarea',
    'textarea_count', 'has_select', 'select_count', 'has_links', 'link_count',
    'has_images', 'image_count', 'has_scripts', 'script_count',
    'has_stylesheets', 'stylesheet_count', 'has_javascript', 'has_comments',
    'comment_count', 'has_meta_tags', 'meta_count', 'has_title',
    'server_apache', 'server_nginx', 'server_iis', 'tech_php', 'tech_aspnet',
    'tech_jsp', 'tech_wordpress', 'tech_drupal', 'tech_joomla',
    'has_debug_info', 'has_error_messages', 'has_sql_errors', 'has_file_paths',
    'cookie_count', 'session_cookies', 'redirect_count', 'has_redirect_chain',
    'final_https', 'input_to_form_ratio', 'script_to_content_ratio',
    'security_score', 'interactivity_score', 'scan_id', 'timestamp',
    'original_url', 'is_redirect_response', 'final_url',
    'redirect_chain_len', 'has_password_input', 'password_count',
    'has_hidden_input', 'hidden_count', 'has_file_upload', 'file_upload_count',
    'has_search_input', 'search_count', 'internal_script_count',
    'external_script_count', 'internal_link_count', 'external_link_count',
    'has_waf', 'waf_cloudflare', 'waf_aws', 'waf_imperva',
    'reflection_detected', 'has_jwt', 'has_api_keys', 'secure_cookie_ratio',
    'httponly_cookie_ratio', 'samesite_cookie_ratio', 'is_vulnerable',
    'inline_script_count', 'csp_header_reflection_detected', 'jwt_count',
    'api_key_count', 'get_form_count', 'post_form_count', 'has_login_form',
    'login_form_count', 'csrf_token_input_count', 'has_csrf_token',
    'same_origin_form_count', 'external_form_count', 'unique_input_names',
    'unique_endpoint_count', 'parameterized_link_count',
    'api_like_endpoint_count', 'inline_event_handler_count',
    'email_input_count', 'url_input_count', 'mailto_link_count',
    'tel_link_count', 'body_truncated_for_analysis', 'vulnerability_type',
]

VULN_CANONICAL_HEADER = [
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
    'issue_density', 'has_idor',
]


def backup_file(path):
    if os.path.exists(path):
        backup = path + BACKUP_SUFFIX
        import shutil
        shutil.copy2(path, backup)
        print(f"  [+] Backup: {backup}")
        return backup
    return None


def fix_recon_csv(path):
    """Fix web_recon_ml_dataset.csv where header and first data row are merged."""
    if not os.path.exists(path):
        print(f"  [!] File not found: {path}")
        return

    print(f"\n[*] Fixing recon CSV: {path}")
    backup_file(path)

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        raw = f.read()

    lines = raw.strip().split('\n')
    if not lines:
        print("  [!] Empty file"); return

    # Check if header is corrupted (vulnerability_type merged with data)
    header_line = lines[0]

    # The corruption pattern: last column name ends without comma,
    # then first data URL starts immediately
    # e.g.: "body_truncated_for_analysis,vulnerability_typehttps://..."
    corrupted_match = re.search(
        r'body_truncated_for_analysis,vulnerability_type(https?://)',
        header_line
    )

    clean_rows = []
    if corrupted_match:
        print("  [!] Detected header corruption — splitting header from merged data")
        # Extract the real header (everything before the URL)
        split_pos = corrupted_match.start(1)
        real_header = header_line[:split_pos]
        first_data = header_line[split_pos:]

        header_cols = real_header.split(',')
        print(f"  [+] Extracted {len(header_cols)} header columns")

        # Parse the first data row
        data_lines = [first_data] + lines[1:]
        for line in data_lines:
            if not line.strip():
                continue
            values = line.split(',')
            # Trim or pad to match header length
            row = {}
            for i, col in enumerate(header_cols):
                row[col] = values[i] if i < len(values) else ''
            clean_rows.append(row)
    else:
        print("  [+] Header appears intact")
        header_cols = RECON_CANONICAL_HEADER
        for line in lines[1:]:
            if not line.strip():
                continue
            values = line.split(',')
            row = {}
            for i, col in enumerate(header_cols):
                row[col] = values[i] if i < len(values) else ''
            clean_rows.append(row)

    # Remove rows with obviously bad data
    valid_rows = []
    BOOLEAN_FIELDS = ['has_query_params', 'has_fragment', 'has_port', 'is_ip_address',
                      'has_forms', 'has_inputs', 'has_https', 'has_cookies', 'has_cors']
    for row in clean_rows:
        url = row.get('target_url', '').strip()
        if not url or not url.startswith('http'):
            print(f"  [!] Dropping row with invalid URL: '{url[:60]}...'")
            continue

        # Detect corrupted rows: boolean fields should be 0 or 1, not decimals like 0.1
        is_corrupted = False
        for bf in BOOLEAN_FIELDS:
            val = row.get(bf, '0').strip()
            try:
                fval = float(val)
                if fval not in (0.0, 1.0) and '.' in val:
                    is_corrupted = True
                    break
            except (ValueError, TypeError):
                pass

        if is_corrupted:
            print(f"  [!] Dropping corrupted row (invalid boolean values): {url[:60]}")
            continue

        valid_rows.append(row)

    # Write clean file with canonical header
    with open(path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header_cols, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(valid_rows)

    print(f"  [+] Wrote {len(valid_rows)} clean rows")


def fix_vuln_csv(path):
    """Fix vulnerability_ml_dataset.csv — empty scan_id in first rows causing column shift."""
    if not os.path.exists(path):
        print(f"  [!] File not found: {path}")
        return

    print(f"\n[*] Fixing vulnerability CSV: {path}")
    backup_file(path)

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        raw_header = next(reader, [])
        raw_rows = list(reader)

    # Check if header has data merged in (like recon file)
    # The vuln CSV header line from observation:
    # "scan_id,url,...,has_idor,https://..."
    # This means the header is followed by the first data row without newline
    header_str = ','.join(raw_header)

    if any(raw_header[-1].startswith('http') for _ in [1] if len(raw_header) > len(VULN_CANONICAL_HEADER)):
        print("  [!] Detected header/data merge in vulnerability CSV")
        # Use canonical header
        header_cols = VULN_CANONICAL_HEADER
    else:
        header_cols = raw_header if len(raw_header) == len(VULN_CANONICAL_HEADER) else VULN_CANONICAL_HEADER

    clean_rows = []
    for raw_row in raw_rows:
        if not raw_row or not any(v.strip() for v in raw_row):
            continue

        # Handle shifted rows (empty scan_id at start)
        row = {}
        values = raw_row

        # If first value is empty and second looks like a URL, shift
        if len(values) > 1 and not values[0].strip() and values[1].strip().startswith('http'):
            values = [''] + values  # pad to realign

        for i, col in enumerate(header_cols):
            row[col] = values[i].strip() if i < len(values) else ''

        # Validate: must have a URL
        url = row.get('url', '').strip()
        if url and url.startswith('http'):
            clean_rows.append(row)

    with open(path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header_cols, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(clean_rows)

    print(f"  [+] Wrote {len(clean_rows)} clean rows")


def main():
    print("=" * 60)
    print("  SMART-HUNTER CSV Corruption Fixer")
    print("=" * 60)

    fix_recon_csv(RECON_CSV)
    fix_vuln_csv(VULN_CSV)

    print(f"\n{'=' * 60}")
    print("  Done! Original files backed up with .backup_* suffix.")
    print("  Please review the cleaned files before re-training.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
