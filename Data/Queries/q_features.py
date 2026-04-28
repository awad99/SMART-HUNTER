"""
q_features.py — Queries for the `features` table
"""
# ────────────────────────── SQL ──────────────────────────
_FEATURE_COLS = [
    'scan_id', 'target_url', 'is_redirect_response', 'url_length', 'has_https',
    'path_depth', 'has_query_params', 'num_query_params', 'subdomain_count',
    'is_ip_address', 'domain_length', 'domain_tld', 'status_code',
    'status_category', 'response_size', 'response_time_ms', 'total_headers',
    'server_header', 'content_type', 'has_cookies', 'num_cookies',
    'security_headers_count', 'has_csp', 'has_hsts', 'has_xss_protection',
    'has_frame_options', 'has_forms', 'form_count', 'has_inputs',
    'input_count', 'password_count', 'hidden_count', 'file_upload_count',
    'search_count', 'script_count', 'internal_script_count',
    'external_script_count', 'link_count', 'internal_link_count',
    'external_link_count', 'image_count', 'meta_count', 'comment_count',
    'server_apache', 'server_nginx', 'server_iis', 'tech_php', 'tech_aspnet',
    'tech_wordpress', 'tech_drupal', 'tech_joomla', 'has_jwt', 'jwt_count',
    'has_api_keys', 'api_key_count', 'has_debug_info', 'has_error_messages',
    'has_sql_errors', 'reflection_detected', 'has_waf', 'waf_cloudflare',
    'waf_aws', 'waf_imperva', 'cookie_count', 'session_cookies',
    'secure_cookie_ratio', 'httponly_cookie_ratio', 'samesite_cookie_ratio',
    'security_score', 'interactivity_score', 'input_to_form_ratio',
    'is_vulnerable', 'vulnerability_type',
]

_BOOL_COLS = {
    'is_redirect_response', 'has_https', 'has_query_params', 'is_ip_address',
    'has_cookies', 'has_csp', 'has_hsts', 'has_xss_protection', 'has_frame_options',
    'has_forms', 'has_inputs', 'server_apache', 'server_nginx', 'server_iis',
    'tech_php', 'tech_aspnet', 'tech_wordpress', 'tech_drupal', 'tech_joomla',
    'has_jwt', 'has_api_keys', 'has_debug_info', 'has_error_messages',
    'has_sql_errors', 'reflection_detected', 'has_waf', 'waf_cloudflare',
    'waf_aws', 'waf_imperva', 'is_vulnerable',
}

# ────────────────────────── Functions ──────────────────────────
def save_features(db, features):
    """
    حفظ ميزات صفحة واحدة في جدول features.
    يُعيد 1 عند النجاح، 0 عند الفشل.

    مثال:
        from Data.Queries.q_features import save_features
        save_features(self.db, features_dict)
    """
    if not features:
        return 0

    data = {k: features.get(k) for k in _FEATURE_COLS if k in features}

    for k in list(data.keys()):
        v = data[k]
        if k in _BOOL_COLS or k.startswith(('has_', 'is_', 'tech_', 'server_')):
            if v is not None:
                data[k] = bool(v)

    if not data:
        return 0

    placeholders = ', '.join(['%s'] * len(data))
    columns      = ', '.join(data.keys())
    query        = f"INSERT INTO features ({columns}) VALUES ({placeholders})"
    result       = db._execute(query, tuple(data.values()))
    return 1 if result is not None else 0
