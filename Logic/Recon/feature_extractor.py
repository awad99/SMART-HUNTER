import re
import os
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import pandas as pd

from Logic.Recon.utils import (
    normalize_candidate_url, same_scope_url, is_ip_address, ordered_unique, safe_ratio
)

MAX_ANALYSIS_BYTES = max(50000, int(os.getenv("SMART_HUNTER_RECON_MAX_ANALYSIS_BYTES", "500000")))

_CONTENT_TYPES = {
    'html': 'html', 'json': 'json', 'xml': 'xml',
    'javascript': 'javascript', 'css': 'css',
    'image': 'image', 'pdf': 'pdf', 'text/plain': 'text',
}

_SEC_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
    "Referrer-Policy", "Permissions-Policy", "Cache-Control",
]

_RE_PASSWORD = re.compile(r'<input[^>]*type=[\'"]password[\'"]', re.I)
_RE_HIDDEN = re.compile(r'<input[^>]*type=[\'"]hidden[\'"]', re.I)
_RE_FILE = re.compile(r'<input[^>]*type=[\'"]file[\'"]', re.I)
_RE_SEARCH = re.compile(r'<input[^>]*type=[\'"]search[\'"]', re.I)
_RE_SEARCH_NAME = re.compile(r'<input[^>]*name=[\'"](?:search|q|query)[\'"]', re.I)
_RE_SCRIPT_SRC = re.compile(r'<script[^>]*src=[\'"]([^\'"]+)[\'"]', re.I)
_RE_HREF = re.compile(r'<a[^>]*href=[\'"]([^\'"]+)[\'"]', re.I)
_RE_JWT = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
_RE_API_KEY = re.compile(r'(?i)(?:api_key|apikey|access_token|secret_key)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?')
_RE_FILE_PATHS = re.compile(r'(?i)(?:/etc/|/var/www/|/home/|[A-Z]:\\(?:inetpub|xampp|Users|Windows)\\)')
_RE_DEBUG_INFO = re.compile(r'(?i)(?:debug|console\.log|var_dump|print_r|traceback|stack trace)')
_RE_ERROR_MSG = re.compile(r'(?i)(?:error|exception|warning|traceback|stack trace|fatal)')
_RE_SQL_ERR = re.compile(r'(?i)(?:sql syntax|mysql|postgresql|oracle|sqlite|database error|odbc|ora-\d+)')
_RE_TOKEN_NAME = re.compile(r'(?i)(?:csrf|xsrf|token|authenticity|nonce)')
_RE_LOGIN_HINT = re.compile(r'(?i)(?:login|signin|auth|account|user|email|pass)')
_RE_COMMENT = re.compile(r'<!--')

class FeatureExtractor:
    """Extracts ML features and HTML properties from HTTP responses."""
    
    def __init__(self, scan_id, waf_detector):
        self.scan_id = scan_id
        self.waf_detector = waf_detector
        self._analysis_cache = {}

    @staticmethod
    def _ct(content_type):
        ct = content_type.lower()
        return next((v for k, v in _CONTENT_TYPES.items() if k in ct), 'other')

    def analyze_html_document(self, html, base_url, content_type=""):
        body = html or ""
        key = f"{base_url}|{len(body)}|{hash(body[:4096])}"
        cached = self._analysis_cache.get(key)
        if cached is not None: return cached

        analysis = {
            'forms': [], 'get_params': [], 'post_params': [], 'buttons': [], 'links': [], 'inputs': [], 'endpoints': [],
            'password_count': 0, 'hidden_count': 0, 'file_upload_count': 0, 'search_count': 0, 'email_input_count': 0,
            'url_input_count': 0, 'textarea_count': 0, 'select_count': 0, 'button_count': 0, 'link_count': 0, 'image_count': 0,
            'meta_count': 0, 'stylesheet_count': 0, 'script_count': 0, 'inline_script_count': 0, 'internal_script_count': 0,
            'external_script_count': 0, 'internal_link_count': 0, 'external_link_count': 0, 'same_origin_form_count': 0,
            'external_form_count': 0, 'get_form_count': 0, 'post_form_count': 0, 'login_form_count': 0, 'csrf_token_input_count': 0,
            'unique_input_names': 0, 'unique_endpoint_count': 0, 'parameterized_link_count': 0, 'api_like_endpoint_count': 0,
            'inline_event_handler_count': 0, 'mailto_link_count': 0, 'tel_link_count': 0,
            'comment_count': len(_RE_COMMENT.findall(body[:MAX_ANALYSIS_BYTES])), 'has_title': 0,
            'analysis_truncated': int(len(body) > MAX_ANALYSIS_BYTES),
        }

        is_html = "html" in (content_type or "").lower() or "<html" in body[:1000].lower() or "<form" in body[:1000].lower()
        if not is_html:
            self._analysis_cache[key] = analysis
            return analysis

        snippet = body[:MAX_ANALYSIS_BYTES]
        soup = BeautifulSoup(snippet, "html.parser")
        input_names = []

        for tag in soup.find_all(True):
            analysis['inline_event_handler_count'] += sum(1 for attr_name in tag.attrs.keys() if str(attr_name).lower().startswith("on"))

        for field in soup.find_all(["input", "textarea", "select"]):
            tag_name = field.name.lower()
            field_type = (field.get("type") or tag_name or "text").lower()
            name = (field.get("name") or "").strip()
            analysis['inputs'].append({'type': field_type, 'name': name, 'id': field.get("id")})
            if name: input_names.append(name)
            if field_type == "password": analysis['password_count'] += 1
            if field_type == "hidden": analysis['hidden_count'] += 1
            if field_type == "file": analysis['file_upload_count'] += 1
            if field_type == "search" or (name and name.lower() in {"search", "q", "query"}): analysis['search_count'] += 1
            if field_type == "email": analysis['email_input_count'] += 1
            if field_type == "url": analysis['url_input_count'] += 1
            if tag_name == "textarea": analysis['textarea_count'] += 1
            if tag_name == "select": analysis['select_count'] += 1
            if name and _RE_TOKEN_NAME.search(name): analysis['csrf_token_input_count'] += 1

        for form in soup.find_all("form"):
            action_raw = (form.get("action") or "").strip()
            action = normalize_candidate_url(base_url, action_raw) or base_url
            method = (form.get("method") or "GET").upper()
            form_inputs, has_password, has_file, has_hidden = [], False, False, False

            for field in form.find_all(["input", "textarea", "select"]):
                field_type = (field.get("type") or field.name or "text").lower()
                name = (field.get("name") or "").strip()
                if name: form_inputs.append(name)
                has_password = has_password or field_type == "password"
                has_file = has_file or field_type == "file"
                has_hidden = has_hidden or field_type == "hidden"

            normalized_inputs = ordered_unique(form_inputs)
            analysis['forms'].append({
                'action': action, 'method': method, 'inputs': normalized_inputs,
                'has_password': has_password, 'has_file': has_file, 'has_hidden': has_hidden,
            })
            analysis['endpoints'].append(action)

            if method == "POST":
                analysis['post_form_count'] += 1
                analysis['post_params'].extend(normalized_inputs)
            else:
                analysis['get_form_count'] += 1
                analysis['get_params'].extend(normalized_inputs)

            if same_scope_url(action, base_url): analysis['same_origin_form_count'] += 1
            else: analysis['external_form_count'] += 1

            if has_password or any(_RE_LOGIN_HINT.search(item or "") for item in normalized_inputs) or _RE_LOGIN_HINT.search(action_raw or ""):
                analysis['login_form_count'] += 1

        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = (tag.get("href") or "").strip()
            if not href: continue
            lowered = href.lower()
            if lowered.startswith("mailto:"): analysis['mailto_link_count'] += 1; continue
            if lowered.startswith("tel:"): analysis['tel_link_count'] += 1; continue
            full_url = normalize_candidate_url(base_url, href)
            if not full_url: continue
            analysis['links'].append(full_url)
            analysis['endpoints'].append(full_url)
            if same_scope_url(full_url, base_url): analysis['internal_link_count'] += 1
            else: analysis['external_link_count'] += 1
            if parse_qs(urlparse(full_url).query): analysis['parameterized_link_count'] += 1
            path = urlparse(full_url).path.lower()
            if "/api/" in path or path.endswith(".json"): analysis['api_like_endpoint_count'] += 1

        for script in soup.find_all("script"):
            src = (script.get("src") or "").strip()
            if src:
                full_src = normalize_candidate_url(base_url, src)
                if full_src:
                    analysis['endpoints'].append(full_src)
                    if same_scope_url(full_src, base_url): analysis['internal_script_count'] += 1
                    else: analysis['external_script_count'] += 1
            else: analysis['inline_script_count'] += 1

        for button in soup.find_all("button"):
            analysis['buttons'].append({'type': (button.get("type") or "button").lower(), 'content': " ".join(button.stripped_strings)})
        for field in soup.find_all("input"):
            if (field.get("type") or "").lower() in {"button", "submit"}:
                analysis['buttons'].append({'type': (field.get("type") or "button").lower(), 'value': field.get("value"), 'name': field.get("name")})

        analysis['image_count'] = len(soup.find_all("img"))
        analysis['meta_count'] = len(soup.find_all("meta"))
        analysis['stylesheet_count'] = sum(1 for link in soup.find_all("link") if "stylesheet" in " ".join(link.get("rel", [])).lower())
        analysis['has_title'] = int(bool(soup.title and soup.title.get_text(strip=True)))
        analysis['script_count'] = analysis['inline_script_count'] + analysis['internal_script_count'] + analysis['external_script_count']
        analysis['button_count'] = len(analysis['buttons'])
        analysis['link_count'] = len(analysis['links'])
        analysis['get_params'] = ordered_unique(analysis['get_params'])
        analysis['post_params'] = ordered_unique(analysis['post_params'])
        analysis['links'] = ordered_unique(analysis['links'])
        analysis['endpoints'] = ordered_unique(analysis['endpoints'])
        analysis['unique_input_names'] = len(set(name for name in input_names if name))
        analysis['unique_endpoint_count'] = len(analysis['endpoints'])

        self._analysis_cache[key] = analysis
        return analysis

    def extract_recon_features(self, response, original_url, final_url, redirect_chain, cookies, is_redirect=False):
        try:
            url = final_url or original_url
            parsed_url = urlparse(url)
            headers = response.headers
            body = response.text or ""
            body_lower = body.lower()
            content_type = headers.get('Content-Type', '')
            dom = self.analyze_html_document(body, url, content_type=content_type)
            waf_result = self.waf_detector.detect_waf(url, response)
            waf_found = waf_result["vendors"]
            server_header = headers.get('Server', '')
            server_lower = server_header.lower()
            powered_by = headers.get('X-Powered-By', '').lower()
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            reflected_params = sum(1 for values in query_params.values() for value in values if len(value) > 2 and value.lower() in body_lower)

            cookie_headers = headers.get_list('set-cookie') if hasattr(headers, 'get_list') else ([headers.get('set-cookie')] if headers.get('set-cookie') else [])
            num_set_cookies = len(cookie_headers)
            secure_cookies = sum(1 for item in cookie_headers if item and 'secure' in item.lower())
            httponly_cookies = sum(1 for item in cookie_headers if item and 'httponly' in item.lower())
            samesite_cookies = sum(1 for item in cookie_headers if item and ('samesite=strict' in item.lower() or 'samesite=lax' in item.lower() or 'samesite=none' in item.lower()))
            jwt_count = len(_RE_JWT.findall(body))
            api_key_count = len(_RE_API_KEY.findall(body))

            features = {
                'url_length': len(url), 'has_https': int(url.startswith('https')), 'path_depth': len([x for x in parsed_url.path.split('/') if x]),
                'has_query_params': int(bool(parsed_url.query)), 'num_query_params': len(query_params), 'has_fragment': int(bool(parsed_url.fragment)),
                'has_port': int(bool(parsed_url.port)), 'subdomain_count': max(0, len(parsed_url.netloc.split('.'))-2),
                'is_ip_address': is_ip_address(parsed_url.hostname or parsed_url.netloc), 'domain_length': len(parsed_url.netloc),
                'domain_has_hyphens': int('-' in parsed_url.netloc), 'domain_tld': parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else 'unknown',
                'status_code': response.status_code, 'status_category': response.status_code // 100, 'response_size': len(body),
                'response_time_ms': getattr(response, 'elapsed', None) and response.elapsed.total_seconds()*1000 or 0,
                'is_redirect': int(is_redirect), 'redirect_chain_len': len(redirect_chain), 'total_headers': len(headers),
                'server_header_present': int('Server' in headers), 'server_header': server_header.split('/')[0] if server_header else 'unknown',
                'x_powered_by_present': int('X-Powered-By' in headers), 'content_type': self._ct(content_type),
                'has_cookies': int('Set-Cookie' in headers), 'num_cookies': len(response.cookies),
                'has_cors': int('Access-Control-Allow-Origin' in headers), 'cache_control': int('Cache-Control' in headers),
                'security_headers_count': sum(1 for item in _SEC_HEADERS if item in headers), 'has_csp': int('Content-Security-Policy' in headers),
                'has_hsts': int('Strict-Transport-Security' in headers), 'has_xss_protection': int('X-XSS-Protection' in headers),
                'has_frame_options': int('X-Frame-Options' in headers), 'has_content_type_options': int('X-Content-Type-Options' in headers),
                'has_forms': int(bool(dom['forms'])), 'form_count': len(dom['forms']), 'has_inputs': int(bool(dom['inputs'])), 'input_count': len(dom['inputs']),
                'has_password_input': int(dom['password_count'] > 0), 'password_count': dom['password_count'], 'has_hidden_input': int(dom['hidden_count'] > 0),
                'hidden_count': dom['hidden_count'], 'has_file_upload': int(dom['file_upload_count'] > 0), 'file_upload_count': dom['file_upload_count'],
                'has_search_input': int(dom['search_count'] > 0), 'search_count': dom['search_count'], 'has_buttons': int(dom['button_count'] > 0),
                'button_count': dom['button_count'], 'has_textarea': int(dom['textarea_count'] > 0), 'textarea_count': dom['textarea_count'],
                'has_select': int(dom['select_count'] > 0), 'select_count': dom['select_count'], 'has_scripts': int(dom['script_count'] > 0),
                'script_count': dom['script_count'], 'inline_script_count': dom['inline_script_count'], 'internal_script_count': dom['internal_script_count'],
                'external_script_count': dom['external_script_count'], 'has_links': int(dom['link_count'] > 0), 'link_count': dom['link_count'],
                'internal_link_count': dom['internal_link_count'], 'external_link_count': dom['external_link_count'], 'has_images': int(dom['image_count'] > 0),
                'image_count': dom['image_count'], 'has_meta_tags': int(dom['meta_count'] > 0), 'meta_count': dom['meta_count'],
                'has_stylesheets': int(dom['stylesheet_count'] > 0), 'stylesheet_count': dom['stylesheet_count'],
                'has_javascript': int(dom['script_count'] > 0 or dom['inline_event_handler_count'] > 0 or 'javascript:' in body_lower),
                'has_comments': int(dom['comment_count'] > 0), 'comment_count': dom['comment_count'], 'has_title': dom['has_title'],
                'server_apache': int('apache' in server_lower), 'server_nginx': int('nginx' in server_lower), 'server_iis': int('iis' in server_lower or 'microsoft' in server_lower),
                'tech_php': int('php' in powered_by or '.php' in body_lower), 'tech_aspnet': int('asp.net' in powered_by or '.aspx' in body_lower),
                'tech_jsp': int('.jsp' in body_lower), 'tech_wordpress': int('wp-content' in body_lower or 'wordpress' in body_lower),
                'tech_drupal': int('drupal' in body_lower), 'tech_joomla': int('joomla' in body_lower),
                'has_debug_info': int(bool(_RE_DEBUG_INFO.search(body_lower))), 'has_error_messages': int(bool(_RE_ERROR_MSG.search(body_lower))),
                'has_sql_errors': int(bool(_RE_SQL_ERR.search(body_lower))), 'has_file_paths': int(bool(_RE_FILE_PATHS.search(body))),
                'has_waf': int(waf_result["detected"]), 'waf_cloudflare': int('Cloudflare' in waf_found), 'waf_aws': int('AWS WAF' in waf_found),
                'waf_imperva': int('Imperva' in waf_found), 'waf_vendor_name': waf_found[0] if waf_found else '',
                'waf_detection_method': waf_result["method"], 'waf_confidence': waf_result["confidence"],
                'reflection_detected': int(reflected_params > 0),
                'csp_header_reflection_detected': int(any(value.lower() in headers.get('Content-Security-Policy', '').lower() for values in query_params.values() for value in values if len(value) > 2)),
                'has_jwt': int(jwt_count > 0), 'jwt_count': jwt_count, 'has_api_keys': int(api_key_count > 0), 'api_key_count': api_key_count,
                'cookie_count': len(cookies), 'session_cookies': sum(1 for k in cookies if 'session' in k.get('name','').lower()),
                'secure_cookie_ratio': safe_ratio(secure_cookies, num_set_cookies), 'httponly_cookie_ratio': safe_ratio(httponly_cookies, num_set_cookies),
                'samesite_cookie_ratio': safe_ratio(samesite_cookies, num_set_cookies), 'redirect_count': max(0, len(redirect_chain)-1),
                'has_redirect_chain': int(len(redirect_chain) > 1), 'final_https': int(bool(final_url) and final_url.startswith('https')),
                'get_form_count': dom['get_form_count'], 'post_form_count': dom['post_form_count'], 'has_login_form': int(dom['login_form_count'] > 0),
                'login_form_count': dom['login_form_count'], 'csrf_token_input_count': dom['csrf_token_input_count'], 'has_csrf_token': int(dom['csrf_token_input_count'] > 0),
                'same_origin_form_count': dom['same_origin_form_count'], 'external_form_count': dom['external_form_count'],
                'unique_input_names': dom['unique_input_names'], 'unique_endpoint_count': dom['unique_endpoint_count'],
                'parameterized_link_count': dom['parameterized_link_count'], 'api_like_endpoint_count': dom['api_like_endpoint_count'],
                'inline_event_handler_count': dom['inline_event_handler_count'], 'email_input_count': dom['email_input_count'],
                'url_input_count': dom['url_input_count'], 'mailto_link_count': dom['mailto_link_count'], 'tel_link_count': dom['tel_link_count'],
                'body_truncated_for_analysis': dom['analysis_truncated'], 'input_to_form_ratio': safe_ratio(len(dom['inputs']), len(dom['forms'])),
                'script_to_content_ratio': safe_ratio(dom['script_count'], max(len(body), 1)),
                'security_score': safe_ratio(sum(1 for item in _SEC_HEADERS if item in headers), len(_SEC_HEADERS)),
                'interactivity_score': safe_ratio(len(dom['forms']) + len(dom['inputs']) + dom['button_count'], max(len(body) / 1000, 1)),
                'is_vulnerable': 0, 'vulnerability_type': '', 'scan_id': self.scan_id, 'timestamp': datetime.now().isoformat(),
                'target_url': url, 'original_url': original_url, 'is_redirect_response': is_redirect, 'final_url': final_url or url,
            }
            return features
        except Exception as e:
            print(f"[-] Feature extraction error: {e}")
            return {'scan_id': self.scan_id, 'timestamp': datetime.now().isoformat(),
                    'target_url': url, 'original_url': original_url,
                    'status_code': getattr(response, 'status_code', 0), 'error_occurred': 1}
