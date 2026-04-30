import hashlib
import json
import os
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse


_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._\-+/=]{8,}")
_LONG_TOKEN_RE = re.compile(r"\b[a-zA-Z0-9_\-]{24,}\b")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_SQL_ERROR_RE = re.compile(r"(?i)(sql syntax|mysql|postgresql|sqlite|ora-\d+|database error|odbc)")
_TRACEBACK_RE = re.compile(r"(?i)(traceback|stack trace|exception|fatal error|uncaught)")
_PATH_RE = re.compile(r"(?i)(/etc/passwd|/var/www|boot\.ini|[A-Z]:\\)")
_REDIRECT_HINT_RE = re.compile(r"(?i)\b(redirect|return|next|continue|dest|url)\b")
_TOKEN_NAME_RE = re.compile(r"(?i)\b(token|secret|session|auth|csrf|xsrf|jwt|api[-_]?key)\b")

_SECURITY_HEADERS = {
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
}

_SECRET_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}

_OVERRIDE_HEADERS = {
    "host",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-original-url",
    "x-rewrite-url",
}

_COMMON_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "authorization",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "host",
    "origin",
    "pragma",
    "referer",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "upgrade-insecure-requests",
    "user-agent",
    "x-requested-with",
}


def coerce_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def collapse_whitespace(text):
    return _WHITESPACE_RE.sub(" ", coerce_text(text)).strip()


def truncate_text(text, limit=4000):
    return coerce_text(text)[: max(0, int(limit))]


def mask_secrets(text):
    value = coerce_text(text)
    value = _JWT_RE.sub("<jwt>", value)
    value = _BEARER_RE.sub("Bearer <token>", value)
    value = _LONG_TOKEN_RE.sub("<token>", value)
    return value


def sanitize_text(text, limit=4000):
    value = coerce_text(text)
    value = _CONTROL_CHARS_RE.sub(" ", value)
    value = mask_secrets(value)
    return collapse_whitespace(truncate_text(value, limit))


def body_hash(text):
    value = coerce_text(text)
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def extract_title(body_text):
    match = _TITLE_RE.search(coerce_text(body_text))
    if not match:
        return ""
    return sanitize_text(_HTML_TAG_RE.sub(" ", match.group(1)), 200)


def html_to_text(body_text, limit=4000):
    stripped = _HTML_TAG_RE.sub(" ", coerce_text(body_text))
    return sanitize_text(stripped, limit)


def extract_error_signatures(text, status_code=None):
    value = coerce_text(text)
    tokens = []
    if _SQL_ERROR_RE.search(value):
        tokens.append("sql_error_signature")
    if _TRACEBACK_RE.search(value):
        tokens.append("exception_trace_signature")
    if _PATH_RE.search(value):
        tokens.append("file_path_signature")
    if _REDIRECT_HINT_RE.search(value):
        tokens.append("redirect_hint")
    if status_code in (401, 403):
        tokens.append("authz_barrier")
    if status_code and int(status_code) >= 500:
        tokens.append("server_error_status")
    return " ".join(sorted(set(tokens)))


def infer_value_shape(value):
    text = coerce_text(value).strip()
    if not text:
        return "empty"
    low = text.lower()
    if low in {"true", "false", "yes", "no", "on", "off"}:
        return "boolean_like"
    if text.isdigit():
        return "numeric"
    if _UUID_RE.match(text):
        return "uuid"
    if _EMAIL_RE.match(text):
        return "email_like"
    if "/" in text or "\\" in text:
        return "path_like"
    if os.path.splitext(text)[1]:
        return "filename_like"
    if _HEX_RE.match(text) or len(text) >= 24 or _TOKEN_NAME_RE.search(text):
        return "token_like"
    if len(text.split()) > 3:
        return "free_text"
    return "short_text"


def normalize_route_template(url):
    parsed = urlparse(coerce_text(url))
    segments = []
    for segment in parsed.path.split("/"):
        piece = segment.strip()
        if not piece:
            continue
        if piece.isdigit():
            segments.append("{int}")
        elif _UUID_RE.match(piece):
            segments.append("{uuid}")
        elif _HEX_RE.match(piece) or (len(piece) > 24 and piece.isalnum()):
            segments.append("{token}")
        else:
            segments.append(piece.lower())
    return "/" + "/".join(segments)


def path_tokens_from_url(url):
    parsed = urlparse(coerce_text(url))
    parts = []
    for segment in parsed.path.split("/"):
        piece = re.sub(r"[^a-zA-Z0-9._-]+", " ", segment).strip(" ._-").lower()
        if not piece:
            continue
        parts.extend(token for token in piece.replace(".", " ").replace("-", " ").replace("_", " ").split() if token)
    return " ".join(parts)


def file_extension_from_url(url):
    return os.path.splitext(urlparse(coerce_text(url)).path)[1].lower().lstrip(".")


def query_metadata(url, explicit_params=None):
    if explicit_params is None:
        parsed = urlparse(coerce_text(url))
        params = parse_qs(parsed.query, keep_blank_values=True)
        query_string = parsed.query
    else:
        params = explicit_params or {}
        query_string = "&".join(f"{key}={coerce_text(vals[0]) if vals else ''}" for key, vals in params.items())
    names = list(params.keys())
    shapes = []
    for key, values in params.items():
        if not values:
            shapes.append(f"{key}:empty")
            continue
        shapes.extend(f"{key}:{infer_value_shape(value)}" for value in values[:3])
    return {
        "query_string_raw": query_string,
        "query_keys_text": " ".join(names),
        "query_param_names": names,
        "query_param_count": len(names),
        "query_shapes_text": " ".join(shapes),
    }


def parse_cookie_names(cookie_header_value):
    names = []
    for part in coerce_text(cookie_header_value).split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        names.append(item.split("=", 1)[0].strip().lower())
    return names


def parse_body_params(content_type, body_text):
    text = coerce_text(body_text)
    ctype = coerce_text(content_type).lower()
    if not text:
        return {}
    if "json" in ctype:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return {str(key): [coerce_text(value)] for key, value in data.items()}
        except Exception:
            return {}
    if "x-www-form-urlencoded" in ctype:
        parsed = parse_qs(text, keep_blank_values=True)
        return {str(key): [coerce_text(value) for value in values] for key, values in parsed.items()}
    return {}


def infer_origin_relation(headers, request_url):
    pairs = header_dict(headers)
    request_host = (urlparse(coerce_text(request_url)).hostname or "").lower()
    origin = (pairs.get("origin") or "").strip()
    referer = (pairs.get("referer") or "").strip()
    for candidate in (origin, referer):
        if not candidate:
            continue
        host = (urlparse(candidate).hostname or "").lower()
        if host and host == request_host:
            return "same_origin"
        if host and request_host and host != request_host:
            return "cross_origin"
    return "missing"


def infer_fetch_metadata(headers):
    pairs = header_dict(headers)
    parts = []
    for key in ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user"):
        value = pairs.get(key)
        if value:
            parts.append(f"{key.replace('-', '_')}={value.strip().lower()}")
    return " ".join(parts)


def infer_auth_scheme(headers):
    pairs = header_dict(headers)
    auth = coerce_text(pairs.get("authorization")).strip()
    if auth:
        prefix = auth.split(" ", 1)[0].lower()
        if prefix in {"bearer", "basic", "digest", "negotiate"}:
            return prefix
        return "authorization_header"
    cookie_names = []
    if pairs.get("cookie"):
        cookie_names.extend(parse_cookie_names(pairs.get("cookie")))
    if cookie_names:
        return "session_cookie"
    return "none"


def infer_user_agent_family(headers_or_user_agent):
    if isinstance(headers_or_user_agent, str):
        user_agent = headers_or_user_agent
    else:
        user_agent = header_dict(headers_or_user_agent).get("user-agent", "")
    text = coerce_text(user_agent).lower()
    if "chrome" in text and "edg" not in text:
        return "chrome"
    if "firefox" in text:
        return "firefox"
    if "safari" in text and "chrome" not in text:
        return "safari"
    if "curl" in text:
        return "curl"
    if "python-requests" in text:
        return "python_requests"
    if "httpx" in text:
        return "httpx"
    return "other"


def _iter_header_pairs(headers):
    if headers is None:
        return []
    if hasattr(headers, "multi_items"):
        try:
            return [(coerce_text(key), coerce_text(value)) for key, value in headers.multi_items()]
        except Exception:
            pass
    if hasattr(headers, "items"):
        try:
            return [(coerce_text(key), coerce_text(value)) for key, value in headers.items()]
        except Exception:
            pass
    if isinstance(headers, dict):
        return [(coerce_text(key), coerce_text(value)) for key, value in headers.items()]
    if isinstance(headers, (list, tuple)):
        out = []
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out.append((coerce_text(item[0]), coerce_text(item[1])))
        return out
    return []


def header_dict(headers):
    result = {}
    for name, value in _iter_header_pairs(headers):
        lname = name.strip().lower()
        if lname and lname not in result:
            result[lname] = value
    return result


def mask_header_value(name, value):
    lname = coerce_text(name).strip().lower()
    text = coerce_text(value)
    if lname in {"cookie", "set-cookie"}:
        names = parse_cookie_names(text)
        return "; ".join(f"{name}=<masked>" for name in names) if names else "<masked-cookie>"
    if lname == "authorization":
        return infer_auth_scheme({lname: text}) + " <masked>"
    if lname in _SECRET_HEADERS or "token" in lname or "secret" in lname:
        return "<masked>"
    return sanitize_text(text, 500)


def extract_header_views(headers, scope):
    pairs = _iter_header_pairs(headers)
    counts = Counter(name.strip().lower() for name, _ in pairs if name)
    raw_lines = []
    canonical_lines = []
    semantic_tokens = set()
    header_rows = []
    cookie_names = []
    set_cookie_semantics = set()
    present_security_headers = set()
    custom_header_count = 0
    suspicious_override = 0
    set_cookie_count = 0

    for index, (name, value) in enumerate(pairs):
        lname = name.strip().lower()
        if not lname:
            continue
        masked = mask_header_value(lname, value)
        raw_lines.append(f"{lname}: {masked}")
        canonical_lines.append(f"{lname}: {masked}")
        if lname not in _COMMON_HEADERS and not lname.startswith("sec-ch-"):
            custom_header_count += 1
        if lname in _OVERRIDE_HEADERS:
            suspicious_override = 1
            semantic_tokens.add(f"{scope}_override_header_present")
        if lname in _SECURITY_HEADERS:
            present_security_headers.add(lname)
            semantic_tokens.add(f"security_header_{lname.replace('-', '_')}_present")
        if lname == "content-type":
            low = masked.lower()
            if "json" in low:
                semantic_tokens.add(f"{scope}_content_type_json")
            elif "html" in low:
                semantic_tokens.add(f"{scope}_content_type_html")
            elif "xml" in low:
                semantic_tokens.add(f"{scope}_content_type_xml")
        if lname == "server":
            semantic_tokens.add("response_server_disclosed")
        if lname == "cache-control" and "no-store" in masked.lower():
            semantic_tokens.add("cache_control_no_store")
        if lname == "access-control-allow-origin" and "*" in masked:
            semantic_tokens.add("cors_wildcard")
        if lname == "authorization":
            semantic_tokens.add(f"auth_scheme_{infer_auth_scheme({lname: value})}")
        if lname == "cookie":
            cookie_names.extend(parse_cookie_names(value))
        if lname == "set-cookie":
            set_cookie_count += 1
            set_cookie_semantics.add("set_cookie_present")
            low = coerce_text(value).lower()
            if "secure" in low:
                set_cookie_semantics.add("set_cookie_secure")
            if "httponly" in low:
                set_cookie_semantics.add("set_cookie_httponly")
            if "samesite" in low:
                set_cookie_semantics.add("set_cookie_samesite")

        header_rows.append(
            {
                "header_scope": scope,
                "header_name": lname,
                "header_value_masked_text": masked,
                "header_value_canonical_text": f"{lname}: {masked}",
                "header_semantic_text": " ".join(sorted(set_cookie_semantics if lname == "set-cookie" else [])),
                "header_order": index,
            }
        )

    for cookie_name in cookie_names:
        semantic_tokens.add(f"cookie_name_{cookie_name}")

    duplicate_count = sum(max(0, count - 1) for count in counts.values())
    if duplicate_count:
        semantic_tokens.add(f"{scope}_duplicate_headers")

    canonical_text = "\n".join(sorted(canonical_lines))
    raw_text = "\n".join(raw_lines)
    if scope == "request":
        fetch_site = header_dict(headers).get("sec-fetch-site")
        if fetch_site:
            semantic_tokens.add(f"fetch_site_{fetch_site.strip().lower()}")
    semantic_text = " ".join(sorted(semantic_tokens | set_cookie_semantics))
    anomaly_score = round(
        duplicate_count * 0.15 + custom_header_count * 0.03 + suspicious_override * 0.5,
        3,
    )

    return {
        "raw_ordered_text": raw_text,
        "canonical_text": canonical_text,
        "semantic_text": semantic_text,
        "header_rows": header_rows,
        "header_count": len(raw_lines),
        "duplicate_header_count": duplicate_count,
        "custom_header_count": custom_header_count,
        "suspicious_override_header_present": suspicious_override,
        "header_anomaly_score": anomaly_score,
        "cookie_names_text": " ".join(sorted(set(cookie_names))),
        "security_header_count": len(present_security_headers),
        "security_headers_text": " ".join(sorted(h.replace("-", "_") for h in present_security_headers)),
        "set_cookie_semantic_text": " ".join(sorted(set_cookie_semantics)),
        "set_cookie_count": set_cookie_count,
    }
