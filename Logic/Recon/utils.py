import ipaddress
from urllib.parse import urlparse, urljoin

def normalize_url(url):
    text = (url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = "https://" + text
    return text

def ordered_unique(items):
    out = []
    seen = set()
    for item in items:
        if item in seen or item in ("", None):
            continue
        seen.add(item)
        out.append(item)
    return out

def safe_ratio(numerator, denominator):
    return (numerator / denominator) if denominator else 0.0

def host_scope_suffix(hostname):
    parts = [part for part in (hostname or "").split(".") if part]
    if len(parts) > 2:
        return ".".join(parts[1:])
    return hostname or ""

def same_scope_host(candidate_host, base_host):
    candidate = (candidate_host or "").lower()
    base = (base_host or "").lower()
    suffix = host_scope_suffix(base)
    return bool(candidate) and (
        candidate == base or
        candidate.endswith("." + base) or
        candidate == suffix or
        candidate.endswith("." + suffix)
    )

def same_scope_url(candidate_url, base_url):
    candidate_host = urlparse(candidate_url).hostname or ""
    base_host = urlparse(base_url).hostname or ""
    return same_scope_host(candidate_host, base_host)

def normalize_candidate_url(base_url, candidate):
    href = (candidate or "").strip()
    if not href:
        return ""
    if href.startswith(("javascript:", "data:", "mailto:", "tel:", "#")):
        return ""
    return urljoin(base_url, href)

def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return 1
    except ValueError:
        return 0

def robust_input(prompt, default='n'):
    import sys
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            return default
        return line.strip().lower()
    except Exception:
        return default
