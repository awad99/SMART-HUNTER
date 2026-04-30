import concurrent.futures
import os
import sys
import threading
import time
import urllib.parse
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning


root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(root, "Data")
TARGET_FILE = os.path.join(DATA_DIR, "targets.txt")

if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))

from Data.Update_Data import get_data_system


UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "ora-",
    "odbc",
    "syntax error",
    "unterminated string",
    "quoted string",
)

THREAD_LOCAL = threading.local()


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def _env_int(name, default, minimum=1):
    try:
        return max(minimum, int(os.getenv(name, "") or default))
    except (TypeError, ValueError):
        return default


def _normalize_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _same_origin(base_url, candidate_url):
    return urllib.parse.urlparse(base_url).netloc == urllib.parse.urlparse(candidate_url).netloc


def read_target_urls():
    print("\n[*] FAST MULTI-TARGET DATASET SCANNER")
    print("[*] Enter target URLs (one per line).")
    print("[*] Press Enter on an empty line to start, or use Data/targets.txt if no URL is entered.")
    urls = []
    seen = set()

    while True:
        try:
            line = input("> ").strip()
            if not line:
                break
            url = _normalize_url(line)
            if not url.startswith(("http://", "https://")):
                print(f"    [-] Invalid URL: {line}")
                continue
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
            print(f"    [+] Added: {url}")
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n    [-] Input cancelled.")
            sys.exit(0)

    if not urls and os.path.exists(TARGET_FILE):
        with open(TARGET_FILE, encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = _normalize_url(line)
                if url and url.startswith(("http://", "https://")) and url not in seen:
                    seen.add(url)
                    urls.append(url)
        if urls:
            print(f"    [+] Loaded {len(urls)} URL(s) from {TARGET_FILE}")

    if urls:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(TARGET_FILE, "w", encoding="utf-8") as f:
            for url in urls:
                f.write(url + "\n")
        print(f"    [+] Saved {len(urls)} URL(s) to {TARGET_FILE}")

    return urls


def _build_session():
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(UA)
    return session


def _get_worker_session():
    session = getattr(THREAD_LOCAL, "session", None)
    if session is None:
        session = _build_session()
        THREAD_LOCAL.session = session
    return session


def _fetch(session, url, timeout):
    try:
        start = time.perf_counter()
        response = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        response.elapsed_ms_fast = int((time.perf_counter() - start) * 1000)
        return response
    except Exception as exc:
        return exc


def _discover_light_targets(url, response, max_links=4):
    targets = {"get": []}
    parsed = urllib.parse.urlparse(response.url or url)
    base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if query:
        targets["get"].append({
            "url": base_url,
            "full_url": response.url,
            "params": list(query.keys()),
            "defaults": {k: v[0] if v else "" for k, v in query.items()},
        })

    content_type = response.headers.get("content-type", "")
    if "html" not in content_type.lower():
        return targets

    try:
        html = response.text or ""
        soup = BeautifulSoup(html[:250000], "html.parser")
    except Exception:
        return targets

    added = 0
    for a_tag in soup.find_all("a", href=True):
        if added >= max_links:
            break
        full_url = urllib.parse.urljoin(response.url or url, a_tag["href"])
        if not _same_origin(response.url or url, full_url):
            continue
        link_parsed = urllib.parse.urlparse(full_url)
        link_query = urllib.parse.parse_qs(link_parsed.query, keep_blank_values=True)
        if not link_query:
            continue
        link_base = urllib.parse.urlunparse((link_parsed.scheme, link_parsed.netloc, link_parsed.path, "", "", ""))
        targets["get"].append({
            "url": link_base,
            "full_url": full_url,
            "params": list(link_query.keys()),
            "defaults": {k: v[0] if v else "" for k, v in link_query.items()},
        })
        added += 1

    seen = set()
    unique = []
    for target in targets["get"]:
        key = (target["url"], tuple(sorted(target["params"])))
        if key in seen:
            continue
        seen.add(key)
        unique.append(target)
    targets["get"] = unique
    return targets


def _inject_get_url(target, param, value):
    source_url = target.get("full_url") or target.get("url")
    parsed = urllib.parse.urlparse(source_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, default in (target.get("defaults") or {}).items():
        query[key] = [default]
    query[param] = [value]
    encoded = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", encoded, ""))


def _fast_active_probes(session, targets, timeout, max_params):
    findings = []
    tested = 0
    canary = f"SHFAST{int(time.time() * 1000)}"

    for target in targets.get("get", []):
        for param in target.get("params", [])[:max_params]:
            tested += 1
            try:
                reflected_url = _inject_get_url(target, param, canary)
                reflected = session.get(reflected_url, timeout=timeout, verify=False, allow_redirects=True)
                if canary in (reflected.text or ""):
                    findings.append({
                        "type": "Reflection Candidate",
                        "parameter": param,
                        "payload": canary,
                        "evidence": "Fast canary reflected in response",
                        "tool": "fast_multi_probe",
                        "confidence": "low",
                        "status": "candidate",
                        "url": target.get("url"),
                        "method": "GET",
                    })

                quote_url = _inject_get_url(target, param, "'")
                quote_resp = session.get(quote_url, timeout=timeout, verify=False, allow_redirects=True)
                quote_text = (quote_resp.text or "").lower()
                if any(marker in quote_text for marker in SQL_ERROR_MARKERS):
                    findings.append({
                        "type": "SQL Injection Candidate",
                        "parameter": param,
                        "payload": "'",
                        "evidence": "Fast quote probe triggered database error text",
                        "tool": "fast_multi_probe",
                        "confidence": "medium",
                        "status": "candidate",
                        "url": target.get("url"),
                        "method": "GET",
                    })
            except Exception:
                continue

    return findings, tested


def _features_for_response(url, response, findings, scan_id):
    features = get_data_system.extract_vulnerability_features(url, response, [])
    features["scan_id"] = scan_id
    features["target_url"] = url
    features["status_code"] = getattr(response, "status_code", 0)
    features["response_size"] = len(getattr(response, "text", "") or "")
    features["response_time_ms"] = getattr(response, "elapsed_ms_fast", 0)
    features["has_sql_errors"] = features.get("has_database_errors", 0)
    features["reflection_detected"] = int(any(f.get("type") == "Reflection Candidate" for f in findings))
    features["is_vulnerable"] = 0
    features["vulnerability_type"] = ",".join(sorted({f.get("type", "") for f in findings if f.get("type")}))
    return features


def fast_scan_target(url, idx, total_count, timeout, max_params):
    scan_id = f"multi_fast_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{idx:04d}"
    session = _get_worker_session()
    started = time.perf_counter()

    response = _fetch(session, url, timeout)
    if isinstance(response, Exception):
        return {
            "url": url,
            "ok": False,
            "scan_id": scan_id,
            "error": f"{response.__class__.__name__}: {response}",
            "findings": [],
            "elapsed": time.perf_counter() - started,
        }

    targets = _discover_light_targets(url, response)
    findings, tested_params = _fast_active_probes(session, targets, timeout, max_params)
    features = _features_for_response(url, response, findings, scan_id)
    elapsed = time.perf_counter() - started
    return {
        "url": url,
        "ok": True,
        "scan_id": scan_id,
        "status": response.status_code,
        "final_url": response.url,
        "targets": sum(len(t.get("params", [])) for t in targets.get("get", [])),
        "tested_params": tested_params,
        "findings": findings,
        "features": features,
        "elapsed": elapsed,
    }


def main():
    urls = read_target_urls()
    if not urls:
        print("[-] No valid URLs provided. Exiting.")
        return

    workers = _env_int("SMART_HUNTER_MULTI_WORKERS", min(32, max(8, len(urls))), minimum=1)
    timeout = _env_int("SMART_HUNTER_MULTI_TIMEOUT", 5, minimum=1)
    max_params = _env_int("SMART_HUNTER_MULTI_MAX_PARAMS", 4, minimum=1)

    print(f"\n[*] Starting FAST multi-target scan for {len(urls)} target(s)")
    print(f"[*] workers={workers} timeout={timeout}s max_params_per_target={max_params}")
    print("[*] Deep tools are skipped here; use FULL scan for full validation.\n")

    started = time.perf_counter()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(fast_scan_target, url, idx, len(urls), timeout, max_params): (idx, url)
            for idx, url in enumerate(urls, 1)
        }
        for future in concurrent.futures.as_completed(futures):
            idx, url = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"url": url, "ok": False, "error": str(exc), "findings": [], "elapsed": 0}
            results.append(result)

            if result.get("ok"):
                print(
                    f"    [{idx}/{len(urls)}] {url} -> "
                    f"HTTP {result.get('status')} | params:{result.get('tested_params', 0)} "
                    f"| candidates:{len(result.get('findings', []))} | {result.get('elapsed', 0):.1f}s"
                )
            else:
                print(f"    [{idx}/{len(urls)}] {url} -> ERROR: {result.get('error')}")

    ok_count = sum(1 for result in results if result.get("ok"))
    finding_count = sum(len(result.get("findings", [])) for result in results)
    saved_rows = get_data_system.update_dataset_batch(
        [result.get("features") for result in results if result.get("ok") and result.get("features")],
        quiet=True,
    )
    elapsed = time.perf_counter() - started
    print("\n" + "=" * 60)
    print(" FAST MULTI-TARGET SUMMARY")
    print("=" * 60)
    print(f" Targets scanned : {ok_count}/{len(urls)}")
    print(f" Candidates      : {finding_count}")
    print(f" Dataset rows    : {saved_rows}")
    print(f" Total time      : {elapsed:.1f}s")
    print(f" Dataset         : {get_data_system.VULN_DATASET}")
    print("=" * 60)


if __name__ == "__main__":
    main()
