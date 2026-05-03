import concurrent.futures
import os
import sys
import time
from datetime import datetime


root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(root, "Data")
TARGET_FILE = os.path.join(DATA_DIR, "targets.txt")

for path in (
    root,
    os.path.join(root, "Logic"),
    os.path.join(root, "Logic", "Recon"),
    os.path.join(root, "Logic", "vulnerability_scan"),
):
    if path not in sys.path:
        sys.path.append(path)

import Recon.url_connection as url_connection
import vulnerability_scan.path_Analyze as path_Analyze
from Data.Queries.scan_stats import ScanStats
from Data.Update_Data import get_data_system
from Data.Update_Data.target_scan_dataset import get_target_scan_dataset_path


def _env_int(name, default, minimum=0):
    try:
        return max(minimum, int(os.getenv(name, "") or default))
    except (TypeError, ValueError):
        return default


def _env_bool(name, default=False):
    raw = str(os.getenv(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "enable", "enabled"}


def _normalize_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _snapshot_stats(stats):
    snapshot = {}
    counts = getattr(stats, "_counts", {}) if stats else {}
    for table, values in counts.items():
        snapshot[table] = {
            "added": int(values.get("added", 0)),
            "modified": int(values.get("modified", 0)),
            "deleted": int(values.get("deleted", 0)),
        }
    return snapshot


def _total_stat(stats_snapshot, table_name):
    row = (stats_snapshot or {}).get(table_name, {})
    return int(row.get("added", 0)) + int(row.get("modified", 0)) + int(row.get("deleted", 0))


def _unique_target_count(items, keys):
    unique = set()
    for item in items or []:
        unique.add(tuple(item.get(key, "") for key in keys))
    return len(unique)


def _confirmed_findings(findings):
    confirmed = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        confidence = str(finding.get("confidence", "")).strip().lower()
        status = str(finding.get("status", "")).strip().lower()
        if confidence == "high" or status == "confirmed":
            confirmed.append(finding)
    return confirmed


def _build_multi_target_dataset_features(result):
    recon = result.get("recon") or {}
    crawl = result.get("crawl") or {}
    features = dict(recon.get("feature_snapshot") or {})

    if not features:
        return {}

    confirmed = _confirmed_findings(crawl.get("vulns", []))
    finding_types = []
    for finding in confirmed:
        finding_type = finding.get("type") or finding.get("vulnerability_type")
        if finding_type:
            finding_types.append(str(finding_type))

    final_url = result.get("final_url") or features.get("final_url") or features.get("target_url") or result.get("url") or ""
    features.update({
        "scan_id": result.get("scan_id") or features.get("scan_id") or "",
        "url": final_url,
        "target_url": final_url,
        "original_url": features.get("original_url") or result.get("url") or final_url,
        "final_url": final_url,
        "status_code": result.get("status") or features.get("status_code") or 0,
        "pages_crawled": result.get("pages_crawled", 0),
        "forms_found": result.get("forms_found", 0),
        "params_found": result.get("params_found", 0),
        "recon_params_found": result.get("recon_params_found", 0),
        "subdomains_found": result.get("subdomains_found", 0),
        "endpoints_found": result.get("endpoints_found", 0),
        "confirmed_vuln_count": len(confirmed),
        "finding_types": "|".join(finding_types),
        "is_vulnerable": int(bool(confirmed)),
        "previous_scan_indicators": (
            f"multi_target=1|pages={result.get('pages_crawled', 0)}"
            f"|params={result.get('params_found', 0)}"
            f"|recon_params={result.get('recon_params_found', 0)}"
            f"|subdomains={result.get('subdomains_found', 0)}"
            f"|endpoints={result.get('endpoints_found', 0)}"
            f"|crawl={int(bool(crawl))}"
            f"|pwntraverse={int(_env_bool('SMART_HUNTER_MULTI_ENABLE_PWNTRAVERSE', False))}"
        ),
    })
    return features


def read_target_urls():
    print("\n[*] ACCELERATED MULTI-TARGET FULL RECON")
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
        with open(TARGET_FILE, encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                url = _normalize_url(line)
                if url and url not in seen and url.startswith(("http://", "https://")):
                    seen.add(url)
                    urls.append(url)
        if urls:
            print(f"    [+] Loaded {len(urls)} URL(s) from {TARGET_FILE}")

    if urls:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(TARGET_FILE, "w", encoding="utf-8") as handle:
            for url in urls:
                handle.write(url + "\n")
        print(f"    [+] Saved {len(urls)} URL(s) to {TARGET_FILE}")

    return urls


def run_parallel_target_scan(url, idx, batch_id, enable_crawl, crawl_depth, crawl_threads, enable_pwntraverse):
    started = time.perf_counter()
    scan_id = f"{batch_id}_{idx:04d}"
    stats = ScanStats(scan_id)

    try:
        recon = url_connection.MainRecon(
            url,
            cookie=None,
            scan_id=scan_id,
            stats=stats,
            interactive=False,
            enable_fuzz=False,
            return_details=True,
        )
        if not recon.get("ok"):
            return {
                "url": url,
                "ok": False,
                "scan_id": scan_id,
                "error": recon.get("error") or "Recon failed",
                "elapsed": time.perf_counter() - started,
                "recon": recon,
            }

        crawl_results = None
        crawl_target = recon.get("final_url") or url
        if enable_crawl and crawl_depth > 0:
            crawl_results = path_Analyze.crawl_and_scan(
                crawl_target,
                max_depth=crawl_depth,
                cookie=None,
                scan_id=scan_id,
                stats=stats,
                threads=crawl_threads,
                enable_pwntraverse=enable_pwntraverse,
                update_training_dataset=False,
            )

        params_found = _unique_target_count((crawl_results or {}).get("discovered_params", []), ("url", "param", "method"))
        forms_found = _unique_target_count((crawl_results or {}).get("discovered_forms", []), ("url", "param", "method"))
        pages_crawled = len((crawl_results or {}).get("visited", []))
        stats_snapshot = _snapshot_stats(stats)

        return {
            "url": url,
            "ok": True,
            "scan_id": scan_id,
            "status": recon.get("status_code"),
            "final_url": crawl_target,
            "elapsed": time.perf_counter() - started,
            "recon": recon,
            "crawl": crawl_results,
            "pages_crawled": pages_crawled,
            "params_found": params_found,
            "forms_found": forms_found,
            "subdomains_found": _total_stat(stats_snapshot, "subdomains"),
            "endpoints_found": _total_stat(stats_snapshot, "endpoints"),
            "recon_params_found": _total_stat(stats_snapshot, "discovered_parameters"),
            "target_csv": get_target_scan_dataset_path(crawl_target, scan_id),
        }
    except Exception as exc:
        return {
            "url": url,
            "ok": False,
            "scan_id": scan_id,
            "error": f"{exc.__class__.__name__}: {exc}",
            "elapsed": time.perf_counter() - started,
        }


def main():
    urls = read_target_urls()
    if not urls:
        print("[-] No valid URLs provided. Exiting.")
        return

    workers = _env_int("SMART_HUNTER_MULTI_WORKERS", min(16, max(4, len(urls))), minimum=1)
    crawl_depth = _env_int("SMART_HUNTER_MULTI_CRAWL_DEPTH", 2, minimum=0)
    crawl_threads = _env_int("SMART_HUNTER_MULTI_CRAWL_THREADS", 12, minimum=1)
    enable_crawl = _env_bool("SMART_HUNTER_MULTI_ENABLE_CRAWL", True)
    enable_pwntraverse = _env_bool("SMART_HUNTER_MULTI_ENABLE_PWNTRAVERSE", False)
    update_dataset = get_data_system.training_dataset_updates_enabled(default=True)
    batch_id = f"multi_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print(f"\n[*] Starting accelerated multi-target scan for {len(urls)} target(s)")
    print(
        f"[*] workers={workers} crawl_enabled={int(enable_crawl)} "
        f"crawl_depth={crawl_depth} crawl_threads={crawl_threads}"
    )
    if enable_pwntraverse:
        print("[*] Full reconnaissance and crawler validation are enabled, including PwnTraverse.\n")
    else:
        print("[*] Full reconnaissance is enabled. Fuzzing and PwnTraverse are skipped in parallel mode for speed and safety.\n")

    started = time.perf_counter()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                run_parallel_target_scan,
                url,
                idx,
                batch_id,
                enable_crawl,
                crawl_depth,
                crawl_threads,
                enable_pwntraverse,
            ): (idx, url)
            for idx, url in enumerate(urls, 1)
        }

        for future in concurrent.futures.as_completed(futures):
            idx, url = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "url": url,
                    "ok": False,
                    "error": f"{exc.__class__.__name__}: {exc}",
                    "elapsed": 0,
                }
            results.append(result)

            if result.get("ok"):
                print(
                    f"    [{idx}/{len(urls)}] {url} -> HTTP {result.get('status')} "
                    f"| subdomains:{result.get('subdomains_found', 0)} "
                    f"| pages:{result.get('pages_crawled', 0)} "
                    f"| params:{result.get('recon_params_found', 0) + result.get('params_found', 0)} "
                    f"| {result.get('elapsed', 0):.1f}s"
                )
            else:
                print(f"    [{idx}/{len(urls)}] {url} -> ERROR: {result.get('error')}")

    ok_results = [result for result in results if result.get("ok")]
    total_elapsed = time.perf_counter() - started
    total_pages = sum(result.get("pages_crawled", 0) for result in ok_results)
    total_forms = sum(result.get("forms_found", 0) for result in ok_results)
    total_params = sum(result.get("params_found", 0) + result.get("recon_params_found", 0) for result in ok_results)
    total_subdomains = sum(result.get("subdomains_found", 0) for result in ok_results)
    total_endpoints = sum(result.get("endpoints_found", 0) for result in ok_results)
    dataset_rows = [_build_multi_target_dataset_features(result) for result in ok_results]
    dataset_rows = [row for row in dataset_rows if row]
    dataset_rows_written = 0

    if update_dataset and dataset_rows:
        dataset_rows_written = get_data_system.update_dataset_batch(dataset_rows, quiet=True)

    print("\n" + "=" * 60)
    print(" PARALLEL FULL RECON SUMMARY")
    print("=" * 60)
    print(f" Targets completed : {len(ok_results)}/{len(urls)}")
    print(f" Subdomains found  : {total_subdomains}")
    print(f" Endpoints found   : {total_endpoints}")
    print(f" Parameters found  : {total_params}")
    print(f" Forms found       : {total_forms}")
    print(f" Pages crawled     : {total_pages}")
    print(f" Total time        : {total_elapsed:.1f}s")
    print(f" Recon dataset     : {url_connection.ML_DATASET_FILE}")
    if update_dataset:
        print(f" Vuln dataset rows : {dataset_rows_written}")
        print(f" Vuln dataset      : {get_data_system.VULN_DATASET}")
    else:
        print(" Vuln dataset      : disabled by SMART_HUNTER_UPDATE_DATASET=0")
    if any(result.get("target_csv") for result in ok_results):
        print(f" Target CSV sample  : {next(result.get('target_csv') for result in ok_results if result.get('target_csv'))}")
    print("=" * 60)


if __name__ == "__main__":
    main()
