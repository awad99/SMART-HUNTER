import os
import subprocess
import time
import urllib.parse
from urllib.parse import urlparse
import json

from Logic.Recon.utils import normalize_url, normalize_candidate_url, same_scope_url, same_scope_host, ordered_unique, robust_input
from Data.Queries.q_subdomains import save_subdomains
from Data.Queries.q_reports import save_report
from Data.Queries.q_fuzzing import save_fuzz_results

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script")
DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "Data")

class DiscoveryRunner:
    """Handles execution of external bash scripts for reconnaissance discovery."""
    def __init__(self, db, scan_id, stats, httpx_client_builder):
        self.db = db
        self.scan_id = scan_id
        self.stats = stats
        self.httpx_client_builder = httpx_client_builder

    def _run_script(self, script, *args, timeout=180, show_keywords=None):
        if not os.path.exists(script):
            print(f"    [-] Script not found: {script}")
            return None

        _DEFAULT_SHOW = ('error', '[-]', '[!]', '[+]', '[*]', 'found', 'discovered', 'saved', 'done', 'complete', 'url', 'subdomain', 'param')
        kw = show_keywords if show_keywords is not None else _DEFAULT_SHOW
        lines = []
        try:
            cmd = ['bash', script, *[str(a) for a in args]]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace", bufsize=1,
            )
            deadline = time.time() + timeout if timeout else None
            for raw in proc.stdout:
                line = raw.rstrip()
                if line:
                    lines.append(line)
                    ll = line.lower()
                    if kw and any(k in ll for k in kw):
                        print(f"    {line}")
                if deadline and time.time() > deadline:
                    print(f"    [!] Timeout ({timeout}s) — killing script")
                    proc.terminate()
                    break
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception as e:
            print(f"    [-] Script error: {e}")
            return None

        if lines:
            print(f"    [+] Script execution finished ({len(lines)} lines of output)")
        return lines or None

    def _normalize_in_scope_urls(self, values, base_url):
        normalized = []
        for item in values or []:
            text = (item or "").strip()
            if not text: continue
            candidate = normalize_url(text) if text.startswith(("http://", "https://")) else normalize_candidate_url(base_url, text)
            if candidate and same_scope_url(candidate, base_url):
                normalized.append(candidate)
        return ordered_unique(normalized)

    def get_subdomain(self, url):
        print(f"\n[*] Subdomain discovery: {url}")
        res = self._run_script(os.path.join(SCRIPT_DIR, "get_subdomain.sh"), url, timeout=120)
        if res:
            subs = []
            target_host = urlparse(url).hostname or ""
            for line in res:
                line = line.strip()
                if not line or line.startswith("[*]") or line.startswith("[-]"): continue
                parts = line.split()
                candidate = (parts[-1] if parts else line).strip().strip("[](),").lower()
                if ('.' in candidate and not candidate.startswith('-') and len(candidate) > 3 and same_scope_host(candidate, target_host)):
                    subs.append(candidate)
            subs = ordered_unique(subs)
            if subs:
                print(f"    [+] Saving {len(subs)} subdomains to DB")
                n = save_subdomains(self.db, self.scan_id, subs)
                self.stats.add('subdomains', n)
            else:
                print("    [*] No additional subdomains found for this target")
        return res

    def get_urls(self, url):
        print(f"\n[*] URL discovery: {url}")
        res = self._run_script(os.path.join(SCRIPT_DIR, "get_URLs.sh"), url, timeout=150)
        if res:
            urls = self._normalize_in_scope_urls(res, url)
            if urls:
                print(f"    [+] Saving {len(urls)} discovered URLs to DB")
                from Data.Queries.q_endpoints import save_endpoints
                n = save_endpoints(self.db, self.scan_id, url, urls, source='wayback/gau')
                self.stats.add('endpoints', n)
        return res

    def get_parameters(self, url):
        print(f"\n[*] Parameter discovery: {url}")
        res = self._run_script(os.path.join(SCRIPT_DIR, "get_parmtras.sh"), url, timeout=90)
        if res:
            from Data.Queries.q_parameters import save_discovered_parameters
            params_to_save = []
            seen = set()
            for line in res:
                line = line.strip()
                if not line: continue
                candidate_url = normalize_url(line) if line.startswith(("http://", "https://")) else normalize_candidate_url(url, line)
                if not candidate_url or not same_scope_url(candidate_url, url): continue
                parsed = urllib.parse.urlparse(candidate_url)
                query_map = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if not query_map: continue
                clean_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))
                for param_name in query_map.keys():
                    key = (clean_url, param_name, 'GET')
                    if key in seen: continue
                    seen.add(key)
                    params_to_save.append({
                        'url': clean_url, 'parameter': param_name, 'method': 'GET', 'raw_line': line
                    })
            if params_to_save:
                print(f"    [+] Saving {len(params_to_save)} discovered parameters to DB")
                save_discovered_parameters(self.db, self.scan_id, params_to_save, source='get_parmtras.sh')
                self.stats.add('discovered_parameters', len(params_to_save))
            save_report(self.db, self.scan_id, 'discovered_parameters_raw', "\n".join(res))
        return res

    def fuzz_url(self, base_url):
        print(f"\n[*] Fuzzing: {base_url}")
        script_path = os.path.join(SCRIPT_DIR, "fuzzing_command_Tools.sh")
        if not os.path.exists(script_path):
            print("[-] fuzzing_command_Tools.sh not found"); return None
        result = subprocess.run(['bash', script_path, base_url], capture_output=True, text=True)
        print(f"[*] Fuzz done (rc={result.returncode})")
        fuzzing = self.parse_ffuf_results(base_url)
        if fuzzing and fuzzing.get('raw'):
            n = save_fuzz_results(self.db, self.scan_id, fuzzing['raw'])
            self.stats.add('fuzzing_results', n)
        if fuzzing and fuzzing.get('found_paths'):
            ans = robust_input("\nCheck found paths? (y/n): ", default='n')
            if ans == 'y':
                self.check_found_paths(base_url, fuzzing['found_paths'])
        return fuzzing

    def parse_ffuf_results(self, base_url, results_file=None):
        canonical_results = os.path.join(DATASET_DIR, "ffuf_results.json")
        search_paths = [results_file, canonical_results, "ffuf_results.json"] if results_file else [canonical_results, "ffuf_results.json"]
        for path in search_paths:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                try:
                    with open(path, encoding="utf-8", errors="ignore") as handle:
                        data = json.load(handle)
                    entries = [{'url': e['url'], 'status': e.get('status',0), 'length': e.get('length',0)}
                               for e in data.get('results', []) if e.get('url')]
                    for e in entries: print(f"    [{e['status']}] {e['url']} ({e['length']} B)")
                    print(f"[+] ffuf: {len(entries)} paths")
                    summary = f"# {base_url}\n" + "\n".join(f"[{e['status']}] {e['url']}" for e in entries)
                    save_report(self.db, self.scan_id, 'ffuf_summary', summary)
                    print(f"[+] ffuf summary saved to DB")
                    return {'found_paths': [e['url'] for e in entries], 'raw': entries}
                except Exception as ex:
                    print(f"[-] ffuf parse error: {ex}")
        print("[-] No ffuf results found")
        return {'found_paths': [], 'raw': []}

    def check_found_paths(self, base_url, paths):
        paths = self._normalize_in_scope_urls(paths, base_url)
        print(f"\n[*] Verifying {len(paths)} paths...")
        if not paths: return
        
        import concurrent.futures
        def _verify(args):
            i, url = args
            try:
                r = self.httpx_client_builder().get(url)
                print(f"  [{i}/{len(paths)}] {r.status_code} | {len(r.text):>8} B | {url}")
            except Exception as ex:
                print(f"  [{i}/{len(paths)}] ERROR: {ex}")

        with self.httpx_client_builder() as client:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(paths))) as executor:
                list(executor.map(_verify, enumerate(paths, 1)))
