import re
import os
import shutil

# --- SQLMAP ---
shutil.copy(r'Logic\vulnerability_scan\sqli_scan.py', r'Logic\vulnerability_scan\sqli\scanners\sqlmap.py')
with open(r'Logic\vulnerability_scan\sqli\scanners\sqlmap.py', 'r', encoding='utf-8') as f:
    text = f.read()

repl = '''from .base import BaseScanner
import os
import urllib.parse
import subprocess
import glob
import re

DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "Data")

class SqlmapScanner(BaseScanner):
    def scan_sqlmap'''
text = re.sub(r'class SQLiScanMixin:.*?    def check_sql_injection_with_sqlmap', repl, text, flags=re.DOTALL)
text = re.sub(r'^.*?from \.base import BaseScanner', 'from .base import BaseScanner', text, flags=re.DOTALL)
text = re.sub(r'    # ── Blind Conditional-Error SQLi  ──.*', '', text, flags=re.DOTALL)

with open(r'Logic\vulnerability_scan\sqli\scanners\sqlmap.py', 'w', encoding='utf-8') as f:
    f.write(text)

# --- BLIND ---
shutil.copy(r'Logic\vulnerability_scan\sqli_scan.py', r'Logic\vulnerability_scan\sqli\scanners\blind.py')
with open(r'Logic\vulnerability_scan\sqli\scanners\blind.py', 'r', encoding='utf-8') as f:
    text = f.read()

repl_blind = '''from .base import BaseScanner
import os
import urllib.parse
import sys
import subprocess

RECON_SCRIPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "Logic", "Recon", "script")

class BlindScanner(BaseScanner):
    def scan_blind_conditional_error'''
text = re.sub(r'class SQLiScanMixin:.*?    def blind_conditional_error_sqli', repl_blind, text, flags=re.DOTALL)
text = re.sub(r'^.*?from \.base import BaseScanner', 'from .base import BaseScanner', text, flags=re.DOTALL)
text = re.sub(r'    def check_sqli_builtin.*', '', text, flags=re.DOTALL)
text = text.replace('def blind_time_delay_sqli', 'def scan_blind_time_delay')

# Fix self._get_inject_session to self.context._get_inject_session
text = text.replace('self._get_inject_session', 'self.context._get_inject_session')
text = text.replace('self.cookie', 'self.context.cookie')
text = text.replace('_BLIND_FINGERPRINT_PROBES', 'self.context.payloads.blind_fingerprint_probes')

with open(r'Logic\vulnerability_scan\sqli\scanners\blind.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('SQLMap and Blind scanners processed.')
