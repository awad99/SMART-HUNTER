"""
HTML Report Generator for SMART-HUNTER bug bounty findings.

Produces a self-contained HTML file ready to share with program teams
or attach to HackerOne / Bugcrowd / Intigriti submissions.

Usage:
    from Logic.Report.html_report import generate_html_report

    path = generate_html_report(
        target="https://example.com",
        scan_id="20240615_120000",
        confirmed=[...],   # list of finding dicts
        candidates=[...],
        output_path="report_example_com.html",
    )
    print(f"Report saved to {path}")
"""

import html
import json
import os
from datetime import datetime


# ------------------------------------------------------------------
# CVSS-like severity → CVSS score mapping for display purposes
# ------------------------------------------------------------------
_SEVERITY_MAP = {
    "high":   ("Critical/High", "#dc3545", "9.0–10.0"),
    "medium": ("Medium",        "#fd7e14", "4.0–6.9"),
    "low":    ("Low/Info",      "#0d6efd", "0.1–3.9"),
}

_VULN_CWE = {
    "sql": ("CWE-89", "Improper Neutralization of SQL Commands"),
    "sqli": ("CWE-89", "Improper Neutralization of SQL Commands"),
    "xss": ("CWE-79", "Cross-site Scripting"),
    "rce": ("CWE-78", "OS Command Injection"),
    "command": ("CWE-78", "OS Command Injection"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "xxe": ("CWE-611", "XML External Entity Reference"),
    "lfi": ("CWE-22", "Path Traversal"),
    "path": ("CWE-22", "Path Traversal"),
    "redirect": ("CWE-601", "Open Redirect"),
    "header": ("CWE-113", "HTTP Response Splitting"),
}


def _cwe_for(finding: dict) -> tuple[str, str]:
    vuln_type = (finding.get("type") or "").lower()
    for key, cwe in _VULN_CWE.items():
        if key in vuln_type:
            return cwe
    return ("CWE-?", "Unknown Vulnerability Class")


def _severity_info(confidence: str) -> tuple[str, str, str]:
    return _SEVERITY_MAP.get(confidence.lower(), ("Unknown", "#6c757d", "N/A"))


def _finding_card(idx: int, finding: dict, is_confirmed: bool) -> str:
    confidence = finding.get("confidence", "medium").lower()
    label, color, cvss = _severity_info(confidence)
    cwe_id, cwe_name = _cwe_for(finding)
    vuln_type = html.escape(str(finding.get("type") or "Unknown"))
    param = html.escape(str(finding.get("parameter") or "N/A"))
    payload = html.escape(str(finding.get("payload") or "N/A"))
    evidence = html.escape(str(finding.get("evidence") or "N/A"))
    tool = html.escape(str(finding.get("tool") or "builtin"))
    curl_cmd = html.escape(str(finding.get("curl_command") or ""))
    status = "CONFIRMED" if is_confirmed else "CANDIDATE"
    status_color = "#198754" if is_confirmed else "#fd7e14"

    curl_block = ""
    if curl_cmd:
        curl_block = f"""
        <div class="mt-3">
          <strong>Reproduce (curl):</strong>
          <pre class="bg-dark text-light p-2 rounded mt-1" style="font-size:0.78rem;overflow-x:auto">{curl_cmd}</pre>
        </div>"""

    return f"""
    <div class="card mb-3 shadow-sm" id="finding-{idx}">
      <div class="card-header d-flex justify-content-between align-items-center" style="background:{color}22;border-left:4px solid {color}">
        <span>
          <strong style="color:{color}">[{label}]</strong>&nbsp;
          <strong>{vuln_type}</strong>
          &nbsp;<small class="text-muted">#{idx}</small>
        </span>
        <span class="badge" style="background:{status_color}">{status}</span>
      </div>
      <div class="card-body">
        <div class="row g-2 mb-2">
          <div class="col-md-4"><small class="text-muted">Parameter</small><br><code>{param}</code></div>
          <div class="col-md-4"><small class="text-muted">Tool</small><br><code>{tool}</code></div>
          <div class="col-md-4"><small class="text-muted">Classification</small><br>
            <a href="https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-','')}.html" target="_blank">{cwe_id}</a>
            — {html.escape(cwe_name)}
          </div>
        </div>
        <div class="mb-2"><strong>Payload:</strong>
          <pre class="bg-light p-2 rounded mt-1" style="font-size:0.82rem;overflow-x:auto">{payload}</pre>
        </div>
        <div class="mb-2"><strong>Evidence:</strong>
          <pre class="bg-light p-2 rounded mt-1" style="font-size:0.82rem;white-space:pre-wrap">{evidence}</pre>
        </div>
        {curl_block}
      </div>
    </div>"""


def generate_html_report(
    target: str,
    scan_id: str,
    confirmed: list,
    candidates: list = None,
    output_path: str = None,
    program_name: str = "",
    tester_name: str = "",
) -> str:
    """Generate a self-contained HTML report and write it to *output_path*.

    Returns the absolute path of the written file.
    """
    candidates = candidates or []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if output_path is None:
        safe = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        output_path = os.path.join(os.getcwd(), f"smart_hunter_report_{safe}_{scan_id}.html")

    total = len(confirmed) + len(candidates)
    high = sum(1 for f in confirmed if f.get("confidence", "").lower() == "high")
    med  = sum(1 for f in confirmed if f.get("confidence", "").lower() == "medium")
    low  = sum(1 for f in confirmed if f.get("confidence", "").lower() == "low")

    # Build finding cards
    cards_confirmed = "".join(
        _finding_card(i + 1, f, is_confirmed=True) for i, f in enumerate(confirmed)
    )
    cards_candidates = "".join(
        _finding_card(len(confirmed) + i + 1, f, is_confirmed=False) for i, f in enumerate(candidates)
    )

    # Raw JSON for download
    raw_json = html.escape(json.dumps({
        "target": target,
        "scan_id": scan_id,
        "date": now,
        "confirmed": confirmed,
        "candidates": candidates,
    }, indent=2, default=str))

    program_line = f"<strong>Program:</strong> {html.escape(program_name)}<br>" if program_name else ""
    tester_line  = f"<strong>Tester:</strong>  {html.escape(tester_name)}<br>"  if tester_name  else ""

    candidates_section = ""
    if candidates:
        candidates_section = f"""
        <h4 class="mt-4 text-warning">Candidates / Unconfirmed ({len(candidates)})</h4>
        <p class="text-muted small">These require manual verification before submission.</p>
        {cards_candidates}"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>SMART-HUNTER Report — {html.escape(target)}</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
        integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN"
        crossorigin="anonymous"/>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background:#f8f9fa; }}
    .header-bar {{ background:linear-gradient(135deg,#1a1a2e,#16213e); color:#fff; padding:2rem; }}
    .stat-card {{ border-radius:8px; padding:1rem; text-align:center; }}
    pre {{ max-height:300px; overflow-y:auto; }}
    .toc a {{ text-decoration:none; }}
  </style>
</head>
<body>
<div class="header-bar mb-4">
  <div class="container">
    <h2>&#128270; SMART-HUNTER Security Report</h2>
    <p class="mb-0 opacity-75">
      <strong>Target:</strong> {html.escape(target)}<br>
      {program_line}
      {tester_line}
      <strong>Scan ID:</strong> {html.escape(scan_id)}<br>
      <strong>Date:</strong> {now}
    </p>
  </div>
</div>

<div class="container">

  <!-- Summary stats -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
      <div class="stat-card bg-danger text-white shadow-sm">
        <h3>{high}</h3><div>High</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-card bg-warning text-dark shadow-sm">
        <h3>{med}</h3><div>Medium</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-card bg-primary text-white shadow-sm">
        <h3>{low}</h3><div>Low</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="stat-card bg-secondary text-white shadow-sm">
        <h3>{total}</h3><div>Total</div>
      </div>
    </div>
  </div>

  <!-- Confirmed findings -->
  <h4 class="text-danger">Confirmed Findings ({len(confirmed)})</h4>
  {'<p class="text-muted">No confirmed vulnerabilities found.</p>' if not confirmed else cards_confirmed}

  {candidates_section}

  <!-- Raw JSON export -->
  <h5 class="mt-5">Raw JSON Data</h5>
  <pre class="bg-dark text-light p-3 rounded" style="font-size:0.75rem">{raw_json}</pre>

  <footer class="text-muted text-center py-4 mt-4 border-top">
    Generated by <strong>SMART-HUNTER</strong> &mdash; For authorized testing only.
  </footer>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    return os.path.abspath(output_path)
