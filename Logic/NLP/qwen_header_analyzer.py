"""
qwen_header_analyzer.py — AI-Powered HTTP Header & Vulnerability Analyzer

Uses Qwen2.5-Coder-1.5B-Instruct to:
  1. Analyze HTTP response headers for security misconfigurations
  2. Analyze vulnerability scan results and recommend attack chains
  3. Prioritize findings and suggest next steps for deeper exploitation
  4. Provide intelligent security assessment summaries
"""

import json
import re
import time
from pydantic import BaseModel, Field

from Logic.NLP.qwen_model_manager import QwenModelManager
from Logic.NLP.http_text_normalizer import (
    extract_header_views,
    header_dict,
    infer_auth_scheme,
    infer_user_agent_family,
    sanitize_text,
)


# ── System Prompts ───────────────────────────────────────────────────────

HEADER_ANALYSIS_SYSTEM_PROMPT = """\
You are an expert cybersecurity analyst specializing in HTTP security headers and web application security.
You analyze HTTP request/response headers and identify:
1. Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
2. Misconfigured headers (weak CSP, permissive CORS, etc.)
3. Information leakage (Server version, X-Powered-By, etc.)
4. Cookie security issues (missing Secure, HttpOnly, SameSite flags)
5. Authentication weaknesses visible in headers
6. Suspicious headers that could indicate injection points

Respond ONLY in valid JSON format with this structure:
{
  "risk_level": "critical|high|medium|low|info",
  "findings": [
    {
      "category": "string",
      "severity": "critical|high|medium|low|info",
      "header": "header-name or N/A",
      "issue": "brief description",
      "recommendation": "fix suggestion"
    }
  ],
  "summary": "one paragraph overall assessment"
}
"""

VULN_ADVISOR_SYSTEM_PROMPT = """\
You are an elite penetration tester and vulnerability researcher. You analyze scan results from automated vulnerability scanners and provide expert recommendations.

Given the scan findings, you MUST:
1. Analyze each vulnerability and assess real-world exploitability
2. Suggest specific attack chains that combine multiple findings
3. Recommend which findings to exploit first (priority order)
4. Suggest additional tests the scanner should run based on what was found
5. Identify patterns that suggest deeper vulnerabilities not yet found
6. Recommend specific payloads or techniques for further exploitation

Respond ONLY in valid JSON format with this structure:
{
  "threat_assessment": "critical|high|medium|low",
  "attack_chains": [
    {
      "name": "chain name",
      "steps": ["step 1", "step 2"],
      "impact": "what the attacker achieves",
      "likelihood": "high|medium|low"
    }
  ],
  "priority_actions": [
    {
      "action": "what to do",
      "reason": "why this matters",
      "priority": 1
    }
  ],
  "additional_tests": [
    {
      "test": "test name",
      "reason": "why run this test",
      "technique": "specific technique or payload"
    }
  ],
  "deeper_insights": "paragraph with patterns and hidden risks noticed",
  "executive_summary": "brief summary for the report"
}
"""


class HeaderFinding(BaseModel):
    category: str
    severity: str
    header: str
    issue: str
    recommendation: str

class HeaderAnalysisResult(BaseModel):
    risk_level: str
    findings: list[HeaderFinding]
    summary: str

class AttackChain(BaseModel):
    name: str
    steps: list[str]
    impact: str
    likelihood: str

class PriorityAction(BaseModel):
    action: str
    reason: str
    priority: int

class AdditionalTest(BaseModel):
    test: str
    reason: str
    technique: str

class VulnerabilityAnalysisResult(BaseModel):
    threat_assessment: str
    attack_chains: list[AttackChain]
    priority_actions: list[PriorityAction]
    additional_tests: list[AdditionalTest]
    deeper_insights: str
    executive_summary: str

class QwenHeaderAnalyzer:
    """AI-powered HTTP header and vulnerability analysis using Qwen2.5-Coder."""

    def __init__(self, model_manager: QwenModelManager | None = None):
        self._manager = model_manager or QwenModelManager()

    # ── Header Analysis ──────────────────────────────────────────────────

    def analyze_headers(
        self,
        request_headers: dict | None = None,
        response_headers: dict | None = None,
        url: str = "",
        status_code: int | None = None,
    ) -> dict:
        """Analyze HTTP headers for security issues using the AI model."""
        request_headers = request_headers or {}
        response_headers = response_headers or {}

        # Build a structured representation using existing normalizer
        req_view = extract_header_views(request_headers, "request")
        resp_view = extract_header_views(response_headers, "response")
        resp_dict = header_dict(response_headers)
        auth_scheme = infer_auth_scheme(request_headers)

        prompt = self._build_header_prompt(
            url=url,
            status_code=status_code,
            req_view=req_view,
            resp_view=resp_view,
            resp_dict=resp_dict,
            auth_scheme=auth_scheme,
        )

        print("  [*] AI analyzing HTTP headers...")
        start_time = time.time()
        raw = self._manager.generate(
            prompt=prompt,
            system_prompt=HEADER_ANALYSIS_SYSTEM_PROMPT,
            max_new_tokens=1024,
            temperature=0.2,
            json_schema=HeaderAnalysisResult.model_json_schema(),
        )
        elapsed = time.time() - start_time
        print(f"  [+] AI header analysis complete ({elapsed:.1f}s)")

        return self._parse_json_response(raw, fallback_type="header_analysis")

    def _build_header_prompt(self, url, status_code, req_view, resp_view, resp_dict, auth_scheme):
        """Build a detailed prompt for header analysis."""
        lines = [
            f"Analyze the HTTP headers for security issues.",
            f"",
            f"TARGET: {url}",
            f"STATUS CODE: {status_code or 'unknown'}",
            f"AUTH SCHEME: {auth_scheme}",
            f"",
            f"=== REQUEST HEADERS ===",
            req_view.get("raw_ordered_text", "(none)"),
            f"",
            f"=== RESPONSE HEADERS ===",
            resp_view.get("raw_ordered_text", "(none)"),
            f"",
            f"=== SECURITY HEADER ANALYSIS ===",
            f"Security headers present: {resp_view.get('security_header_count', 0)}",
            f"Security headers: {resp_view.get('security_headers_text', 'none')}",
            f"Set-Cookie count: {resp_view.get('set_cookie_count', 0)}",
            f"Set-Cookie flags: {resp_view.get('set_cookie_semantic_text', 'none')}",
            f"Custom headers: {resp_view.get('custom_header_count', 0)}",
            f"Header anomaly score: {resp_view.get('header_anomaly_score', 0)}",
            f"",
            f"Server: {resp_dict.get('server', 'not disclosed')}",
            f"X-Powered-By: {resp_dict.get('x-powered-by', 'not disclosed')}",
            f"Content-Type: {resp_dict.get('content-type', 'unknown')}",
            f"",
            f"Provide a thorough security analysis of these headers in JSON format.",
        ]
        return "\n".join(lines)

    # ── Vulnerability Scan Analysis ──────────────────────────────────────

    def analyze_scan_results(
        self,
        url: str,
        confirmed_findings: list[dict],
        candidate_findings: list[dict],
        response_headers: dict | None = None,
        targets: dict | None = None,
        risk_score: int = 0,
    ) -> dict:
        """Analyze vulnerability scan results and provide AI recommendations."""
        max_confirmed = 15
        max_candidates = 10
        
        print("\n" + "=" * 60)
        print("  [*] AI VULNERABILITY ADVISOR — Analyzing scan results...")
        print("=" * 60)
        start_time = time.time()
        
        if len(confirmed_findings) <= max_confirmed and len(candidate_findings) <= max_candidates:
            prompt = self._build_vuln_prompt(
                url=url,
                confirmed=confirmed_findings,
                candidates=candidate_findings,
                headers=response_headers,
                targets=targets,
                risk_score=risk_score,
            )

            raw = self._manager.generate(
                prompt=prompt,
                system_prompt=VULN_ADVISOR_SYSTEM_PROMPT,
                max_new_tokens=1536,
                temperature=0.3,
                json_schema=VulnerabilityAnalysisResult.model_json_schema(),
            )
            result_raw = raw
        else:
            batches = []
            c_idx, cand_idx = 0, 0
            while c_idx < len(confirmed_findings) or cand_idx < len(candidate_findings):
                c_batch = confirmed_findings[c_idx : c_idx + max_confirmed]
                cand_batch = candidate_findings[cand_idx : cand_idx + max_candidates]
                c_idx += max_confirmed
                cand_idx += max_candidates
                
                prompt = self._build_vuln_prompt(
                    url=url,
                    confirmed=c_batch,
                    candidates=cand_batch,
                    headers=response_headers,
                    targets=targets,
                    risk_score=risk_score,
                )
                print(f"  [*] Analyzing batch {len(batches)+1}...")
                raw = self._manager.generate(
                    prompt=prompt,
                    system_prompt=VULN_ADVISOR_SYSTEM_PROMPT,
                    max_new_tokens=1536,
                    temperature=0.3,
                    json_schema=VulnerabilityAnalysisResult.model_json_schema(),
                )
                batches.append(raw)
                
            print(f"  [*] Synthesizing {len(batches)} batches...")
            synthesis_prompt = f"Synthesize the following {len(batches)} vulnerability reports into one final unified report.\n\n"
            for i, batch_raw in enumerate(batches):
                synthesis_prompt += f"=== REPORT {i+1} ===\n{batch_raw}\n\n"
                
            raw_final = self._manager.generate(
                prompt=synthesis_prompt,
                system_prompt=VULN_ADVISOR_SYSTEM_PROMPT,
                max_new_tokens=2048,
                temperature=0.3,
                json_schema=VulnerabilityAnalysisResult.model_json_schema(),
            )
            result_raw = raw_final

        elapsed = time.time() - start_time
        print(f"  [+] AI analysis complete ({elapsed:.1f}s)")

        result = self._parse_json_response(result_raw, fallback_type="vuln_analysis")
        self._print_ai_report(result)
        return result

    def _build_vuln_prompt(self, url, confirmed, candidates, headers, targets, risk_score):
        """Build prompt for vulnerability scan analysis."""
        lines = [
            f"Analyze vulnerability scan results and provide attack recommendations.",
            f"",
            f"TARGET: {url}",
            f"RISK SCORE: {risk_score}",
            f"",
        ]

        # Confirmed findings
        lines.append(f"=== CONFIRMED VULNERABILITIES ({len(confirmed)}) ===")
        if confirmed:
            for i, v in enumerate(confirmed, 1):
                vtype = v.get("type") or v.get("vulnerability_type") or "Unknown"
                lines.append(
                    f"  [{i}] Type: {vtype}\n"
                    f"      Parameter: {v.get('parameter', 'N/A')}\n"
                    f"      Payload: {sanitize_text(str(v.get('payload', 'N/A')), 200)}\n"
                    f"      Evidence: {sanitize_text(str(v.get('evidence', '')), 200)}\n"
                    f"      Confidence: {v.get('confidence', 'unknown')}\n"
                    f"      Tool: {v.get('tool', 'unknown')}"
                )
        else:
            lines.append("  (none)")

        # Candidate findings
        lines.append(f"\n=== CANDIDATE/SUSPECTED FINDINGS ({len(candidates)}) ===")
        if candidates:
            for i, v in enumerate(candidates, 1):
                vtype = v.get("type") or v.get("vulnerability_type") or "Unknown"
                lines.append(
                    f"  [{i}] Type: {vtype}\n"
                    f"      Parameter: {v.get('parameter', 'N/A')}\n"
                    f"      Evidence: {sanitize_text(str(v.get('evidence', '')), 150)}\n"
                    f"      Status: {v.get('status', 'candidate')}"
                )
        else:
            lines.append("  (none)")

        # Response headers summary
        if headers:
            resp_dict = header_dict(headers)
            lines.append(f"\n=== RESPONSE HEADERS CONTEXT ===")
            for key in ["server", "x-powered-by", "content-security-policy",
                         "strict-transport-security", "x-frame-options",
                         "access-control-allow-origin", "set-cookie"]:
                val = resp_dict.get(key)
                if val:
                    lines.append(f"  {key}: {sanitize_text(val, 200)}")

        # Discovered attack surface
        if targets:
            lines.append(f"\n=== DISCOVERED ATTACK SURFACE ===")
            lines.append(f"  GET targets: {len(targets.get('get', []))}")
            lines.append(f"  POST targets: {len(targets.get('post', []))}")
            lines.append(f"  Cookie targets: {len(targets.get('cookie', []))}")
            # Show first few POST endpoint details
            for t in targets.get("post", [])[:5]:
                lines.append(f"  POST {t.get('url', '?')} params={t.get('params', [])}")

        lines.append(
            f"\nBased on these results, provide a JSON analysis with "
            f"attack chains, priority actions, and additional tests to run."
        )
        return "\n".join(lines)

    # ── Trace-based analysis ─────────────────────────────────────────────

    def analyze_trace(self, trace_bundle: dict) -> dict:
        """Analyze an HTTPTraceBuilder output bundle."""
        request = trace_bundle.get("request", {})
        response = trace_bundle.get("response", {})

        return self.analyze_headers(
            request_headers={},  # Headers are pre-extracted in the trace
            response_headers={},
            url=request.get("page_url_text", ""),
            status_code=response.get("status_code"),
        )

    # ── Pretty-print AI report ───────────────────────────────────────────

    def _print_ai_report(self, result: dict) -> None:
        """Print a formatted AI security advisory to the console."""
        print(f"\n{'='*70}")
        print(f" {'🤖':} AI SECURITY ADVISOR REPORT")
        print(f"{'='*70}")

        # Threat level
        threat = result.get("threat_assessment", "unknown")
        threat_colors = {
            "critical": "!!!",
            "high": "!! ",
            "medium": "!  ",
            "low": "   ",
        }
        marker = threat_colors.get(threat, "   ")
        print(f"\n  [{marker}] THREAT LEVEL: {threat.upper()}")

        # Executive summary
        summary = result.get("executive_summary", "")
        if summary:
            print(f"\n  SUMMARY: {summary}")

        # Attack chains
        chains = result.get("attack_chains", [])
        if chains:
            print(f"\n  {'─'*50}")
            print(f"  ATTACK CHAINS ({len(chains)}):")
            for i, chain in enumerate(chains, 1):
                print(f"\n    [{i}] {chain.get('name', 'Unnamed Chain')}")
                print(f"        Impact: {chain.get('impact', 'Unknown')}")
                print(f"        Likelihood: {chain.get('likelihood', 'Unknown')}")
                steps = chain.get("steps", [])
                for j, step in enumerate(steps, 1):
                    print(f"        Step {j}: {step}")

        # Priority actions
        actions = result.get("priority_actions", [])
        if actions:
            print(f"\n  {'─'*50}")
            print(f"  PRIORITY ACTIONS ({len(actions)}):")
            for action in actions:
                prio = action.get("priority", "?")
                print(f"    [P{prio}] {action.get('action', '')}")
                print(f"         Reason: {action.get('reason', '')}")

        # Additional tests
        tests = result.get("additional_tests", [])
        if tests:
            print(f"\n  {'─'*50}")
            print(f"  RECOMMENDED ADDITIONAL TESTS ({len(tests)}):")
            for test in tests:
                print(f"    [+] {test.get('test', '')}")
                print(f"        Why: {test.get('reason', '')}")
                technique = test.get("technique", "")
                if technique:
                    print(f"        Technique: {technique}")

        # Deeper insights
        insights = result.get("deeper_insights", "")
        if insights:
            print(f"\n  {'─'*50}")
            print(f"  DEEPER INSIGHTS:")
            # Wrap at ~70 chars
            words = insights.split()
            line = "    "
            for w in words:
                if len(line) + len(w) > 72:
                    print(line)
                    line = "    "
                line += w + " "
            if line.strip():
                print(line)

        print(f"\n{'='*70}\n")

    # ── JSON Parsing helper ──────────────────────────────────────────────

    def _parse_json_response(self, raw_text: str, fallback_type: str = "unknown") -> dict:
        """Extract JSON from model response, handling markdown code fences."""
        text = raw_text.strip()

        # Try to extract JSON from markdown code fence
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if json_match:
            text = json_match.group(1).strip()

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in the text
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        # Fallback: return raw text in a structured format
        return {
            "parse_error": True,
            "raw_response": text[:2000],
            "type": fallback_type,
            "threat_assessment": "unknown",
            "executive_summary": text[:500] if text else "Model returned unparseable output",
            "attack_chains": [],
            "priority_actions": [],
            "additional_tests": [],
            "deeper_insights": "",
        }

    # ── Quick header check (lightweight, no AI) ──────────────────────────

    @staticmethod
    def quick_header_check(response_headers: dict) -> list[dict]:
        """Fast rule-based header check (no model required). Use as fallback."""
        issues = []
        rd = header_dict(response_headers)

        checks = [
            ("content-security-policy", "Missing Content-Security-Policy header",
             "high", "Add CSP header to prevent XSS and injection attacks"),
            ("strict-transport-security", "Missing Strict-Transport-Security (HSTS)",
             "high", "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            ("x-frame-options", "Missing X-Frame-Options header",
             "medium", "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking"),
            ("x-content-type-options", "Missing X-Content-Type-Options header",
             "medium", "Add X-Content-Type-Options: nosniff"),
            ("referrer-policy", "Missing Referrer-Policy header",
             "low", "Add Referrer-Policy: strict-origin-when-cross-origin"),
            ("permissions-policy", "Missing Permissions-Policy header",
             "low", "Add Permissions-Policy to restrict browser features"),
        ]

        for header_name, issue, severity, recommendation in checks:
            if header_name not in rd:
                issues.append({
                    "category": "missing_security_header",
                    "severity": severity,
                    "header": header_name,
                    "issue": issue,
                    "recommendation": recommendation,
                })

        # Check for information leakage
        if rd.get("server"):
            issues.append({
                "category": "information_leakage",
                "severity": "low",
                "header": "server",
                "issue": f"Server header discloses: {rd['server']}",
                "recommendation": "Remove or obfuscate the Server header",
            })
        if rd.get("x-powered-by"):
            issues.append({
                "category": "information_leakage",
                "severity": "medium",
                "header": "x-powered-by",
                "issue": f"X-Powered-By discloses technology: {rd['x-powered-by']}",
                "recommendation": "Remove the X-Powered-By header",
            })

        # CORS wildcard
        cors = rd.get("access-control-allow-origin", "")
        if cors == "*":
            issues.append({
                "category": "cors_misconfiguration",
                "severity": "high",
                "header": "access-control-allow-origin",
                "issue": "CORS allows all origins (wildcard *)",
                "recommendation": "Restrict CORS to specific trusted origins",
            })

        return issues
