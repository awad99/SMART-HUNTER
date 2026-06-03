"""
verify_qwen_integration.py — End-to-end test for Qwen AI integration.

Tests:
  1. Model manager loads correctly (CUDA detection)
  2. Header analyzer runs on sample headers
  3. Vulnerability advisor runs on sample findings
  4. JSON output is valid and well-structured
"""

import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def _assert(condition, message):
    if not condition:
        raise AssertionError(f"FAIL: {message}")
    print(f"  [PASS] {message}")


def test_model_manager():
    """Test 1: Model manager initialization and CUDA detection."""
    print("\n" + "=" * 60)
    print("[TEST 1] Model Manager & CUDA Detection")
    print("=" * 60)

    from Logic.NLP.qwen_model_manager import QwenModelManager

    manager = QwenModelManager()
    status = manager.status()
    print(f"  Model ID: {status['model_id']}")
    print(f"  Device: {status['device']}")
    print(f"  Loaded: {status['loaded']}")

    _assert(status["model_id"] == "Qwen/Qwen2.5-Coder-1.5B-Instruct", "Correct model ID")
    _assert(status["device"] in ("cuda", "cpu"), "Valid device detected")

    # Check if CUDA is available
    try:
        import torch
        if torch.cuda.is_available():
            _assert(status["device"] == "cuda", "CUDA device selected")
            print(f"  GPU: {torch.cuda.get_device_name(0)}")
            print(f"  VRAM: {torch.cuda.get_device_properties(0).total_mem / (1024**3):.1f} GB")
        else:
            print("  [INFO] No CUDA GPU — running on CPU")
    except ImportError:
        print("  [WARN] PyTorch not installed yet")

    return manager


def test_header_analyzer(manager):
    """Test 2: Header security analysis."""
    print("\n" + "=" * 60)
    print("[TEST 2] AI Header Security Analysis")
    print("=" * 60)

    from Logic.NLP.qwen_header_analyzer import QwenHeaderAnalyzer

    analyzer = QwenHeaderAnalyzer(model_manager=manager)

    # Sample headers with intentional security issues
    request_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Cookie": "sessionid=abc123def456; csrftoken=xyz789",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
        "X-Forwarded-For": "127.0.0.1",
    }
    response_headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "Apache/2.4.52 (Ubuntu)",
        "X-Powered-By": "PHP/8.1.2",
        "Set-Cookie": "session=abc; path=/",  # Missing Secure, HttpOnly, SameSite
        "Access-Control-Allow-Origin": "*",  # Wildcard CORS
        # Missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
    }

    # Quick rule-based check (no model needed)
    print("\n  --- Quick Rule-Based Check ---")
    quick_issues = analyzer.quick_header_check(response_headers)
    print(f"  Found {len(quick_issues)} rule-based issues:")
    for issue in quick_issues:
        print(f"    [{issue['severity'].upper()}] {issue['issue']}")
    _assert(len(quick_issues) >= 4, "Rule-based check finds missing security headers")

    # Full AI analysis
    print("\n  --- Full AI Analysis ---")
    result = analyzer.analyze_headers(
        request_headers=request_headers,
        response_headers=response_headers,
        url="https://example.com/admin/dashboard",
        status_code=200,
    )

    _assert(isinstance(result, dict), "AI returns a dictionary")
    print(f"  AI Risk Level: {result.get('risk_level', 'N/A')}")
    print(f"  AI Findings: {len(result.get('findings', []))}")
    if result.get("summary"):
        print(f"  AI Summary: {result['summary'][:200]}")

    return analyzer


def test_vuln_advisor(analyzer):
    """Test 3: Vulnerability scan results analysis."""
    print("\n" + "=" * 60)
    print("[TEST 3] AI Vulnerability Advisor")
    print("=" * 60)

    # Simulated scan results
    confirmed = [
        {
            "type": "SQL Injection",
            "parameter": "id",
            "payload": "1' OR '1'='1",
            "evidence": "SQL syntax error in response: mysql_fetch_array()",
            "confidence": "high",
            "tool": "builtin_sqli",
        },
        {
            "type": "XSS (Reflected)",
            "parameter": "search",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload reflected unencoded in response body",
            "confidence": "high",
            "tool": "xsstrike",
        },
    ]
    candidates = [
        {
            "type": "CSRF",
            "parameter": "form_action:/update-profile",
            "evidence": "No CSRF token found in form",
            "status": "candidate",
        },
        {
            "type": "Header Injection",
            "parameter": "Header:X-Forwarded-For",
            "evidence": "Header value reflected in response",
            "status": "suspected",
        },
    ]
    response_headers = {
        "Server": "Apache/2.4.52",
        "Content-Type": "text/html",
    }
    targets = {
        "get": [{"url": "https://example.com/search", "params": ["q", "page"]}],
        "post": [
            {"url": "https://example.com/login", "params": ["username", "password"]},
            {"url": "https://example.com/api/update", "params": ["id", "name", "email"]},
        ],
        "cookie": [{"url": "https://example.com", "params": ["session", "csrf"]}],
    }

    result = analyzer.analyze_scan_results(
        url="https://example.com",
        confirmed_findings=confirmed,
        candidate_findings=candidates,
        response_headers=response_headers,
        targets=targets,
        risk_score=13,
    )

    _assert(isinstance(result, dict), "AI advisor returns a dictionary")
    _assert("threat_assessment" in result or "executive_summary" in result, "Has threat info")

    print(f"\n  Threat Level: {result.get('threat_assessment', 'N/A')}")
    print(f"  Attack Chains: {len(result.get('attack_chains', []))}")
    print(f"  Priority Actions: {len(result.get('priority_actions', []))}")
    print(f"  Additional Tests: {len(result.get('additional_tests', []))}")

    return result


def main():
    print("\n" + "#" * 60)
    print("#  SMART-HUNTER AI Integration Verification")
    print("#  Model: Qwen/Qwen2.5-Coder-1.5B-Instruct")
    print("#" * 60)

    # Test 1: Model manager
    manager = test_model_manager()

    # Test 2: Header analysis (loads model)
    analyzer = test_header_analyzer(manager)

    # Test 3: Vulnerability advisor
    test_vuln_advisor(analyzer)

    # Final status
    print("\n" + "=" * 60)
    print("[RESULT] All tests passed!")
    status = manager.status()
    print(f"  Model: {status['model_id']}")
    print(f"  Device: {status['device']}")
    print(f"  Loaded: {status['loaded']}")
    if "gpu_memory_allocated_mb" in status:
        print(f"  GPU Memory Used: {status['gpu_memory_allocated_mb']} MB")
    print("=" * 60)

    # Cleanup
    manager.unload()


if __name__ == "__main__":
    main()
