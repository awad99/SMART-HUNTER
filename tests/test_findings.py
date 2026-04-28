import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Logic" / "Recon"))

from vulnerability_scan.findings import normalize_finding, risk_score, split_findings


def test_legacy_confirmed_confidence_becomes_status():
    finding = normalize_finding({"type": "SQL Injection", "confidence": "confirmed"})

    assert finding["confidence"] == "high"
    assert finding["status"] == "confirmed"


def test_size_diff_sqli_is_candidate_only():
    finding = normalize_finding({
        "type": "SQL Injection",
        "confidence": "high",
        "evidence": "Response size diff: 800 bytes",
    })

    assert finding["status"] == "candidate"


def test_boolean_size_toggle_is_suspected_only():
    finding = normalize_finding({
        "type": "SQL Injection",
        "confidence": "medium",
        "evidence": "Boolean TRUE/FALSE size difference: 500 bytes",
    })

    assert finding["status"] == "suspected"


def test_split_findings_keeps_only_confirmed_in_confirmed_bucket():
    findings = [
        {"type": "Command Injection", "confidence": "high"},
        {"type": "SQL Injection", "confidence": "high", "evidence": "Response size diff: 400 bytes"},
        {"type": "IDOR", "confidence": "low", "status": "candidate"},
    ]

    confirmed, candidates = split_findings(findings)

    assert len(confirmed) == 1
    assert len(candidates) == 2
    assert risk_score(confirmed) == 5
