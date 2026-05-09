import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "Logic")):
    if path not in sys.path:
        sys.path.insert(0, path)


from vulnerability_scan.rce.payload_manager import PayloadManager
from vulnerability_scan.rce.scanners.builtin import BuiltinScanner


def test_time_probes_keep_ping_fallback_for_same_separator_family():
    manager = PayloadManager()

    selected_types = {probe["type"] for probe in manager.select_time_probes()}

    assert "Linux sleep double-OR" in selected_types
    assert "Linux ping double-OR" in selected_types


def test_post_variants_wrap_ping_for_feedback_email_fields():
    variants = BuiltinScanner._build_payload_variants("|| ping -c 5 127.0.0.1", "post")

    assert variants[0] == "x||ping -c 10 127.0.0.1||"
    assert "x||ping -c 5 127.0.0.1||" in variants
    assert "test@test.com||ping -c 5 127.0.0.1||" in variants


def test_plus_encoded_payloads_are_normalized_for_structured_requests():
    variants = BuiltinScanner._build_payload_variants("x||ping+-c+10+127.0.0.1||", "post")

    assert "x||ping -c 10 127.0.0.1||" in variants
    assert "x||ping+-c+10+127.0.0.1||" not in variants


def test_strong_repeat_delay_fallback_accepts_repeatable_10s_ping_hits():
    assert BuiltinScanner._strong_repeat_delay_hit(
        0.7, 15.7, 15.6, "x||ping -c 10 127.0.0.1||"
    )


def test_email_control_value_stays_valid_for_feedback_forms():
    assert BuiltinScanner._benign_control_value("email", "FUZZ") == "deep.scan@example.com"
