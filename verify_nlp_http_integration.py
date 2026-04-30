import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from Data.Update_Data.nlp_trace_writer import NLPTraceWriter
from Logic.NLP.http_trace_builder import HTTPTraceBuilder
from Logic.NLP.route_decider import RouteDecider
from Logic.NLP.train_http_classifier import HTTPDatasetReadiness


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    writer = NLPTraceWriter()
    writer.ensure_layout()

    readiness = HTTPDatasetReadiness().summarize()
    for section in ("requests", "responses", "headers", "labels", "splits"):
        _assert(readiness[section]["exists"], f"Missing dataset file: {section}")
        _assert(readiness[section]["headers"], f"Missing header row in: {section}")

    builder = HTTPTraceBuilder()
    decider = RouteDecider()

    path_trace = builder.build_from_http_exchange(
        scan_id="VERIFY_TRACE",
        source_module="verify.nlp",
        page_url="https://example.test/download?file=report.pdf&id=123",
        request_method="GET",
        request_headers={
            "User-Agent": "Mozilla/5.0",
            "Cookie": "sessionid=abc123; csrftoken=xyz",
            "Sec-Fetch-Site": "same-origin",
        },
        response_headers={
            "Content-Type": "text/html; charset=utf-8",
            "Server": "nginx",
            "Cache-Control": "no-store",
        },
        response_body="<html><title>Download report</title><body>Choose a file export.</body></html>",
        status_code=200,
        input_names=["file", "id"],
        label_source="verification",
    )
    path_decision = decider.decide(path_trace)
    _assert(path_decision["candidate_family"] == "path_traversal_candidate", "Path traversal routing heuristic failed")
    _assert(path_decision["analyzer_route"] == "run_path_analyze", "Path traversal analyzer route mismatch")

    static_trace = builder.build_from_http_exchange(
        scan_id="VERIFY_TRACE",
        source_module="verify.nlp",
        page_url="https://example.test/assets/app.js",
        request_method="GET",
        request_headers={"User-Agent": "Mozilla/5.0"},
        response_headers={"Content-Type": "application/javascript"},
        response_body="console.log('ok');",
        status_code=200,
        label_source="verification",
    )
    static_decision = decider.decide(static_trace)
    _assert(static_decision["candidate_family"] == "low_value_static", "Static asset routing heuristic failed")
    _assert(static_decision["analyzer_route"] == "skip_heavy_scan", "Static asset route mismatch")

    http_request_headers = set(readiness["requests"]["headers"])
    http_response_headers = set(readiness["responses"]["headers"])
    http_label_headers = set(readiness["labels"]["headers"])
    _assert({"scan_id", "trace_id"}.issubset(http_request_headers), "Request schema missing join columns")
    _assert({"scan_id", "trace_id"}.issubset(http_response_headers), "Response schema missing join columns")
    _assert({"scan_id", "trace_id"}.issubset(http_label_headers), "Label schema missing join columns")

    result = {
        "status": "ok",
        "datasets_initialized": True,
        "join_ready": readiness["join_ready"],
        "training_ready": readiness["training_ready"],
        "path_trace_route": path_decision,
        "static_trace_route": static_decision,
        "note": "The NLP HTTP system is structurally ready. Training remains gated until real joined traces and labels are collected.",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
