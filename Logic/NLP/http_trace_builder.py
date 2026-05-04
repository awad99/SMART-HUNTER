import time
import uuid
from urllib.parse import urlparse

from Logic.NLP.http_text_normalizer import (
    body_hash,
    coerce_text,
    extract_error_signatures,
    extract_header_views,
    extract_title,
    file_extension_from_url,
    header_dict,
    html_to_text,
    extract_smart_snippet,
    infer_auth_scheme,
    infer_fetch_metadata,
    infer_origin_relation,
    infer_user_agent_family,
    normalize_route_template,
    parse_body_params,
    path_tokens_from_url,
    query_metadata,
    sanitize_text,
)


class HTTPTraceBuilder:
    def __init__(self, body_limit=4000):
        self.body_limit = max(512, int(body_limit))

    def new_trace_id(self):
        return uuid.uuid4().hex

    def build_from_http_exchange(
        self,
        scan_id,
        source_module,
        page_url,
        request_method="GET",
        request_headers=None,
        request_body="",
        response_headers=None,
        response_body="",
        status_code=None,
        response_time_ms=None,
        parent_trace_id="",
        baseline_trace_id="",
        label_source="passive_trace",
        input_names=None,
        route_metadata=None,
        candidate_family="",
        confirmed_family="",
        extra_labels=None,
        trace_id=None,
    ):
        trace_id = trace_id or self.new_trace_id()
        request_headers = request_headers or {}
        response_headers = response_headers or {}
        input_names = input_names or []
        route_metadata = route_metadata or {}
        extra_labels = extra_labels or {}

        parsed = urlparse(coerce_text(page_url))
        request_header_views = extract_header_views(request_headers, "request")
        response_header_views = extract_header_views(response_headers, "response")
        request_body_clean = sanitize_text(request_body, self.body_limit)
        response_body_text = coerce_text(response_body)
        response_body_clean = extract_smart_snippet(response_body_text, self.body_limit)
        body_params = parse_body_params(header_dict(request_headers).get("content-type", ""), request_body)
        qmeta = query_metadata(page_url)
        if body_params:
            qmeta["body_param_names"] = list(body_params.keys())
        else:
            qmeta["body_param_names"] = []

        request_row = {
            "scan_id": scan_id,
            "trace_id": trace_id,
            "parent_trace_id": parent_trace_id,
            "source_module": source_module,
            "target_root": f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else "",
            "page_url": coerce_text(page_url),
            "route_template": route_metadata.get("route_template_text") or normalize_route_template(page_url),
            "method": coerce_text(request_method or "GET").upper(),
            "scheme": parsed.scheme.lower(),
            "host": (parsed.hostname or "").lower(),
            "port": parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else ""),
            "path": parsed.path or "/",
            "path_tokens_text": path_tokens_from_url(page_url),
            "query_string_raw": qmeta["query_string_raw"],
            "query_keys_text": qmeta["query_keys_text"],
            "query_param_names": qmeta["query_param_names"],
            "query_param_count": qmeta["query_param_count"],
            "query_shapes_text": qmeta["query_shapes_text"],
            "body_content_type": header_dict(request_headers).get("content-type", ""),
            "request_body_text": request_body_clean,
            "input_names": [str(name) for name in input_names if name],
            "file_extension": file_extension_from_url(page_url),
            "cookie_names_text": request_header_views["cookie_names_text"],
            "request_header_raw_ordered_text": request_header_views["raw_ordered_text"],
            "request_header_canonical_text": request_header_views["canonical_text"],
            "request_header_semantic_text": request_header_views["semantic_text"],
            "request_origin_relation_text": infer_origin_relation(request_headers, page_url),
            "request_fetch_metadata_text": infer_fetch_metadata(request_headers),
            "auth_context_type": infer_auth_scheme(request_headers),
            "referer": header_dict(request_headers).get("referer", ""),
            "origin": header_dict(request_headers).get("origin", ""),
            "sec_fetch_dest": header_dict(request_headers).get("sec-fetch-dest", ""),
            "user_agent_family": infer_user_agent_family(request_headers),
            "request_header_count": request_header_views["header_count"],
            "custom_header_count": request_header_views["custom_header_count"],
            "duplicate_header_count": request_header_views["duplicate_header_count"],
            "suspicious_override_header_present": request_header_views["suspicious_override_header_present"],
            "header_anomaly_score": request_header_views["header_anomaly_score"],
            "label_is_valuable_target": 1 if qmeta["query_param_count"] or input_names else 0,
            "label_source": label_source,
        }

        response_row = {
            "scan_id": scan_id,
            "trace_id": trace_id,
            "source_module": source_module,
            "status_code": int(status_code) if str(status_code).isdigit() else "",
            "response_time_ms": round(float(response_time_ms or 0.0), 3) if response_time_ms is not None else "",
            "content_type": header_dict(response_headers).get("content-type", ""),
            "body_title": extract_title(response_body_text),
            "body_snippet_text": response_body_clean,
            "error_signatures_text": extract_error_signatures(response_body_text, status_code=status_code),
            "redirect_location": header_dict(response_headers).get("location", ""),
            "response_header_raw_ordered_text": response_header_views["raw_ordered_text"],
            "response_header_canonical_text": response_header_views["canonical_text"],
            "response_header_semantic_text": response_header_views["semantic_text"],
            "response_security_headers_text": response_header_views["security_headers_text"],
            "set_cookie_semantic_text": response_header_views["set_cookie_semantic_text"],
            "response_header_count": response_header_views["header_count"],
            "security_header_count": response_header_views["security_header_count"],
            "set_cookie_count": response_header_views.get("set_cookie_count", 0),
            "response_size": len(response_body_text.encode("utf-8", errors="ignore")),
            "response_headers_anomaly_score": response_header_views["header_anomaly_score"],
            "server_header": header_dict(response_headers).get("server", ""),
            "body_hash": body_hash(response_body_text),
            "cache_signals": "cache_control_present" if header_dict(response_headers).get("cache-control") else "",
            "label_is_valuable_target": request_row["label_is_valuable_target"],
            "label_source": label_source,
        }

        header_rows = []
        for row in request_header_views["header_rows"]:
            entry = dict(row)
            entry.update(
                {
                    "scan_id": scan_id,
                    "trace_id": trace_id,
                    "source_module": source_module,
                }
            )
            header_rows.append(entry)
        for row in response_header_views["header_rows"]:
            entry = dict(row)
            entry.update(
                {
                    "scan_id": scan_id,
                    "trace_id": trace_id,
                    "source_module": source_module,
                }
            )
            header_rows.append(entry)

        label_row = {
            "scan_id": scan_id,
            "trace_id": trace_id,
            "parent_trace_id": parent_trace_id,
            "baseline_trace_id": baseline_trace_id,
            "source_module": source_module,
            "label_target_value": request_row["label_is_valuable_target"],
            "label_candidate_family": candidate_family,
            "label_confirmed_family": confirmed_family,
            "label_source": label_source,
            "label_confidence": float(extra_labels.get("label_confidence", 0.0)),
            "human_reviewed": bool(extra_labels.get("human_reviewed", False)),
            "validation_tool": extra_labels.get("validation_tool", ""),
            "analyzer_route": extra_labels.get("analyzer_route", ""),
            "analyzer_reason": extra_labels.get("analyzer_reason", ""),
        }

        return {
            "request": request_row,
            "response": response_row,
            "headers": header_rows,
            "label": label_row,
        }

    def build_from_response_object(
        self,
        scan_id,
        source_module,
        response,
        fallback_url="",
        parent_trace_id="",
        baseline_trace_id="",
        label_source="passive_trace",
        input_names=None,
        route_metadata=None,
        candidate_family="",
        confirmed_family="",
        extra_labels=None,
    ):
        request = getattr(response, "request", None)
        request_url = fallback_url or coerce_text(getattr(request, "url", "") or getattr(response, "url", ""))
        request_method = coerce_text(getattr(request, "method", "GET") or "GET").upper()
        request_headers = getattr(request, "headers", {}) or {}
        request_body = ""
        for attr in ("content", "body"):
            if hasattr(request, attr):
                try:
                    request_body = coerce_text(getattr(request, attr))
                    if request_body:
                        break
                except Exception:
                    continue
        response_headers = getattr(response, "headers", {}) or {}
        response_body = ""
        try:
            response_body = coerce_text(getattr(response, "text", ""))
        except Exception:
            response_body = ""

        response_time_ms = None
        elapsed = getattr(response, "elapsed", None)
        if elapsed is not None:
            try:
                response_time_ms = elapsed.total_seconds() * 1000
            except Exception:
                response_time_ms = None

        status_code = getattr(response, "status_code", "")
        return self.build_from_http_exchange(
            scan_id=scan_id,
            source_module=source_module,
            page_url=request_url,
            request_method=request_method,
            request_headers=request_headers,
            request_body=request_body,
            response_headers=response_headers,
            response_body=response_body,
            status_code=status_code,
            response_time_ms=response_time_ms,
            parent_trace_id=parent_trace_id,
            baseline_trace_id=baseline_trace_id,
            label_source=label_source,
            input_names=input_names,
            route_metadata=route_metadata,
            candidate_family=candidate_family,
            confirmed_family=confirmed_family,
            extra_labels=extra_labels,
        )

    def build_candidate_trace(
        self,
        scan_id,
        source_module,
        page_url,
        request_method="GET",
        request_headers=None,
        request_body="",
        input_names=None,
        parent_trace_id="",
        baseline_trace_id="",
        label_source="candidate_trace",
        candidate_family="",
        extra_labels=None,
        route_metadata=None,
    ):
        return self.build_from_http_exchange(
            scan_id=scan_id,
            source_module=source_module,
            page_url=page_url,
            request_method=request_method,
            request_headers=request_headers or {},
            request_body=request_body,
            response_headers={},
            response_body="",
            status_code="",
            response_time_ms="",
            parent_trace_id=parent_trace_id,
            baseline_trace_id=baseline_trace_id,
            label_source=label_source,
            input_names=input_names or [],
            route_metadata=route_metadata or {},
            candidate_family=candidate_family,
            confirmed_family="",
            extra_labels=extra_labels or {},
        )
