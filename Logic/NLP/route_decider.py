from collections import defaultdict


class RouteDecider:
    FAMILY_TO_ANALYZER = {
        "path_traversal_candidate": "run_path_analyze",
        "idor_candidate": "run_idor_scan",
        "xss_candidate": "run_xss_scan",
        "sqli_candidate": "run_sqli_scan",
        "command_injection_candidate": "run_rce_scan",
        "header_injection_candidate": "run_header_scan",
        "header_misconfiguration_candidate": "run_header_scan",
        "open_redirect_candidate": "skip_heavy_scan",
        "low_value_static": "skip_heavy_scan",
    }

    def decide(self, trace_bundle, tabular_prediction=None):
        request = trace_bundle.get("request", {})
        response = trace_bundle.get("response", {})
        scores = defaultdict(float)
        reasons = []

        path_tokens = set((request.get("path_tokens_text") or "").split())
        query_keys = set((request.get("query_keys_text") or "").split())
        input_names = set((request.get("input_names_text") or "").split())
        query_shapes = request.get("query_shapes_text", "")
        request_semantics = request.get("request_header_semantic_text", "")
        response_semantics = response.get("response_header_semantic_text", "")
        error_signatures = response.get("error_signatures_text", "")
        route_template = request.get("route_template_text", "")
        content_type = (response.get("content_type_text") or "").lower()
        auth_scheme = request.get("request_auth_scheme_text", "")
        security_header_count = int(response.get("security_header_count") or 0)
        response_status = int(response.get("status_code") or 0) if str(response.get("status_code", "")).isdigit() else 0
        joined_keys = path_tokens | query_keys | input_names

        def add_score(family, amount, reason):
            scores[family] += amount
            reasons.append(reason)

        if joined_keys & {"file", "path", "download", "include", "template", "doc", "document", "folder", "page"}:
            add_score("path_traversal_candidate", 0.58, "path/file style parameter or route token")
        if "path_like" in query_shapes or "filename_like" in query_shapes:
            add_score("path_traversal_candidate", 0.26, "parameter values look like file paths")

        if joined_keys & {"id", "user", "userid", "user_id", "account", "order", "invoice", "profile", "project"}:
            add_score("idor_candidate", 0.42, "identifier style route or parameter")
        if "{int}" in route_template or "{uuid}" in route_template:
            add_score("idor_candidate", 0.20, "normalized route contains object placeholders")
        if auth_scheme in {"bearer", "session_cookie", "authorization_header"}:
            add_score("idor_candidate", 0.08, "authenticated context can support object comparison")

        if joined_keys & {"search", "q", "query", "message", "comment", "name", "term"}:
            add_score("xss_candidate", 0.32, "reflective input names present")
        if content_type.startswith("text/html") and input_names:
            add_score("xss_candidate", 0.24, "interactive html page")
        if "security_header_content_security_policy_present" not in response_semantics and content_type.startswith("text/html"):
            add_score("xss_candidate", 0.10, "html response lacks csp signal")

        if "sql_error_signature" in error_signatures:
            add_score("sqli_candidate", 0.72, "response contains sql error signature")
        if joined_keys & {"id", "sort", "filter", "search", "query"}:
            add_score("sqli_candidate", 0.16, "common sql input parameters detected")

        if joined_keys & {"cmd", "command", "exec", "execute", "ping", "host", "ip", "domain"}:
            add_score("command_injection_candidate", 0.66, "command style parameter names present")
        if "file_path_signature" in error_signatures:
            add_score("command_injection_candidate", 0.10, "response exposes filesystem paths")

        if joined_keys & {"redirect", "return", "next", "continue", "dest", "url"}:
            add_score("open_redirect_candidate", 0.74, "redirect style parameters present")

        if request.get("suspicious_override_header_present"):
            add_score("header_injection_candidate", 0.74, "override style request header present")
        if security_header_count <= 2 and content_type.startswith("text/html"):
            add_score("header_misconfiguration_candidate", 0.46, "html response has weak security header coverage")
        if "response_server_disclosed" in response_semantics:
            add_score("header_misconfiguration_candidate", 0.08, "server banner disclosed")

        if (
            not query_keys
            and not input_names
            and (
                content_type.startswith("image/")
                or "javascript" in content_type
                or content_type.startswith("text/css")
                or request.get("file_extension_text") in {"css", "js", "png", "jpg", "jpeg", "gif", "svg", "woff", "woff2"}
            )
        ):
            add_score("low_value_static", 0.88, "static asset with no interactive inputs")

        if tabular_prediction:
            predictions = tabular_prediction.get("predictions", {})
            mapping = {
                "sql_injection": "sqli_candidate",
                "xss": "xss_candidate",
                "command_injection": "command_injection_candidate",
                "path_traversal": "path_traversal_candidate",
                "idor": "idor_candidate",
            }
            for key, family in mapping.items():
                probability = float(predictions.get(key, 0.0) or 0.0)
                if probability > 0:
                    add_score(family, min(0.35, probability * 0.4), f"tabular branch supports {family}")

        top_family = "low_value_static"
        top_score = 0.0
        if scores:
            top_family, top_score = max(scores.items(), key=lambda item: item[1])

        if top_family == "low_value_static" and any(
            scores.get(family, 0.0) >= 0.35 for family in scores if family != "low_value_static"
        ):
            alternative = max(
                ((family, score) for family, score in scores.items() if family != "low_value_static"),
                key=lambda item: item[1],
            )
            top_family, top_score = alternative

        top_score = round(min(0.99, top_score), 3)
        analyzer_route = self.FAMILY_TO_ANALYZER.get(top_family, "skip_heavy_scan")
        if top_score < 0.30:
            analyzer_route = "skip_heavy_scan"

        valuable_target = int(top_family != "low_value_static" and top_score >= 0.30)
        relevant_reasons = []
        for reason in reasons:
            if reason not in relevant_reasons:
                relevant_reasons.append(reason)

        return {
            "candidate_family": top_family,
            "analyzer_route": analyzer_route,
            "confidence": top_score,
            "valuable_target": valuable_target,
            "reason": "; ".join(relevant_reasons[:4]) or "no strong passive signal",
            "scores": {family: round(score, 3) for family, score in sorted(scores.items())},
        }
