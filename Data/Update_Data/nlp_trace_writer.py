import csv
import os

from Data.Queries.q_http_trace_labels import save_http_trace_label
from Data.Queries.q_http_traces import save_http_trace, save_http_trace_headers


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NLP_DIR = os.path.join(BASE_DIR, "Data", "Datasets", "Datasets_for_Model_NLP")
HTTP_DIR = os.path.join(NLP_DIR, "http")
RECON_DIR = os.path.join(NLP_DIR, "recon")
VULN_DIR = os.path.join(NLP_DIR, "vulnerability")

HTTP_REQUEST_COLUMNS = [
    "scan_id",
    "trace_id",
    "parent_trace_id",
    "source_module",
    "target_root",
    "page_url_text",
    "route_template_text",
    "method_text",
    "path_tokens_text",
    "query_string_raw",
    "query_keys_text",
    "query_shapes_text",
    "request_body_text",
    "input_names_text",
    "file_extension_text",
    "cookie_names_text",
    "request_header_raw_ordered_text",
    "request_header_canonical_text",
    "request_header_semantic_text",
    "request_origin_relation_text",
    "request_fetch_metadata_text",
    "request_auth_scheme_text",
    "request_header_count",
    "custom_header_count",
    "duplicate_header_count",
    "suspicious_override_header_present",
    "header_anomaly_score",
    "label_is_valuable_target",
    "label_source",
]

HTTP_RESPONSE_COLUMNS = [
    "scan_id",
    "trace_id",
    "source_module",
    "status_code",
    "response_time_ms",
    "content_type_text",
    "body_title_text",
    "body_snippet_text",
    "error_signatures_text",
    "redirect_location_text",
    "response_header_raw_ordered_text",
    "response_header_canonical_text",
    "response_header_semantic_text",
    "response_security_headers_text",
    "set_cookie_semantic_text",
    "response_header_count",
    "security_header_count",
    "set_cookie_count",
    "response_size",
    "response_headers_anomaly_score",
    "label_is_valuable_target",
    "label_source",
]

HTTP_HEADER_COLUMNS = [
    "scan_id",
    "trace_id",
    "source_module",
    "header_scope",
    "header_name",
    "header_value_masked_text",
    "header_value_canonical_text",
    "header_semantic_text",
    "header_order",
]

HTTP_LABEL_COLUMNS = [
    "scan_id",
    "trace_id",
    "parent_trace_id",
    "baseline_trace_id",
    "source_module",
    "label_target_value",
    "label_candidate_family",
    "label_confirmed_family",
    "label_source",
    "label_confidence",
    "human_reviewed",
    "validation_tool",
    "analyzer_route",
    "analyzer_reason",
]

HTTP_SPLIT_COLUMNS = [
    "scan_id",
    "trace_id",
    "dataset_origin",
    "split_name",
    "is_lab_trace",
    "target_family_expected",
    "target_platform",
    "scan_environment",
]

LEGACY_RECON_REQUEST_COLUMNS = [
    "URL_Path_Text",
    "Query_Params_Text",
    "Method",
    "Cookie_Names_Text",
    "Headers_Text",
    "User_Agent",
    "Priority",
    "Sec_Fetch_Dest",
    "Param_Count",
    "Label_Is_Valuable_Target",
    "Scan_ID",
    "Trace_ID",
    "Source_Module",
    "Route_Template_Text",
    "Query_Shapes_Text",
    "Request_Body_Text",
    "Input_Names_Text",
    "File_Extension_Text",
    "Request_Header_Raw_Ordered_Text",
    "Request_Header_Canonical_Text",
    "Request_Header_Semantic_Text",
    "Request_Origin_Relation_Text",
    "Request_Fetch_Metadata_Text",
    "Request_Auth_Scheme_Text",
    "Label_Source",
]

LEGACY_RECON_RESPONSE_COLUMNS = [
    "Status_Code",
    "Content_Type",
    "Response_Headers_Text",
    "Server_Tech_Text",
    "Body_Title_Text",
    "Response_Size",
    "Label_Is_Valuable_Target",
    "Scan_ID",
    "Trace_ID",
    "Source_Module",
    "Response_Time_ms",
    "Body_Snippet_Text",
    "Error_Signatures_Text",
    "Redirect_Location_Text",
    "Response_Header_Raw_Ordered_Text",
    "Response_Header_Canonical_Text",
    "Response_Header_Semantic_Text",
    "Response_Security_Headers_Text",
    "Set_Cookie_Semantic_Text",
    "Label_Source",
]

LEGACY_VULN_REQUEST_COLUMNS = [
    "URL_Full_Text",
    "Method",
    "Injection_Point",
    "Payload_Injected",
    "Request_Headers_Text",
    "Request_Body_Text",
    "Label_Expected_Vuln_Type",
    "Scan_ID",
    "Trace_ID",
    "Baseline_Trace_ID",
    "Source_Module",
    "Route_Template_Text",
    "Param_Name_Injected",
    "Param_Value_Shape_Text",
    "Request_Header_Raw_Ordered_Text",
    "Request_Header_Canonical_Text",
    "Request_Header_Semantic_Text",
    "Request_Auth_Scheme_Text",
    "Comparison_Context_Text",
    "Probe_Profile_ID",
    "Label_Source",
]

LEGACY_VULN_RESPONSE_COLUMNS = [
    "Status_Code",
    "Response_Time_ms",
    "Response_Headers_Text",
    "Response_Body_Snippet",
    "Error_Signatures_Text",
    "Label_Is_Vulnerable",
    "Label_Vuln_Type",
    "Scan_ID",
    "Trace_ID",
    "Baseline_Trace_ID",
    "Source_Module",
    "Response_Header_Raw_Ordered_Text",
    "Response_Header_Canonical_Text",
    "Response_Header_Semantic_Text",
    "Response_Security_Headers_Text",
    "Set_Cookie_Semantic_Text",
    "Label_Source",
]

PATHS = {
    "http_requests": os.path.join(HTTP_DIR, "http_trace_requests.csv"),
    "http_responses": os.path.join(HTTP_DIR, "http_trace_responses.csv"),
    "http_headers": os.path.join(HTTP_DIR, "http_trace_headers.csv"),
    "http_labels": os.path.join(HTTP_DIR, "http_trace_labels.csv"),
    "http_splits": os.path.join(HTTP_DIR, "http_trace_splits.csv"),
    "recon_request": os.path.join(RECON_DIR, "recon_request.csv"),
    "recon_response": os.path.join(RECON_DIR, "recon_response.csv"),
    "vulnerability_request": os.path.join(VULN_DIR, "vulnerability_request.csv"),
    "vulnerability_response": os.path.join(VULN_DIR, "vulnerability_response.csv"),
}


class NLPTraceWriter:
    def __init__(self):
        self.schemas = {
            PATHS["http_requests"]: HTTP_REQUEST_COLUMNS,
            PATHS["http_responses"]: HTTP_RESPONSE_COLUMNS,
            PATHS["http_headers"]: HTTP_HEADER_COLUMNS,
            PATHS["http_labels"]: HTTP_LABEL_COLUMNS,
            PATHS["http_splits"]: HTTP_SPLIT_COLUMNS,
            PATHS["recon_request"]: LEGACY_RECON_REQUEST_COLUMNS,
            PATHS["recon_response"]: LEGACY_RECON_RESPONSE_COLUMNS,
            PATHS["vulnerability_request"]: LEGACY_VULN_REQUEST_COLUMNS,
            PATHS["vulnerability_response"]: LEGACY_VULN_RESPONSE_COLUMNS,
        }

    def ensure_layout(self):
        for folder in (HTTP_DIR, RECON_DIR, VULN_DIR):
            os.makedirs(folder, exist_ok=True)
        for path, columns in self.schemas.items():
            self._ensure_csv_schema(path, columns)

    def _ensure_csv_schema(self, path, columns):
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8", newline="") as handle:
                csv.DictWriter(handle, fieldnames=columns).writeheader()
            return

        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            existing_header = next(reader, [])
            rows = list(reader)

        if existing_header == columns:
            return

        rewritten_rows = []
        for row in rows:
            mapping = {existing_header[index]: row[index] for index in range(min(len(existing_header), len(row)))}
            rewritten_rows.append({column: mapping.get(column, "") for column in columns})

        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rewritten_rows)

    def _append_row(self, path, columns, row):
        values = {column: row.get(column, "") for column in columns}
        with open(path, "a", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writerow(values)

    def _append_rows(self, path, columns, rows):
        if not rows:
            return
        with open(path, "a", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in columns})

    def write_trace_bundle(self, trace_bundle, db=None):
        self.ensure_layout()
        request_row = trace_bundle.get("request", {})
        response_row = trace_bundle.get("response", {})
        header_rows = trace_bundle.get("headers", [])
        label_row = trace_bundle.get("label", {})

        self._append_row(PATHS["http_requests"], HTTP_REQUEST_COLUMNS, request_row)
        self._append_row(PATHS["http_responses"], HTTP_RESPONSE_COLUMNS, response_row)
        self._append_rows(PATHS["http_headers"], HTTP_HEADER_COLUMNS, header_rows)
        self._append_row(PATHS["http_labels"], HTTP_LABEL_COLUMNS, label_row)

        self._append_row(PATHS["recon_request"], LEGACY_RECON_REQUEST_COLUMNS, self._legacy_recon_request_row(request_row))
        self._append_row(PATHS["recon_response"], LEGACY_RECON_RESPONSE_COLUMNS, self._legacy_recon_response_row(response_row))

        candidate_family = label_row.get("label_candidate_family", "")
        if candidate_family and candidate_family != "low_value_static":
            self._append_row(
                PATHS["vulnerability_request"],
                LEGACY_VULN_REQUEST_COLUMNS,
                self._legacy_vulnerability_request_row(request_row, label_row),
            )
            self._append_row(
                PATHS["vulnerability_response"],
                LEGACY_VULN_RESPONSE_COLUMNS,
                self._legacy_vulnerability_response_row(response_row, label_row),
            )

        if db and str(os.getenv("SMART_HUNTER_NLP_DB_WRITE", "")).strip().lower() in {"1", "true", "yes", "on"}:
            try:
                save_http_trace(db, request_row, response_row)
                save_http_trace_headers(db, header_rows)
                save_http_trace_label(db, label_row)
            except Exception:
                pass

    def _legacy_recon_request_row(self, request_row):
        return {
            "URL_Path_Text": request_row.get("path_tokens_text", ""),
            "Query_Params_Text": request_row.get("query_keys_text", ""),
            "Method": request_row.get("method_text", ""),
            "Cookie_Names_Text": request_row.get("cookie_names_text", ""),
            "Headers_Text": request_row.get("request_header_canonical_text", ""),
            "User_Agent": request_row.get("user_agent_family", ""),
            "Priority": "",
            "Sec_Fetch_Dest": request_row.get("sec_fetch_dest", ""),
            "Param_Count": request_row.get("query_param_count", ""),
            "Label_Is_Valuable_Target": request_row.get("label_is_valuable_target", ""),
            "Scan_ID": request_row.get("scan_id", ""),
            "Trace_ID": request_row.get("trace_id", ""),
            "Source_Module": request_row.get("source_module", ""),
            "Route_Template_Text": request_row.get("route_template_text", ""),
            "Query_Shapes_Text": request_row.get("query_shapes_text", ""),
            "Request_Body_Text": request_row.get("request_body_text", ""),
            "Input_Names_Text": request_row.get("input_names_text", ""),
            "File_Extension_Text": request_row.get("file_extension_text", ""),
            "Request_Header_Raw_Ordered_Text": request_row.get("request_header_raw_ordered_text", ""),
            "Request_Header_Canonical_Text": request_row.get("request_header_canonical_text", ""),
            "Request_Header_Semantic_Text": request_row.get("request_header_semantic_text", ""),
            "Request_Origin_Relation_Text": request_row.get("request_origin_relation_text", ""),
            "Request_Fetch_Metadata_Text": request_row.get("request_fetch_metadata_text", ""),
            "Request_Auth_Scheme_Text": request_row.get("request_auth_scheme_text", ""),
            "Label_Source": request_row.get("label_source", ""),
        }

    def _legacy_recon_response_row(self, response_row):
        return {
            "Status_Code": response_row.get("status_code", ""),
            "Content_Type": response_row.get("content_type_text", ""),
            "Response_Headers_Text": response_row.get("response_header_canonical_text", ""),
            "Server_Tech_Text": response_row.get("server_header", ""),
            "Body_Title_Text": response_row.get("body_title_text", ""),
            "Response_Size": response_row.get("response_size", ""),
            "Label_Is_Valuable_Target": response_row.get("label_is_valuable_target", ""),
            "Scan_ID": response_row.get("scan_id", ""),
            "Trace_ID": response_row.get("trace_id", ""),
            "Source_Module": response_row.get("source_module", ""),
            "Response_Time_ms": response_row.get("response_time_ms", ""),
            "Body_Snippet_Text": response_row.get("body_snippet_text", ""),
            "Error_Signatures_Text": response_row.get("error_signatures_text", ""),
            "Redirect_Location_Text": response_row.get("redirect_location_text", ""),
            "Response_Header_Raw_Ordered_Text": response_row.get("response_header_raw_ordered_text", ""),
            "Response_Header_Canonical_Text": response_row.get("response_header_canonical_text", ""),
            "Response_Header_Semantic_Text": response_row.get("response_header_semantic_text", ""),
            "Response_Security_Headers_Text": response_row.get("response_security_headers_text", ""),
            "Set_Cookie_Semantic_Text": response_row.get("set_cookie_semantic_text", ""),
            "Label_Source": response_row.get("label_source", ""),
        }

    def _legacy_vulnerability_request_row(self, request_row, label_row):
        first_query_key = (request_row.get("query_keys_text") or "").split(" ")[0] if request_row.get("query_keys_text") else ""
        first_query_shape = ""
        if request_row.get("query_shapes_text"):
            first_query_shape = request_row["query_shapes_text"].split(" ")[0]
        return {
            "URL_Full_Text": request_row.get("page_url_text", ""),
            "Method": request_row.get("method_text", ""),
            "Injection_Point": "query_or_form",
            "Payload_Injected": "",
            "Request_Headers_Text": request_row.get("request_header_canonical_text", ""),
            "Request_Body_Text": request_row.get("request_body_text", ""),
            "Label_Expected_Vuln_Type": label_row.get("label_candidate_family", ""),
            "Scan_ID": request_row.get("scan_id", ""),
            "Trace_ID": request_row.get("trace_id", ""),
            "Baseline_Trace_ID": label_row.get("baseline_trace_id", ""),
            "Source_Module": request_row.get("source_module", ""),
            "Route_Template_Text": request_row.get("route_template_text", ""),
            "Param_Name_Injected": first_query_key,
            "Param_Value_Shape_Text": first_query_shape,
            "Request_Header_Raw_Ordered_Text": request_row.get("request_header_raw_ordered_text", ""),
            "Request_Header_Canonical_Text": request_row.get("request_header_canonical_text", ""),
            "Request_Header_Semantic_Text": request_row.get("request_header_semantic_text", ""),
            "Request_Auth_Scheme_Text": request_row.get("request_auth_scheme_text", ""),
            "Comparison_Context_Text": label_row.get("analyzer_reason", ""),
            "Probe_Profile_ID": "",
            "Label_Source": label_row.get("label_source", ""),
        }

    def _legacy_vulnerability_response_row(self, response_row, label_row):
        return {
            "Status_Code": response_row.get("status_code", ""),
            "Response_Time_ms": response_row.get("response_time_ms", ""),
            "Response_Headers_Text": response_row.get("response_header_canonical_text", ""),
            "Response_Body_Snippet": response_row.get("body_snippet_text", ""),
            "Error_Signatures_Text": response_row.get("error_signatures_text", ""),
            "Label_Is_Vulnerable": 1 if label_row.get("label_candidate_family") else 0,
            "Label_Vuln_Type": label_row.get("label_candidate_family", ""),
            "Scan_ID": response_row.get("scan_id", ""),
            "Trace_ID": response_row.get("trace_id", ""),
            "Baseline_Trace_ID": label_row.get("baseline_trace_id", ""),
            "Source_Module": response_row.get("source_module", ""),
            "Response_Header_Raw_Ordered_Text": response_row.get("response_header_raw_ordered_text", ""),
            "Response_Header_Canonical_Text": response_row.get("response_header_canonical_text", ""),
            "Response_Header_Semantic_Text": response_row.get("response_header_semantic_text", ""),
            "Response_Security_Headers_Text": response_row.get("response_security_headers_text", ""),
            "Set_Cookie_Semantic_Text": response_row.get("set_cookie_semantic_text", ""),
            "Label_Source": label_row.get("label_source", ""),
        }
