import csv
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HTTP_DATASET_DIR = os.path.join(BASE_DIR, "Data", "Datasets", "Datasets_for_Model_NLP", "http")


class HTTPDatasetReadiness:
    REQUIRED_FILES = {
        "requests": os.path.join(HTTP_DATASET_DIR, "http_trace_requests.csv"),
        "responses": os.path.join(HTTP_DATASET_DIR, "http_trace_responses.csv"),
        "headers": os.path.join(HTTP_DATASET_DIR, "http_trace_headers.csv"),
        "labels": os.path.join(HTTP_DATASET_DIR, "http_trace_labels.csv"),
        "splits": os.path.join(HTTP_DATASET_DIR, "http_trace_splits.csv"),
    }

    def _count_rows(self, path):
        if not os.path.exists(path):
            return 0
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
            return max(0, sum(1 for line in handle if line.strip()) - 1)

    def _headers(self, path):
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            return next(reader, [])

    def summarize(self):
        summary = {}
        for name, path in self.REQUIRED_FILES.items():
            summary[name] = {
                "path": path,
                "exists": os.path.exists(path),
                "rows": self._count_rows(path),
                "headers": self._headers(path),
            }
        requests_headers = set(summary["requests"]["headers"])
        responses_headers = set(summary["responses"]["headers"])
        labels_headers = set(summary["labels"]["headers"])
        summary["join_ready"] = {"scan_id", "trace_id"}.issubset(requests_headers) and {
            "scan_id",
            "trace_id",
        }.issubset(responses_headers) and {"scan_id", "trace_id"}.issubset(labels_headers)
        summary["training_ready"] = (
            summary["requests"]["rows"] >= 2000
            and summary["labels"]["rows"] >= 500
            and summary["join_ready"]
        )
        return summary

    def train_or_explain(self):
        summary = self.summarize()
        if not summary["training_ready"]:
            return {
                "trained": False,
                "summary": summary,
                "reason": "Canonical HTTP datasets are prepared, but there are not enough joined traces or labels yet.",
            }
        return {
            "trained": False,
            "summary": summary,
            "reason": "Training pipeline is intentionally gated until the project provides a reviewed implementation.",
        }
