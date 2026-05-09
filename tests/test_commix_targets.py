import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "Logic")):
    if path not in sys.path:
        sys.path.insert(0, path)


from vulnerability_scan.rce import RCEScanMixin
from vulnerability_scan.rce.scanners.commix import CommixScanner


class _DummyContext:
    cookie = None

    @staticmethod
    def log(level, message):
        return None


def test_commix_serializes_post_targets_with_valid_form_data():
    scanner = CommixScanner(_DummyContext())
    targets = {
        "get": [],
        "post": [{
            "url": "https://lab.example/feedback/submit",
            "params": ["csrf", "name", "email", "subject", "message"],
            "defaults": {
                "csrf": "abc123",
                "name": "scanner",
                "email": "scan@example.com",
                "subject": "security-test",
                "message": "security test message",
            },
            "page_url": "https://lab.example/feedback",
        }],
    }

    urls = scanner._load_targets("https://lab.example/feedback", "", targets=targets)

    assert urls == [
        "POST|https://lab.example/feedback/submit|"
        "csrf=abc123&name=scanner&email=scan%40example.com&subject=security-test&message=security+test+message|"
        "email,name,subject,message|https://lab.example/feedback"
    ]


def test_commix_preserves_get_query_strings_from_discovery():
    scanner = CommixScanner(_DummyContext())
    targets = {
        "get": [{
            "url": "https://lab.example/search",
            "full_url": "https://lab.example/search?q=printer&sort=asc",
            "params": ["q", "sort"],
            "defaults": {"q": "printer", "sort": "asc"},
        }],
        "post": [],
    }

    urls = scanner._load_targets("https://lab.example/search", "", targets=targets)

    assert urls == ["GET|https://lab.example/search?q=printer&sort=asc||q,sort"]


class _DummyBase:
    def __init__(self):
        self.cookie = None
        self.session = None
        self.scan_id = "test-scan"
        self.current_target_url = "https://lab.example/feedback"
        self.vulnerabilities_found = []
        self.scan_candidates = []
        self.discovery_calls = 0

    def discover_parameters(self, url):
        self.discovery_calls += 1
        return {
            "get": [],
            "post": [{
                "url": "https://lab.example/feedback/submit",
                "params": ["email"],
                "defaults": {"email": "scan@example.com"},
                "page_url": url,
            }],
            "cookie": [],
        }


class _DummyOrchestrator:
    def __init__(self):
        self.called = None

    def check_command_injection_with_commix(self, url, **kwargs):
        self.called = (url, kwargs.get("targets"))
        return []


class _DummyChecker(RCEScanMixin, _DummyBase):
    def __init__(self):
        super().__init__()


def test_commix_rebuilds_targets_when_last_targets_missing():
    checker = _DummyChecker()
    spy = _DummyOrchestrator()
    checker._rce_orchestrator = spy

    checker.check_command_injection_with_commix()

    assert checker.discovery_calls == 1
    assert checker._last_targets == spy.called[1]
    assert spy.called[0] == "https://lab.example/feedback"
