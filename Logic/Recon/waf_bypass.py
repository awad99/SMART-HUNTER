"""
WAF Bypass Client — uses Botasaurus to bypass WAF/anti-bot protections.

Two-tier bypass strategy:
  Tier 1: AntiDetectRequests — lightweight HTTP with anti-detect headers & TLS mimicry.
  Tier 2: AntiDetectDriver  — full stealth Chrome browser with google_get() for
          Cloudflare JS-challenge bypass.  Slower but highly effective.

Usage:
    client = WafBypassClient(waf_vendors=["Cloudflare"])
    resp   = client.get("https://target.com")
    print(resp.status_code, resp.text[:200])
    cookies = client.get_harvested_cookies()
"""

import os
import time
import threading
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Graceful import — the tool must work even when botasaurus is absent.
# ---------------------------------------------------------------------------
_HAS_BOTASAURUS = False
_HAS_BOTASAURUS_REQUESTS = False
_AntiDetectRequests = None
_AntiDetectDriver = None

try:
    from botasaurus.browser import browser as _browser_decorator, Driver as _Driver
    from botasaurus.request import request as _request_decorator, Request as _Request
    _HAS_BOTASAURUS = True
    _HAS_BOTASAURUS_REQUESTS = True
except ImportError:
    pass

# Fallback: try the lightweight requests-only package
if not _HAS_BOTASAURUS_REQUESTS:
    try:
        from botasaurus_requests import request as _bare_request
        _HAS_BOTASAURUS_REQUESTS = True
    except ImportError:
        _bare_request = None

# ---------------------------------------------------------------------------
# WAF vendors that typically need a real browser to bypass
# ---------------------------------------------------------------------------
_BROWSER_LEVEL_WAFS = frozenset({
    "cloudflare", "datadome", "perimeterx", "distil",
    "kasada", "shape security", "imperva", "incapsula",
})

# ---------------------------------------------------------------------------
# ResponseAdapter — makes Botasaurus results look like httpx.Response
# ---------------------------------------------------------------------------

class ResponseAdapter:
    """Thin wrapper so downstream code that expects httpx.Response keeps working."""

    def __init__(self, *, status_code=200, headers=None, text="", url="",
                 cookies=None, request_obj=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.url = url
        self.cookies = cookies or {}
        # Provide a minimal request attribute for code that reads response.request
        self.request = request_obj or _MinimalRequest(method="GET", url=url, headers={})

    # httpx compat helpers
    @property
    def content(self):
        return (self.text or "").encode("utf-8", errors="replace")

    def json(self):
        import json
        return json.loads(self.text)

    def __bool__(self):
        return True


class _MinimalRequest:
    """Stub for response.request so print_request_response_details doesn't crash."""
    def __init__(self, method, url, headers):
        self.method = method
        self.url = url
        self.headers = headers or {}


# ---------------------------------------------------------------------------
# WafBypassClient
# ---------------------------------------------------------------------------

class WafBypassClient:
    """HTTP client that uses Botasaurus to bypass WAF protections.

    Parameters
    ----------
    waf_vendors : list[str]
        WAF names detected (e.g. ["Cloudflare"]).  Used to decide which
        bypass tier to start with.
    proxy : str | None
        Optional proxy URL (e.g. "http://user:pass@host:port").
    headless : bool
        If True, run Chrome headless (Tier 2).
    cookie : str | None
        Existing cookie string to carry forward.
    timeout : float
        Per-request timeout in seconds.
    """

    def __init__(self, waf_vendors=None, proxy=None, headless=True,
                 cookie=None, timeout=15.0):
        self.waf_vendors = [v.lower() for v in (waf_vendors or [])]
        self.proxy = proxy or os.getenv("SMART_HUNTER_PROXY")
        self.headless = headless
        self.cookie = cookie
        self.timeout = timeout

        # Cookies harvested from a successful browser bypass
        self._harvested_cookies: dict = {}
        self._lock = threading.Lock()

        # Decide starting tier
        self._needs_browser = any(v in _BROWSER_LEVEL_WAFS for v in self.waf_vendors)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, url, **kwargs) -> ResponseAdapter:
        """GET with automatic tier escalation."""
        return self._request("GET", url, **kwargs)

    def post(self, url, data=None, **kwargs) -> ResponseAdapter:
        """POST with automatic tier escalation."""
        return self._request("POST", url, data=data, **kwargs)

    def get_harvested_cookies(self) -> dict:
        """Return cookies captured from browser bypass sessions."""
        with self._lock:
            return dict(self._harvested_cookies)

    @property
    def available(self) -> bool:
        """True if at least one bypass backend is installed."""
        return _HAS_BOTASAURUS or _HAS_BOTASAURUS_REQUESTS

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    def _request(self, method, url, **kwargs) -> ResponseAdapter:
        if not self.available:
            print("    [!] Botasaurus not installed — WAF bypass unavailable")
            return self._fallback_httpx(method, url, **kwargs)

        # If the WAF needs browser-level bypass, try Tier 2 first
        if self._needs_browser and _HAS_BOTASAURUS:
            resp = self._tier2_browser(method, url, **kwargs)
            if resp and resp.status_code < 400:
                return resp
            print("    [!] Browser bypass returned non-success, trying Tier 1...")

        # Tier 1: lightweight anti-detect requests
        if _HAS_BOTASAURUS_REQUESTS:
            resp = self._tier1_request(method, url, **kwargs)
            if resp and resp.status_code < 400:
                return resp

        # Tier 2 fallback (if not already tried and available)
        if not self._needs_browser and _HAS_BOTASAURUS:
            resp = self._tier2_browser(method, url, **kwargs)
            if resp and resp.status_code < 400:
                return resp

        # Last resort: plain httpx
        print("    [!] All bypass tiers failed — falling back to httpx")
        return self._fallback_httpx(method, url, **kwargs)

    # ------------------------------------------------------------------
    # Tier 1 — AntiDetectRequests (lightweight)
    # ------------------------------------------------------------------

    def _tier1_request(self, method, url, **kwargs) -> ResponseAdapter | None:
        """Use botasaurus AntiDetectRequests for stealthy HTTP."""
        print(f"    [*] WAF Bypass Tier 1 (AntiDetectRequests): {method} {url}")
        try:
            if _HAS_BOTASAURUS:
                return self._tier1_via_botasaurus(method, url, **kwargs)
            elif _bare_request is not None:
                return self._tier1_via_bare(method, url, **kwargs)
        except Exception as exc:
            print(f"    [-] Tier 1 error: {exc}")
        return None

    def _tier1_via_botasaurus(self, method, url, **kwargs) -> ResponseAdapter | None:
        """Tier 1 using the full botasaurus package."""
        result_holder = {}

        @_request_decorator(proxy=self.proxy)
        def _do(req: _Request, data):
            nonlocal result_holder
            target_url = data
            extra_headers = {}
            if self.cookie:
                extra_headers["Cookie"] = self.cookie
            # Merge harvested cookies
            if self._harvested_cookies:
                cookie_parts = []
                if self.cookie:
                    cookie_parts.append(self.cookie)
                cookie_parts.extend(f"{k}={v}" for k, v in self._harvested_cookies.items())
                extra_headers["Cookie"] = "; ".join(cookie_parts)

            if method.upper() == "POST":
                resp = req.post(target_url, data=kwargs.get("data"), headers=extra_headers)
            else:
                resp = req.get(target_url, headers=extra_headers)

            result_holder = {
                "status_code": getattr(resp, "status_code", 200),
                "headers": dict(getattr(resp, "headers", {})),
                "text": getattr(resp, "text", str(resp)),
                "url": target_url,
            }

        _do(url)

        if result_holder:
            print(f"    [+] Tier 1 response: {result_holder.get('status_code', '?')}")
            return ResponseAdapter(**result_holder)
        return None

    def _tier1_via_bare(self, method, url, **kwargs) -> ResponseAdapter | None:
        """Tier 1 using the standalone botasaurus-requests package."""
        headers = {}
        if self.cookie:
            headers["Cookie"] = self.cookie

        if method.upper() == "POST":
            resp = _bare_request.post(url, data=kwargs.get("data"), headers=headers)
        else:
            resp = _bare_request.get(url, headers=headers)

        return ResponseAdapter(
            status_code=getattr(resp, "status_code", 200),
            headers=dict(getattr(resp, "headers", {})),
            text=getattr(resp, "text", str(resp)),
            url=url,
        )

    # ------------------------------------------------------------------
    # Tier 2 — AntiDetectDriver (full browser)
    # ------------------------------------------------------------------

    def _tier2_browser(self, method, url, **kwargs) -> ResponseAdapter | None:
        """Use botasaurus Chrome driver with stealth + google_get for CF bypass."""
        if not _HAS_BOTASAURUS:
            return None

        print(f"    [*] WAF Bypass Tier 2 (Browser/google_get): {method} {url}")
        result_holder = {}

        @_browser_decorator(headless=self.headless, block_images=True,
                            proxy=self.proxy)
        def _do(driver: _Driver, data):
            nonlocal result_holder
            target_url = data

            # Use google_get to simulate coming from Google (bypasses CF)
            try:
                driver.google_get(target_url)
            except Exception:
                # Fallback to direct navigation
                driver.get(target_url)

            # Wait for page to stabilize
            time.sleep(2)

            # Extract page content
            page_html = ""
            try:
                page_html = driver.page_html
            except Exception:
                try:
                    page_html = driver.text("html")
                except Exception:
                    pass

            # Harvest cookies from the browser session
            browser_cookies = {}
            try:
                raw_cookies = driver.get_cookies()
                if raw_cookies:
                    for c in raw_cookies:
                        name = c.get("name", "")
                        value = c.get("value", "")
                        if name:
                            browser_cookies[name] = value
            except Exception:
                pass

            # Capture current URL (may have changed after CF challenge)
            current_url = target_url
            try:
                current_url = driver.current_url
            except Exception:
                pass

            result_holder = {
                "status_code": 200,  # browser doesn't expose raw status
                "headers": {},
                "text": page_html,
                "url": current_url,
                "cookies": browser_cookies,
            }

        try:
            _do(url)
        except Exception as exc:
            print(f"    [-] Tier 2 browser error: {exc}")
            return None

        if result_holder:
            # Harvest cookies for downstream reuse
            cookies = result_holder.pop("cookies", {})
            with self._lock:
                self._harvested_cookies.update(cookies)
            if cookies:
                print(f"    [+] Harvested {len(cookies)} cookies from browser session")

            print(f"    [+] Tier 2 response: page loaded ({len(result_holder.get('text', ''))} bytes)")
            return ResponseAdapter(**result_holder)
        return None

    # ------------------------------------------------------------------
    # Fallback — plain httpx
    # ------------------------------------------------------------------

    @staticmethod
    def _fallback_httpx(method, url, **kwargs) -> ResponseAdapter:
        """Last-resort fallback using standard httpx."""
        import httpx
        try:
            with httpx.Client(verify=False, timeout=15.0, follow_redirects=True,
                              http2=True) as client:
                if method.upper() == "POST":
                    resp = client.post(url, data=kwargs.get("data"))
                else:
                    resp = client.get(url)
                return ResponseAdapter(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    text=resp.text,
                    url=str(resp.url),
                )
        except Exception as exc:
            print(f"    [-] httpx fallback error: {exc}")
            return ResponseAdapter(status_code=0, text="", url=url)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def is_bypass_available() -> bool:
    """Quick check: can we bypass WAFs at all?"""
    return _HAS_BOTASAURUS or _HAS_BOTASAURUS_REQUESTS


def create_bypass_client(waf_result: dict, cookie=None, proxy=None) -> WafBypassClient | None:
    """Factory: create a bypass client from a WafDetector result dict.

    Returns None if no WAF was detected or botasaurus is not installed.
    """
    if not waf_result.get("detected"):
        return None
    if not is_bypass_available():
        print("    [!] WAF detected but botasaurus is not installed — cannot bypass")
        print("    [!] Install with: pip install botasaurus")
        return None

    vendors = waf_result.get("vendors", [])
    print(f"    [*] Initializing WAF bypass client for: {', '.join(vendors)}")
    return WafBypassClient(waf_vendors=vendors, cookie=cookie, proxy=proxy)
