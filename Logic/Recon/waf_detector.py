"""
WAF Detector — two-tier detection using WAFW00F (active) with passive fallback.

Tier 1: WAFW00F active engine (100+ WAF plugins, sends probe requests).
Tier 2: Lightweight passive header/body/cookie signature matching (8 vendors).

Usage:
    detector = WafDetector()
    result = detector.detect_waf("https://target.com", response)
    # result => {"detected": True, "vendors": ["Cloudflare"], "method": "wafw00f", "confidence": "high"}
"""

import re
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

# ---------------------------------------------------------------------------
# Try importing WAFW00F — graceful degradation if missing
# ---------------------------------------------------------------------------
try:
    from wafw00f.main import WAFW00F as _WAFW00F_Engine
    _HAS_WAFW00F = True
except ImportError:
    _WAFW00F_Engine = None
    _HAS_WAFW00F = False

# ---------------------------------------------------------------------------
# Passive WAF signatures (fallback only)
# ---------------------------------------------------------------------------
_PASSIVE_WAF_SIGS = {
    "Cloudflare":       ["cf-ray", "__cfduid", "cloudflare"],
    "AWS WAF":          ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":           ["akamai-grn", "x-akamai-transformed"],
    "Sucuri":           ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":          ["x-iinfo", "incap_ses", "visid_incap"],
    "F5 BIG-IP":        ["x-wa-info", "bigipserver"],
    "ModSecurity":      ["mod_security", "modsecurity"],
    "Barracuda":        ["barra_counter_session"],
}

# Default timeout (seconds) for WAFW00F active scan
_WAFW00F_TIMEOUT = 10


def _empty_result():
    """Return a blank WAF result dict."""
    return {"detected": False, "vendors": [], "method": "none", "confidence": "none"}


class WafDetector:
    """Two-tier WAF detection: WAFW00F active + passive signature fallback."""

    def __init__(self, active_timeout: int = _WAFW00F_TIMEOUT):
        self.active_timeout = active_timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect_waf(self, url: str, response=None) -> dict:
        """Run WAF detection and return a structured result dict.

        Parameters
        ----------
        url : str
            Target URL (required for WAFW00F active probing).
        response : httpx.Response | requests.Response, optional
            An already-fetched HTTP response for passive fallback.

        Returns
        -------
        dict  {"detected": bool, "vendors": list[str],
               "method": str, "confidence": str}
        """
        result = _empty_result()

        # --- Tier 1: WAFW00F active scan ---
        if _HAS_WAFW00F and url:
            try:
                active = self._active_detect(url)
                if active["detected"]:
                    self._print_result(active)
                    return active
            except Exception as exc:
                print(f"    [!] WAFW00F error: {exc} — falling back to passive")

        # --- Tier 2: Passive signature match ---
        if response is not None:
            passive = self._passive_detect(response)
            if passive["detected"]:
                self._print_result(passive)
                return passive

        # --- Nothing found ---
        self._print_result(result)
        return result

    def get_waf_matches(self, url: str, response=None) -> list[str]:
        """Backward-compatible helper — returns a plain vendor list.

        Keeps existing callers (e.g. FeatureExtractor) working without
        changing their interface beyond adding the url arg.
        """
        return self.detect_waf(url, response)["vendors"]

    # ------------------------------------------------------------------
    # Tier 1 — WAFW00F active detection
    # ------------------------------------------------------------------

    def _active_detect(self, url: str) -> dict:
        """Run WAFW00F engine with a timeout guard."""

        def _run():
            engine = _WAFW00F_Engine(target=url)
            # identwaf() runs all WAF plugins
            waf_identified = engine.identwaf()
            if waf_identified:
                name = engine.knowledge.get("wafname", "Unknown WAF")
                return {"detected": True, "vendors": [name],
                        "method": "wafw00f", "confidence": "high"}
            # genericdetect() uses behavioural analysis
            is_generic = engine.genericdetect()
            if is_generic:
                return {"detected": True, "vendors": ["Generic WAF"],
                        "method": "wafw00f_generic", "confidence": "medium"}
            return _empty_result()

        # Run in a separate thread so we can enforce a timeout
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run)
            try:
                return future.result(timeout=self.active_timeout)
            except FuturesTimeout:
                print(f"    [!] WAFW00F timed out after {self.active_timeout}s")
                future.cancel()
                return _empty_result()

    # ------------------------------------------------------------------
    # Tier 2 — Passive signature matching (original logic, kept as fallback)
    # ------------------------------------------------------------------

    @staticmethod
    def _passive_detect(response) -> dict:
        """Check headers, cookies, and body against static WAF signatures."""
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookie_str = headers_lower.get("set-cookie", "")
        body_lower = (response.text or "")[:4000].lower()

        vendors = [
            vendor
            for vendor, sigs in _PASSIVE_WAF_SIGS.items()
            if any(
                sig in headers_lower
                or sig in cookie_str
                or sig in body_lower
                for sig in sigs
            )
        ]

        if vendors:
            return {"detected": True, "vendors": vendors,
                    "method": "passive_fallback", "confidence": "medium"}
        return _empty_result()

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    @staticmethod
    def _print_result(result: dict):
        if result["detected"]:
            vendors = ", ".join(result["vendors"])
            method = result["method"]
            conf = result["confidence"]
            print(f"    [!] WAF/CDN detected: {vendors}  (method={method}, confidence={conf})")
        else:
            print("    [*] No WAF detected")

    # ------------------------------------------------------------------
    # Bypass intelligence
    # ------------------------------------------------------------------

    @staticmethod
    def needs_browser_bypass(result: dict) -> bool:
        """Check if the detected WAF requires full browser-level bypass.

        Some WAFs (Cloudflare, DataDome, PerimeterX) use JS challenges that
        can only be solved by a real browser engine.  Others (ModSecurity,
        basic AWS WAF rules) can be bypassed with anti-detect HTTP requests.
        """
        BROWSER_WAFS = {"cloudflare", "datadome", "perimeterx", "distil",
                        "kasada", "shape security", "imperva", "incapsula"}
        return any(
            any(bw in v.lower() for bw in BROWSER_WAFS)
            for v in result.get("vendors", [])
        )
