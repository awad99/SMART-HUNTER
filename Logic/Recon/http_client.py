import os
import random
import httpx

# Pool of realistic browser user-agents — rotated per request to avoid scanner fingerprinting
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

def _random_ua() -> str:
    return random.choice(_UA_POOL)

def _default_ua() -> dict:
    return {"User-Agent": _random_ua()}

UA = {'User-Agent': _UA_POOL[0]}
HTTP_TIMEOUT = float(os.getenv("SMART_HUNTER_RECON_TIMEOUT", "10"))
_PROXY_CACHE = {"checked": False, "value": None}

def env_bool(name, default=False):
    raw = str(os.getenv(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "enable", "enabled"}

class ReconHttpClient:
    """Handles HTTP connections and proxy configuration for reconnaissance."""

    @staticmethod
    def find_proxy():
        manual_proxy = os.getenv("SMART_HUNTER_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        if manual_proxy:
            return manual_proxy

        if not env_bool("SMART_HUNTER_AUTO_PROXY", False):
            return None

        if _PROXY_CACHE["checked"]:
            return _PROXY_CACHE["value"]

        for port in (8080, 8081):
            proxy_url = f"http://127.0.0.1:{port}"
            try:
                with httpx.Client(proxy=proxy_url, timeout=2.0, verify=False, trust_env=False) as client:
                    client.get("http://example.com", timeout=2.0)
                _PROXY_CACHE["checked"] = True
                _PROXY_CACHE["value"] = proxy_url
                print(f"[+] Proxy detected on port {port}")
                return proxy_url
            except Exception:
                continue

        _PROXY_CACHE["checked"] = True
        _PROXY_CACHE["value"] = None
        return None

    @staticmethod
    def build_client(cookie=None, cookies_dict=None, follow_redirects=False):
        proxy = ReconHttpClient.find_proxy()
        request_headers = {**_default_ua(), **({'Cookie': cookie} if cookie else {})}
        
        params = {
            "timeout": httpx.Timeout(HTTP_TIMEOUT),
            "follow_redirects": follow_redirects,
            "verify": False,
            "http2": True,
            "headers": request_headers,
            "cookies": cookies_dict,
            "limits": httpx.Limits(max_connections=20, max_keepalive_connections=10),
            "trust_env": not bool(proxy),
        }
        if proxy:
            params["proxy"] = proxy
        return httpx.Client(**params)

    @staticmethod
    def build_bypass_client(waf_result, cookie=None):
        """Create a WafBypassClient when a WAF has been detected.

        Parameters
        ----------
        waf_result : dict
            Output from ``WafDetector.detect_waf()``.
        cookie : str | None
            Session cookie string to carry into bypass requests.

        Returns
        -------
        WafBypassClient | None
            A bypass client ready to use, or None if bypass is unavailable
            or no WAF was detected.
        """
        from Logic.Recon.waf_bypass import create_bypass_client
        proxy = ReconHttpClient.find_proxy()
        return create_bypass_client(waf_result, cookie=cookie, proxy=proxy)
