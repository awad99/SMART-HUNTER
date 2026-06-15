"""
ScopeValidator — enforce bug bounty program scope rules before scanning.

Usage:
    validator = ScopeValidator(
        in_scope=["*.example.com", "api.example.com"],
        out_of_scope=["admin.example.com", "cdn.example.com"],
    )
    if not validator.is_in_scope("https://admin.example.com/login"):
        print("OUT OF SCOPE — skipping")

Patterns:
    *.example.com   — matches any subdomain of example.com
    example.com     — exact domain match
    Glob wildcards (fnmatch) are supported for everything else.
"""

import fnmatch
from urllib.parse import urlparse


class ScopeValidator:
    def __init__(self, in_scope=None, out_of_scope=None):
        self.in_scope = [s.strip() for s in (in_scope or []) if s.strip()]
        self.out_of_scope = [s.strip() for s in (out_of_scope or []) if s.strip()]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, url: str) -> bool:
        """Return True if the URL falls within the defined scope.

        Out-of-scope rules take precedence over in-scope rules.
        If no in-scope list is defined every host is considered in scope
        (unless explicitly out-of-scope).
        """
        host = self._host(url)
        if not host:
            return False

        for pattern in self.out_of_scope:
            if self._match(host, pattern):
                return False

        if not self.in_scope:
            return True

        return any(self._match(host, p) for p in self.in_scope)

    def filter_urls(self, urls) -> list:
        return [u for u in urls if self.is_in_scope(u)]

    def check_and_warn(self, url: str) -> bool:
        """Return is_in_scope() and print a warning when out of scope."""
        ok = self.is_in_scope(url)
        if not ok:
            print(f"  [SCOPE] SKIPPING out-of-scope target: {url}")
        return ok

    def summary(self) -> str:
        lines = []
        if self.in_scope:
            lines.append(f"  In-scope  : {', '.join(self.in_scope)}")
        else:
            lines.append("  In-scope  : (all hosts)")
        if self.out_of_scope:
            lines.append(f"  Excluded  : {', '.join(self.out_of_scope)}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _host(url: str) -> str:
        try:
            return urlparse(url).netloc.split(":")[0].lower()
        except Exception:
            return ""

    @staticmethod
    def _match(host: str, pattern: str) -> bool:
        pattern = pattern.lower().strip()
        if pattern.startswith("*."):
            # Wildcard subdomain: *.example.com matches sub.example.com AND example.com
            domain = pattern[2:]
            return host == domain or host.endswith("." + domain)
        return fnmatch.fnmatch(host, pattern)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_text(cls, text: str) -> "ScopeValidator":
        """Parse a plain-text scope definition.

        Format (one entry per line):
            +*.example.com          -> in-scope
            -admin.example.com      -> out-of-scope
            *.example.com           -> in-scope (no prefix defaults to +)
        """
        in_scope, out_of_scope = [], []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                out_of_scope.append(line[1:].strip())
            elif line.startswith("+"):
                in_scope.append(line[1:].strip())
            else:
                in_scope.append(line)
        return cls(in_scope=in_scope, out_of_scope=out_of_scope)

    @classmethod
    def prompt_interactive(cls) -> "ScopeValidator":
        """Ask the user to enter scope interactively (called from CLI)."""
        print("\n[SCOPE] Define bug bounty scope (leave blank to skip):")
        print("  Format: one pattern per line, prefix - to exclude (e.g. -admin.example.com)")
        print("  Example in-scope: *.example.com")
        print("  Press Enter twice when done.\n")
        lines = []
        while True:
            try:
                line = input("  scope> ").strip()
            except EOFError:
                break
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)
        return cls.from_text("\n".join(lines))
