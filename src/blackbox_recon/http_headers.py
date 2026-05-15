"""HTTP security header reconnaissance.

This module performs non-invasive HTTP GET/HEAD-style inspection of discovered
HTTP(S) services and records missing/observed defensive headers. It is intended
for authorized reconnaissance and reporting, not exploitation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
]


@dataclass
class HttpHeaderResult:
    url: str
    final_url: str
    status_code: Optional[int]
    title: Optional[str]
    observed_security_headers: Dict[str, str]
    missing_security_headers: List[str]
    disclosure_headers: Dict[str, str]
    cookie_flags: List[Dict[str, Any]]
    http_to_https_redirect: Optional[bool]
    error: Optional[str] = None


class HttpHeaderAnalyzer:
    """Lightweight HTTP header analyzer using Python requests."""

    def __init__(self, timeout: int = 10):
        self.timeout = int(timeout)

    def analyze(self, url: str) -> Dict[str, Any]:
        try:
            resp = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            headers = dict(resp.headers)
            lower_map = {k.lower(): k for k in headers.keys()}

            observed: Dict[str, str] = {}
            missing: List[str] = []
            for h in SECURITY_HEADERS:
                key = lower_map.get(h.lower())
                if key:
                    observed[h] = headers.get(key, "")
                else:
                    missing.append(h)

            disclosure: Dict[str, str] = {}
            for h in DISCLOSURE_HEADERS:
                key = lower_map.get(h.lower())
                if key:
                    disclosure[h] = headers.get(key, "")

            cookies = self._cookie_flags(headers)
            title = self._title(resp.text or "")
            redirect = None
            if url.lower().startswith("http://"):
                redirect = resp.url.lower().startswith("https://")

            result = HttpHeaderResult(
                url=url,
                final_url=resp.url,
                status_code=resp.status_code,
                title=title,
                observed_security_headers=observed,
                missing_security_headers=missing,
                disclosure_headers=disclosure,
                cookie_flags=cookies,
                http_to_https_redirect=redirect,
                error=None,
            )
            return asdict(result)
        except Exception as exc:
            result = HttpHeaderResult(
                url=url,
                final_url=url,
                status_code=None,
                title=None,
                observed_security_headers={},
                missing_security_headers=[],
                disclosure_headers={},
                cookie_flags=[],
                http_to_https_redirect=None,
                error=str(exc)[:500],
            )
            return asdict(result)

    @staticmethod
    def _title(body: str) -> Optional[str]:
        low = body.lower()
        start = low.find("<title")
        if start < 0:
            return None
        start = low.find(">", start)
        end = low.find("</title>", start)
        if start < 0 or end < 0 or end <= start:
            return None
        text = body[start + 1 : end].strip()
        return " ".join(text.split())[:160] or None

    @staticmethod
    def _cookie_flags(headers: Dict[str, str]) -> List[Dict[str, Any]]:
        raw = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                raw.append(v)
        out: List[Dict[str, Any]] = []
        for c in raw[:10]:
            parts = [p.strip() for p in c.split(";")]
            name = parts[0].split("=", 1)[0] if parts else "cookie"
            flags = {p.lower(): p for p in parts[1:]}
            out.append(
                {
                    "name": name[:80],
                    "secure": "secure" in flags,
                    "httponly": "httponly" in flags,
                    "samesite": next((p for p in parts[1:] if p.lower().startswith("samesite=")), None),
                }
            )
        return out
