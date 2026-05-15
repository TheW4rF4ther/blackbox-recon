"""Kali-native web fingerprinting helpers.

Runs optional, observational web fingerprinting tools against already-discovered
HTTP(S) URLs. These helpers do not exploit applications; they collect stack and
WAF/CDN indicators for evidence-backed reporting.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class WebFingerprintResult:
    url: str
    module: str
    tool: str
    command: Optional[str]
    status: str
    findings: List[Dict[str, Any]]
    stdout_excerpt: Optional[str] = None
    stderr_excerpt: Optional[str] = None
    error: Optional[str] = None


def _run_cmd(cmd: List[str], timeout_sec: int) -> Tuple[str, str, int, Optional[str]]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=max(5, int(timeout_sec)))
        return proc.stdout or "", proc.stderr or "", proc.returncode, None
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or "", exc.stderr or "", 124, f"timeout after {timeout_sec}s"
    except Exception as exc:
        return "", "", 1, str(exc)[:500]


def _clean_lines(text: str) -> List[str]:
    lines: List[str] = []
    for line in (text or "").splitlines():
        s = " ".join(line.strip().split())
        if not s:
            continue
        # Drop common WAFW00F ASCII art/banner noise.
        if len(re.sub(r"[A-Za-z0-9]", "", s)) > max(8, len(s) * 0.55):
            continue
        if "W00f!" in s or "wafw00f" in s.lower() and "checking" not in s.lower():
            continue
        lines.append(s)
    return lines


def run_whatweb(url: str, *, timeout_sec: int = 60) -> Dict[str, Any]:
    exe = shutil.which("whatweb")
    if not exe:
        return asdict(WebFingerprintResult(url, "whatweb", "whatweb", None, "skipped", [], error="whatweb not found on PATH"))
    cmd = [exe, "--color=never", "--no-errors", "-a", "3", url]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    findings: List[Dict[str, Any]] = []
    clean = "\n".join(_clean_lines(stdout))
    if clean.strip():
        findings.append({"type": "whatweb_fingerprint", "summary": clean.strip()[:1600]})
    status = "ok" if code in (0, 1) and not err else "tool_error"
    return asdict(WebFingerprintResult(url, "whatweb", "whatweb", " ".join(cmd), status, findings, clean[-4000:] if clean else None, stderr[-2000:] if stderr else None, err))


def run_wafw00f(url: str, *, timeout_sec: int = 60) -> Dict[str, Any]:
    exe = shutil.which("wafw00f")
    if not exe:
        return asdict(WebFingerprintResult(url, "wafw00f", "wafw00f", None, "skipped", [], error="wafw00f not found on PATH"))
    cmd = [exe, "-a", url]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    text = (stdout or "") + "\n" + (stderr or "")
    clean_lines = _clean_lines(text)
    clean = "\n".join(clean_lines)
    low = clean.lower()
    findings: List[Dict[str, Any]] = []

    positive = False
    positive_patterns = [
        "is behind",
        "protected by",
        "detected protection",
        "the site is behind",
        "identified as",
        "generic detection results",
    ]
    negative_patterns = [
        "no waf detected",
        "does not seem to be behind a waf",
        "seems to be behind a waf: false",
        "no firewall detected",
    ]
    if any(p in low for p in positive_patterns) and not any(p in low for p in negative_patterns):
        positive = True

    if positive:
        findings.append({"type": "waf_signal", "summary": clean[:1600]})
    elif clean:
        findings.append({"type": "waf_scan_completed", "summary": clean[:1000]})
    status = "ok" if code in (0, 1) and not err else "tool_error"
    return asdict(WebFingerprintResult(url, "wafw00f", "wafw00f", " ".join(cmd), status, findings, clean[-4000:] if clean else None, stderr[-2000:] if stderr else None, err))


def run_web_fingerprinting(urls: List[str], *, timeout_sec: int = 60, max_urls: int = 8) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    for url in list(dict.fromkeys(urls))[: max(1, int(max_urls))]:
        results.append(run_whatweb(url, timeout_sec=timeout_sec))
        results.append(run_wafw00f(url, timeout_sec=timeout_sec))
    return {"results": results, "urls_considered": len(urls), "modules_run": len(results)}
