"""DNS record enrichment helper.

Uses Kali-native `dig` when available and falls back to Python DNS lookups for
basic A/AAAA/PTR coverage. This module is observational and intended for
external attack-surface inventory.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DnsEnumResult:
    target: str
    record_type: str
    tool: str
    command: Optional[str]
    status: str
    records: List[str]
    stdout_excerpt: Optional[str] = None
    stderr_excerpt: Optional[str] = None
    error: Optional[str] = None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _run_cmd(cmd: List[str], timeout_sec: int) -> Tuple[str, str, int, Optional[str]]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=max(5, int(timeout_sec)))
        return proc.stdout or "", proc.stderr or "", proc.returncode, None
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or "", exc.stderr or "", 124, f"timeout after {timeout_sec}s"
    except Exception as exc:
        return "", "", 1, str(exc)[:500]


def _dig(target: str, rtype: str, timeout_sec: int) -> DnsEnumResult:
    exe = shutil.which("dig")
    if not exe:
        return DnsEnumResult(target, rtype, "dig", None, "skipped", [], error="dig not found on PATH")
    query = "-x" if rtype == "PTR" else rtype
    cmd = [exe, "+short", query, target] if rtype == "PTR" else [exe, "+short", target, rtype]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    records = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    status = "ok" if code == 0 and not err else "tool_error"
    return DnsEnumResult(target, rtype, "dig", " ".join(cmd), status, records[:100], stdout[-3000:] if stdout else None, stderr[-1000:] if stderr else None, err)


def _python_dns(target: str, rtype: str) -> DnsEnumResult:
    records: List[str] = []
    status = "ok"
    error = None
    try:
        if rtype == "PTR" and _is_ip(target):
            records = [socket.gethostbyaddr(target)[0]]
        elif rtype in ("A", "AAAA") and not _is_ip(target):
            infos = socket.getaddrinfo(target, None)
            records = sorted({str(i[4][0]) for i in infos})
        else:
            status = "skipped"
    except Exception as exc:
        status = "tool_error"
        error = str(exc)[:400]
    return DnsEnumResult(target, rtype, "python_socket", None, status, records[:100], None, None, error)


def run_dns_enrichment(target: str, *, timeout_sec: int = 20) -> Dict[str, Any]:
    rtypes = ["PTR"] if _is_ip(target) else ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA"]
    results: List[Dict[str, Any]] = []
    for rtype in rtypes:
        row = _dig(target, rtype, timeout_sec)
        if row.status == "skipped":
            row = _python_dns(target, rtype)
        results.append(asdict(row))
    return {"target": target, "results": results, "queries_run": len(results)}
