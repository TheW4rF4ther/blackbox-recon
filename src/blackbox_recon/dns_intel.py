"""DNS intelligence helpers (nslookup for PTR / forward records on IP targets)."""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional


def _find_nslookup() -> Optional[str]:
    return shutil.which("nslookup")


def _parse_nslookup_text(text: str) -> Dict[str, Any]:
    """Extract names and addresses from typical nslookup output (Windows / BIND style)."""
    names: List[str] = []
    addresses: List[str] = []
    name_re = re.compile(r"(?i)^\s*name:\s*(.+)\s*$")
    addr_re = re.compile(r"(?i)^\s*address(?:es)?:\s*([0-9a-f:.]+)\s*$")
    for line in text.splitlines():
        m = name_re.match(line)
        if m:
            n = m.group(1).strip().rstrip(".")
            if n and n not in names:
                names.append(n)
            continue
        m = addr_re.match(line)
        if m:
            a = m.group(1).strip()
            if a and a not in addresses:
                addresses.append(a)
    return {"ptr_or_canonical_names": names, "addresses_in_output": addresses}


def run_nslookup(target: str, timeout_sec: int = 120) -> Dict[str, Any]:
    """
    Run system ``nslookup`` against ``target`` (IPv4, IPv6, or hostname).

    Returns a structured dict suitable for JSON reports (stdout/stderr + parsed hints).
    """
    exe = _find_nslookup()
    if not exe:
        return {
            "tool": "nslookup",
            "target": target,
            "status": "skipped",
            "reason": "nslookup executable not found on PATH",
            "command": None,
            "stdout": "",
            "stderr": "",
            "parsed": {},
        }

    cmd = [exe, target]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(5, timeout_sec),
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {
            "tool": "nslookup",
            "target": target,
            "status": "timeout",
            "reason": f"exceeded {timeout_sec}s",
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "",
            "parsed": {},
        }
    except (FileNotFoundError, OSError) as exc:
        return {
            "tool": "nslookup",
            "target": target,
            "status": "error",
            "reason": str(exc),
            "command": " ".join(cmd),
            "stdout": "",
            "stderr": "",
            "parsed": {},
        }

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    parsed = _parse_nslookup_text(out + "\n" + err)
    status = "ok" if proc.returncode == 0 else "completed_nonzero"
    return {
        "tool": "nslookup",
        "target": target,
        "status": status,
        "exit_code": proc.returncode,
        "command": " ".join(cmd),
        "stdout": out[:20000],
        "stderr": err[:8000],
        "parsed": parsed,
    }
