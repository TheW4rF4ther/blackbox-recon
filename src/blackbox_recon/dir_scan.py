"""Web path discovery via gobuster or dirb when available."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Tuple


def default_bundled_wordlist() -> Path:
    """Packaged short wordlist for quick content discovery when none is configured."""
    return Path(__file__).resolve().parent / "data" / "web_discovery_small.txt"


# Typical locations on Kali / Parrot when optional wordlists are installed.
_KALI_DIR_WORDLIST_CANDIDATES: Tuple[str, ...] = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
)


def resolve_directory_wordlist(explicit: Optional[str] = None) -> Path:
    """
    Pick a directory wordlist: explicit config, then ``BLACKBOX_RECON_DIR_WORDLIST``,
    then first existing Kali-style path, else the bundled small list.
    """
    if explicit:
        p = Path(explicit).expanduser()
        if p.is_file():
            return p
    env = os.environ.get("BLACKBOX_RECON_DIR_WORDLIST", "").strip()
    if env:
        p = Path(env).expanduser()
        if p.is_file():
            return p
    for candidate in _KALI_DIR_WORDLIST_CANDIDATES:
        p = Path(candidate)
        if p.is_file():
            return p
    return default_bundled_wordlist()


def find_gobuster() -> Optional[str]:
    return shutil.which("gobuster")


def find_dirb() -> Optional[str]:
    return shutil.which("dirb")


_GOBLINE = re.compile(r"^\s*(/[^\s]*)\s+\(Status:\s*(\d{3})\)\s*$")
_DIRB_LINE = re.compile(r"^\s*\+\s+(https?://\S+)\s+\(CODE:(\d+)\|")


def _interesting_status(code: int) -> bool:
    return code in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502)


def _parse_gobuster_lines(lines: List[str]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in lines:
        m = _GOBLINE.match(line.strip())
        if not m:
            continue
        path, sc = m.group(1), int(m.group(2))
        hits.append(
            {
                "path": path,
                "status_code": sc,
                "interesting": _interesting_status(sc),
            }
        )
    return hits


def _parse_dirb_lines(lines: List[str]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in lines:
        m = _DIRB_LINE.match(line.strip())
        if not m:
            continue
        url, code_s = m.group(1), m.group(2)
        try:
            code = int(code_s)
        except ValueError:
            continue
        try:
            path = urlparse(url).path or "/"
        except Exception:
            path = url
        hits.append(
            {
                "path": path,
                "url": url,
                "status_code": code,
                "interesting": _interesting_status(code),
            }
        )
    return hits


def _pick_tool(preference: str) -> Tuple[str, Optional[str]]:
    pref = (preference or "auto").strip().lower()
    gb, db = find_gobuster(), find_dirb()
    if pref == "gobuster":
        return ("gobuster", gb)
    if pref == "dirb":
        return ("dirb", db)
    if gb:
        return ("gobuster", gb)
    if db:
        return ("dirb", db)
    return ("none", None)


def run_directory_scan(
    base_url: str,
    wordlist_path: str,
    *,
    tool: str = "auto",
    threads: int = 10,
    timeout_sec: int = 900,
) -> Dict[str, Any]:
    """
    Run gobuster (preferred) or dirb against ``base_url``.

    ``base_url`` should include scheme and trailing slash is optional.
    """
    wl = Path(wordlist_path)
    if not wl.is_file():
        return {
            "base_url": base_url,
            "status": "skipped",
            "reason": f"wordlist not found: {wordlist_path}",
            "tool": None,
            "command": None,
            "findings": [],
            "stdout_tail": "",
            "stderr_tail": "",
        }

    name, exe = _pick_tool(tool)
    if not exe:
        return {
            "base_url": base_url,
            "status": "skipped",
            "reason": "Neither gobuster nor dirb found on PATH; install one or set directory_tool to none",
            "tool": None,
            "command": None,
            "findings": [],
            "stdout_tail": "",
            "stderr_tail": "",
        }

    url = base_url.rstrip("/") + "/"

    if name == "gobuster":
        cmd = [
            exe,
            "dir",
            "-u",
            url,
            "-w",
            str(wl),
            "-t",
            str(max(1, min(threads, 50))),
            "-q",
            "-k",
            "--timeout",
            "10s",
        ]
    else:
        cmd = [exe, url, str(wl), "-S", "-r"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30, timeout_sec),
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {
            "base_url": url,
            "status": "timeout",
            "tool": name,
            "command": " ".join(cmd),
            "findings": [],
            "stdout_tail": "",
            "stderr_tail": f"Exceeded {timeout_sec}s",
        }
    except (FileNotFoundError, OSError) as exc:
        return {
            "base_url": url,
            "status": "error",
            "reason": str(exc),
            "tool": name,
            "command": " ".join(cmd),
            "findings": [],
            "stdout_tail": "",
            "stderr_tail": "",
        }

    out_lines = (proc.stdout or "").splitlines()
    err = (proc.stderr or "").strip()
    if name == "gobuster":
        findings = _parse_gobuster_lines(out_lines)
    else:
        findings = _parse_dirb_lines(out_lines)

    interesting = [f for f in findings if f.get("interesting")]
    return {
        "base_url": url,
        "status": "ok" if proc.returncode == 0 else "completed_nonzero",
        "exit_code": proc.returncode,
        "tool": name,
        "command": " ".join(cmd),
        "wordlist": str(wl),
        "findings_total": len(findings),
        "findings_interesting": interesting[:200],
        "findings_sample": findings[:80],
        "stdout_tail": (proc.stdout or "")[-12000:],
        "stderr_tail": err[-4000:],
    }
