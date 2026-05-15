"""Web path discovery via Kali-native content discovery tools.

Auto mode prefers stronger modern tooling when present:
feroxbuster -> ffuf -> gobuster -> dirsearch -> dirb.
The returned structure remains stable for the Blackbox Recon dashboard/report.
"""

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


_KALI_DIR_WORDLIST_CANDIDATES: Tuple[str, ...] = (
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
)


def resolve_directory_wordlist(explicit: Optional[str] = None) -> Path:
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


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def find_gobuster() -> Optional[str]:
    return _which("gobuster")


def find_dirb() -> Optional[str]:
    return _which("dirb")


_GOBLINE = re.compile(r"^\s*(/[^\s]*)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*(\d+)\])?.*$")
_DIRB_LINE = re.compile(r"^\s*\+\s+(https?://\S+)\s+\(CODE:(\d+)\|")
_FEROX_LINE = re.compile(r"^\s*(\d{3})\s+\S+\s+\S+\s+\S+\s+(https?://\S+)")
_FFUF_LINE = re.compile(r"^\s*([^\s]+)\s+\[Status:\s*(\d{3}),\s*Size:\s*(\d+),.*\]")
_DIRSEARCH_LINE = re.compile(r"^\s*(\d{3})\s+-\s+\S+\s+-\s+(https?://\S+)")


def _interesting_status(code: int) -> bool:
    return code in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502)


def _path_from_url(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return url


def _parse_gobuster_lines(lines: List[str]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in lines:
        m = _GOBLINE.match(line.strip())
        if not m:
            continue
        path, sc, size = m.group(1), int(m.group(2)), m.group(3)
        hits.append({"path": path, "status_code": sc, "size": int(size) if size else None, "interesting": _interesting_status(sc)})
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
        hits.append({"path": _path_from_url(url), "url": url, "status_code": code, "interesting": _interesting_status(code)})
    return hits


def _parse_ferox_lines(lines: List[str]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in lines:
        m = _FEROX_LINE.match(line.strip())
        if not m:
            continue
        code, url = int(m.group(1)), m.group(2)
        hits.append({"path": _path_from_url(url), "url": url, "status_code": code, "interesting": _interesting_status(code)})
    return hits


def _parse_ffuf_lines(lines: List[str], base_url: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in lines:
        m = _FFUF_LINE.match(line.strip())
        if not m:
            continue
        word, code_s, size_s = m.group(1), m.group(2), m.group(3)
        code = int(code_s)
        path = "/" + word.strip("/")
        hits.append({"path": path, "url": base_url.rstrip("/") + path, "status_code": code, "size": int(size_s), "interesting": _interesting_status(code)})
    return hits


def _parse_dirsearch_lines(lines: List[str]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for line in lines:
        m = _DIRSEARCH_LINE.match(line.strip())
        if not m:
            continue
        code, url = int(m.group(1)), m.group(2)
        hits.append({"path": _path_from_url(url), "url": url, "status_code": code, "interesting": _interesting_status(code)})
    return hits


def _pick_tool(preference: str) -> Tuple[str, Optional[str]]:
    pref = (preference or "auto").strip().lower()
    tools = {
        "feroxbuster": _which("feroxbuster"),
        "ffuf": _which("ffuf"),
        "gobuster": _which("gobuster"),
        "dirsearch": _which("dirsearch"),
        "dirb": _which("dirb"),
    }
    if pref in tools:
        return (pref, tools[pref])
    for name in ("feroxbuster", "ffuf", "gobuster", "dirsearch", "dirb"):
        if tools.get(name):
            return (name, tools[name])
    return ("none", None)


def run_directory_scan(
    base_url: str,
    wordlist_path: str,
    *,
    tool: str = "auto",
    threads: int = 10,
    timeout_sec: int = 900,
) -> Dict[str, Any]:
    """Run content discovery against ``base_url`` using the best available Kali tool."""
    wl = Path(wordlist_path)
    if not wl.is_file():
        return {"base_url": base_url, "status": "skipped", "reason": f"wordlist not found: {wordlist_path}", "tool": None, "command": None, "findings": [], "stdout_tail": "", "stderr_tail": ""}

    name, exe = _pick_tool(tool)
    if not exe:
        return {"base_url": base_url, "status": "skipped", "reason": "No supported directory brute-force tool found on PATH", "tool": None, "command": None, "findings": [], "stdout_tail": "", "stderr_tail": ""}

    url = base_url.rstrip("/") + "/"
    t = str(max(1, min(int(threads), 50)))
    ext = "txt,html,php,asp,aspx,jsp"
    dot_ext = ",".join(["." + x for x in ext.split(",")])

    if name == "feroxbuster":
        cmd = [exe, "-u", url, "-w", str(wl), "-t", t, "-x", ext, "-k", "-q", "-e", "-r", "-n"]
    elif name == "ffuf":
        cmd = [exe, "-u", url + "FUZZ", "-w", str(wl), "-t", t, "-e", dot_ext, "-v", "-r", "-noninteractive"]
    elif name == "gobuster":
        cmd = [exe, "dir", "-u", url, "-w", str(wl), "-t", t, "-q", "-k", "--timeout", "10s", "-x", ext]
    elif name == "dirsearch":
        cmd = [exe, "-u", url, "-t", t, "-e", ext, "-f", "-q", "-F", "-w", str(wl), "--format=plain"]
    else:
        cmd = [exe, url, str(wl), "-S", "-r", "-X", "," + dot_ext]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(30, timeout_sec), errors="replace")
    except subprocess.TimeoutExpired:
        return {"base_url": url, "status": "timeout", "tool": name, "command": " ".join(cmd), "findings": [], "stdout_tail": "", "stderr_tail": f"Exceeded {timeout_sec}s"}
    except (FileNotFoundError, OSError) as exc:
        return {"base_url": url, "status": "error", "reason": str(exc), "tool": name, "command": " ".join(cmd), "findings": [], "stdout_tail": "", "stderr_tail": ""}

    out_lines = (proc.stdout or "").splitlines()
    if name == "feroxbuster":
        findings = _parse_ferox_lines(out_lines)
    elif name == "ffuf":
        findings = _parse_ffuf_lines(out_lines, url)
    elif name == "gobuster":
        findings = _parse_gobuster_lines(out_lines)
    elif name == "dirsearch":
        findings = _parse_dirsearch_lines(out_lines)
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
        "stderr_tail": (proc.stderr or "")[-4000:],
    }
