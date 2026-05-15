"""Optional screenshot triage for discovered web services.

Uses gowitness when available. This is observational and intended to speed up
operator triage by capturing visual evidence of discovered HTTP(S) services.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ScreenshotResult:
    url: str
    tool: str
    command: Optional[str]
    status: str
    screenshot_path: Optional[str]
    findings: List[Dict[str, Any]]
    stdout_excerpt: Optional[str] = None
    stderr_excerpt: Optional[str] = None
    error: Optional[str] = None


def _run_cmd(cmd: List[str], timeout_sec: int) -> Tuple[str, str, int, Optional[str]]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(10, int(timeout_sec)),
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode, None
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or "", exc.stderr or "", 124, f"timeout after {timeout_sec}s"
    except Exception as exc:
        return "", "", 1, str(exc)[:500]


def _safe_name(url: str) -> str:
    out = url.replace("://", "__").replace("/", "_").replace(":", "_")
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in out)[:120]


def run_screenshot_triage(
    urls: List[str],
    *,
    output_dir: str,
    timeout_sec: int = 90,
    max_urls: int = 8,
) -> Dict[str, Any]:
    exe = shutil.which("gowitness")
    outdir = Path(output_dir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, Any]] = []
    for url in list(dict.fromkeys(urls))[: max(1, int(max_urls))]:
        if not exe:
            results.append(
                asdict(
                    ScreenshotResult(
                        url=url,
                        tool="gowitness",
                        command=None,
                        status="skipped",
                        screenshot_path=None,
                        findings=[],
                        error="gowitness not found on PATH",
                    )
                )
            )
            continue
        # gowitness versions differ. The single URL mode is stable enough across
        # common builds, and the explicit screenshot path makes report linking easy.
        outfile = outdir / f"{_safe_name(url)}.png"
        cmd = [exe, "scan", "single", "--url", url, "--screenshot-path", str(outfile)]
        stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
        exists = outfile.exists() and outfile.stat().st_size > 0
        findings: List[Dict[str, Any]] = []
        if exists:
            findings.append({"type": "screenshot_captured", "path": str(outfile)})
        status = "ok" if exists or code in (0, 1) and not err else "tool_error"
        results.append(
            asdict(
                ScreenshotResult(
                    url=url,
                    tool="gowitness",
                    command=" ".join(cmd),
                    status=status,
                    screenshot_path=str(outfile) if exists else None,
                    findings=findings,
                    stdout_excerpt=stdout[-4000:] if stdout else None,
                    stderr_excerpt=stderr[-2000:] if stderr else None,
                    error=err,
                )
            )
        )
    return {"results": results, "urls_considered": len(urls), "screenshots_captured": sum(1 for r in results if r.get("screenshot_path"))}
