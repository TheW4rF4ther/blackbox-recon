"""Service-enum extension wrapper: artifacts + optional ssh-audit.

This module wraps the stable service_enum dispatcher instead of replacing it.
It adds durable artifact paths and richer SSH analysis when ssh-audit is present.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .artifacts import write_tool_artifact


def _is_open(row: Dict[str, Any]) -> bool:
    return str(row.get("state") or "").lower() == "open"


def _target_from_rows(rows: Iterable[Dict[str, Any]]) -> str:
    for row in rows:
        if isinstance(row, dict) and row.get("host"):
            return str(row.get("host"))
    return "target"


def _run_cmd(cmd: List[str], timeout_sec: int) -> Tuple[str, str, int, Optional[str]]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=max(5, int(timeout_sec)))
        return proc.stdout or "", proc.stderr or "", proc.returncode, None
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or "", exc.stderr or "", 124, f"timeout after {timeout_sec}s"
    except Exception as exc:
        return "", "", 1, str(exc)[:500]


def _ssh_audit(host: str, port: int, timeout_sec: int, target: str) -> Dict[str, Any]:
    exe = shutil.which("ssh-audit")
    if not exe:
        return {
            "host": host,
            "port": port,
            "service": "ssh",
            "module": "ssh_audit",
            "tool": "ssh-audit",
            "command": None,
            "status": "skipped",
            "findings": [],
            "error": "ssh-audit not found on PATH",
        }
    cmd = [exe, "-p", str(port), host]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    low = (stdout or "").lower()
    findings: List[Dict[str, Any]] = []
    warn_lines = []
    fail_lines = []
    info_lines = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        sl = s.lower()
        if "(fail)" in sl or "fail" in sl[:20]:
            fail_lines.append(s[:240])
        elif "(warn)" in sl or "warn" in sl[:20]:
            warn_lines.append(s[:240])
        elif "(info)" in sl and len(info_lines) < 8:
            info_lines.append(s[:240])
    if fail_lines:
        findings.append({"type": "ssh_audit_fail", "values": fail_lines[:20]})
    if warn_lines:
        findings.append({"type": "ssh_audit_warn", "values": warn_lines[:20]})
    if not findings and stdout:
        findings.append({"type": "ssh_audit_completed", "values": info_lines[:8]})
    status = "ok" if code in (0, 1) and not err else "tool_error"
    row = {
        "host": host,
        "port": port,
        "service": "ssh",
        "module": "ssh_audit",
        "tool": "ssh-audit",
        "command": " ".join(cmd),
        "status": status,
        "findings": findings,
        "stdout_excerpt": stdout[-10000:] if stdout else None,
        "stderr_excerpt": stderr[-4000:] if stderr else None,
        "error": err,
    }
    artifact = write_tool_artifact(target=target, host=host, port=port, service="ssh", module="ssh_audit", command=row["command"], stdout=stdout, stderr=stderr)
    if artifact:
        row["artifact_path"] = artifact
    return row


def _attach_artifacts(results: Dict[str, Any], target: str) -> None:
    for row in results.get("results") or []:
        if not isinstance(row, dict) or row.get("artifact_path"):
            continue
        stdout = row.get("stdout_excerpt")
        stderr = row.get("stderr_excerpt")
        command = row.get("command")
        if not (stdout or stderr or command):
            continue
        path = write_tool_artifact(
            target=target,
            host=str(row.get("host") or "target"),
            port=int(row.get("port") or 0),
            service=str(row.get("service") or "service"),
            module=str(row.get("module") or row.get("tool") or "tool"),
            command=command,
            stdout=stdout,
            stderr=stderr,
        )
        if path:
            row["artifact_path"] = path


def patch_service_enum() -> None:
    """Patch service_enum.run_service_enumeration once."""
    from . import service_enum as base

    if getattr(base, "_blackbox_service_enum_plus_patched", False):
        return
    original = base.run_service_enumeration

    def run_service_enumeration_plus(port_rows: Iterable[Dict[str, Any]], *, timeout_sec: int = 60, max_services: int = 24) -> Dict[str, Any]:
        rows = [r for r in port_rows if isinstance(r, dict)]
        target = _target_from_rows(rows)
        out = original(rows, timeout_sec=timeout_sec, max_services=max_services)
        _attach_artifacts(out, target)
        added = []
        for row in rows:
            if not _is_open(row):
                continue
            port = int(row.get("port") or 0)
            service = str(row.get("service") or "").lower()
            if port == 22 or service == "ssh":
                added.append(_ssh_audit(str(row.get("host") or target), port, min(max(timeout_sec, 45), 120), target))
        out.setdefault("results", []).extend(added)
        out["modules_run"] = len([r for r in out.get("results") or [] if isinstance(r, dict) and r.get("status") != "skipped"])
        out["ssh_audit_enabled"] = bool(shutil.which("ssh-audit"))
        return out

    base.run_service_enumeration = run_service_enumeration_plus
    base._blackbox_service_enum_plus_patched = True
