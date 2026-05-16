"""TLS extension wrapper: artifacts + optional testssl.sh.

Keeps sslscan/python_ssl behavior intact, then augments with testssl.sh when
present. Raw TLS output is saved to per-service artifacts.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .artifacts import write_tool_artifact


def _run_cmd(cmd: List[str], timeout_sec: int) -> Tuple[str, str, int, Optional[str]]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=max(10, int(timeout_sec)))
        return proc.stdout or "", proc.stderr or "", proc.returncode, None
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or "", exc.stderr or "", 124, f"timeout after {timeout_sec}s"
    except Exception as exc:
        return "", "", 1, str(exc)[:500]


def _weak_testssl_signals(stdout: str) -> List[str]:
    low = (stdout or "").lower()
    signals: List[str] = []
    checks = {
        "heartbleed": "Heartbleed signal in testssl output",
        "robot": "ROBOT signal in testssl output",
        "sweet32": "SWEET32/3DES signal in testssl output",
        "poodle": "POODLE signal in testssl output",
        "rc4": "RC4 signal in testssl output",
        "expired": "Certificate expiration signal in testssl output",
        "self-signed": "Self-signed certificate signal in testssl output",
        "not ok": "testssl reported not-ok item",
    }
    for token, msg in checks.items():
        if token in low:
            signals.append(msg)
    return sorted(set(signals))


def _testssl(host: str, port: int, timeout_sec: int, target: str) -> Optional[Dict[str, Any]]:
    exe = shutil.which("testssl.sh") or shutil.which("testssl")
    if not exe:
        return None
    cmd = [exe, "--fast", "--warnings", "off", f"{host}:{port}"]
    stdout, stderr, code, err = _run_cmd(cmd, max(timeout_sec, 120))
    signals = _weak_testssl_signals(stdout)
    findings = []
    if signals:
        findings.append({"type": "testssl_weak_signal", "values": signals[:20]})
    elif stdout:
        findings.append({"type": "testssl_scan_completed"})
    row = {
        "host": host,
        "port": port,
        "tool": "testssl.sh",
        "command": " ".join(cmd),
        "status": "ok" if code in (0, 1) and not err else "tool_error",
        "certificate": {},
        "supported_protocols": [],
        "weak_signals": signals,
        "testssl_findings": findings,
        "stdout_excerpt": stdout[-10000:] if stdout else None,
        "stderr_excerpt": stderr[-4000:] if stderr else None,
        "error": err,
    }
    artifact = write_tool_artifact(target=target, host=host, port=port, service="tls", module="testssl", command=row["command"], stdout=stdout, stderr=stderr)
    if artifact:
        row["artifact_path"] = artifact
    return row


def patch_tls_scan() -> None:
    """Patch tls_scan.scan_tls_url once."""
    from . import tls_scan as base

    if getattr(base, "_blackbox_tls_plus_patched", False):
        return
    original = base.scan_tls_url

    def scan_tls_url_plus(url: str, *, timeout_sec: int = 60) -> Optional[Dict[str, Any]]:
        primary = original(url, timeout_sec=timeout_sec)
        if not primary:
            return None
        target = str(primary.get("host") or "target")
        artifact = write_tool_artifact(
            target=target,
            host=str(primary.get("host") or target),
            port=int(primary.get("port") or 443),
            service="tls",
            module=str(primary.get("tool") or "tls_scan"),
            command=primary.get("command"),
            stdout=primary.get("stdout_excerpt"),
            stderr=primary.get("stderr_excerpt"),
        )
        if artifact:
            primary["artifact_path"] = artifact
        extra = _testssl(str(primary.get("host") or target), int(primary.get("port") or 443), timeout_sec, target)
        if extra:
            primary.setdefault("additional_tls_tools", []).append(extra)
            weak = set(primary.get("weak_signals") or [])
            weak.update(extra.get("weak_signals") or [])
            primary["weak_signals"] = sorted(weak)
        primary["testssl_enabled"] = bool(shutil.which("testssl.sh") or shutil.which("testssl"))
        return primary

    base.scan_tls_url = scan_tls_url_plus
    base._blackbox_tls_plus_patched = True
