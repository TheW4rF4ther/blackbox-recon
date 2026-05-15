"""TLS reconnaissance helpers.

Uses Kali-native `sslscan` when present and falls back to Python's ssl module
for certificate metadata. This module is intentionally observational.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TlsScanResult:
    host: str
    port: int
    tool: str
    command: Optional[str]
    status: str
    certificate: Dict[str, Any]
    supported_protocols: List[str]
    weak_signals: List[str]
    stdout_excerpt: Optional[str] = None
    stderr_excerpt: Optional[str] = None
    error: Optional[str] = None


def _parse_host_port_from_url(url: str) -> Optional[Tuple[str, int]]:
    if not url.lower().startswith("https://"):
        return None
    rest = url.split("://", 1)[1].split("/", 1)[0]
    if ":" in rest:
        h, p = rest.rsplit(":", 1)
        try:
            return h, int(p)
        except ValueError:
            return h, 443
    return rest, 443


def _cert_python(host: str, port: int, timeout: int) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    cert: Dict[str, Any] = {}
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert() or {}
    return {
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_name": cert.get("subjectAltName"),
    }


def _sslscan_protocols(text: str) -> List[str]:
    protocols: List[str] = []
    for line in text.splitlines():
        l = line.strip()
        if not l:
            continue
        for proto in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
            if l.startswith(proto) and ("enabled" in l.lower() or "accepted" in l.lower()):
                protocols.append(proto)
    return sorted(set(protocols))


def _weak_signals(protocols: List[str], cert: Dict[str, Any], stdout: str) -> List[str]:
    out: List[str] = []
    if "SSLv2" in protocols or "SSLv3" in protocols:
        out.append("Legacy SSL protocol appears enabled")
    if "TLSv1.0" in protocols or "TLSv1.1" in protocols:
        out.append("Deprecated TLS protocol appears enabled")
    low = stdout.lower()
    for token in ("rc4", "des-cbc", "3des", "anon", "null cipher"):
        if token in low:
            out.append(f"Weak cipher signal observed: {token}")
    not_after = cert.get("not_after")
    if isinstance(not_after, str) and not_after:
        try:
            # Example: 'Jun  1 12:00:00 2026 GMT'
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            if dt < datetime.now(timezone.utc):
                out.append("Certificate appears expired")
        except Exception:
            pass
    return sorted(set(out))


def scan_tls_url(url: str, *, timeout_sec: int = 60) -> Optional[Dict[str, Any]]:
    hp = _parse_host_port_from_url(url)
    if not hp:
        return None
    host, port = hp
    exe = shutil.which("sslscan")
    cert: Dict[str, Any] = {}
    stdout = ""
    stderr = ""
    command: Optional[str] = None
    tool = "python_ssl"
    status = "ok"
    error: Optional[str] = None

    try:
        cert = _cert_python(host, port, min(int(timeout_sec), 15))
    except Exception as exc:
        cert = {}
        error = f"python_ssl_cert_error: {str(exc)[:300]}"

    protocols: List[str] = []
    if exe:
        tool = "sslscan"
        command = f"{exe} --no-colour {host}:{port}"
        try:
            proc = subprocess.run(
                [exe, "--no-colour", f"{host}:{port}"],
                capture_output=True,
                text=True,
                timeout=int(timeout_sec),
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if proc.returncode not in (0, 1):
                status = "tool_error"
                error = (stderr or stdout or f"sslscan exited {proc.returncode}")[:500]
            protocols = _sslscan_protocols(stdout)
        except Exception as exc:
            status = "tool_error"
            error = str(exc)[:500]
    weak = _weak_signals(protocols, cert, stdout)
    result = TlsScanResult(
        host=host,
        port=port,
        tool=tool,
        command=command,
        status=status,
        certificate=cert,
        supported_protocols=protocols,
        weak_signals=weak,
        stdout_excerpt=stdout[:5000] if stdout else None,
        stderr_excerpt=stderr[:2000] if stderr else None,
        error=error,
    )
    return asdict(result)
