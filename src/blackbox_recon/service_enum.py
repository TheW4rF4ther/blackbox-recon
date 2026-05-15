"""Service-specific enumeration dispatcher.

The goal of this module is to make Blackbox Recon behave more like a serious
operator workflow: once ports are discovered, run focused, service-aware
reconnaissance steps. These checks are intentionally observational and scoped to
services already confirmed open by the current run.
"""

from __future__ import annotations

import ftplib
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class ServiceEnumResult:
    host: str
    port: int
    service: str
    module: str
    tool: str
    command: Optional[str]
    status: str
    findings: List[Dict[str, Any]]
    stdout_excerpt: Optional[str] = None
    stderr_excerpt: Optional[str] = None
    error: Optional[str] = None


def _service_name(row: Dict[str, Any]) -> str:
    svc = str(row.get("service") or "").lower()
    port = int(row.get("port") or 0)
    if not svc or svc == "unknown":
        return {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            110: "pop3",
            139: "netbios-ssn",
            143: "imap",
            445: "smb",
            465: "smtps",
            587: "submission",
            993: "imaps",
            995: "pop3s",
            3389: "rdp",
        }.get(port, "unknown")
    return svc


def _is_open(row: Dict[str, Any]) -> bool:
    return str(row.get("state") or "").lower() == "open"


def _run_cmd(cmd: List[str], timeout_sec: int) -> Tuple[str, str, int, Optional[str]]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(5, int(timeout_sec)),
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode, None
    except subprocess.TimeoutExpired as exc:
        return exc.stdout or "", exc.stderr or "", 124, f"timeout after {timeout_sec}s"
    except Exception as exc:
        return "", "", 1, str(exc)[:500]


def _nmap_script(host: str, port: int, script: str, timeout_sec: int) -> ServiceEnumResult:
    exe = shutil.which("nmap")
    service = "ssh" if "ssh" in script else "rdp"
    if not exe:
        return ServiceEnumResult(
            host=host,
            port=port,
            service=service,
            module=f"nmap_{script}",
            tool="nmap",
            command=None,
            status="skipped",
            findings=[],
            error="nmap not found on PATH",
        )
    cmd = [exe, "-Pn", "-n", "--max-retries", "1", "--host-timeout", f"{timeout_sec}s", "--script", script, "-p", str(port), host]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec + 10)
    low = stdout.lower()
    findings: List[Dict[str, Any]] = []
    if "ssh2-enum-algos" in script:
        weak_tokens = ["diffie-hellman-group1-sha1", "ssh-rsa", "hmac-md5", "3des-cbc", "arcfour"]
        observed = sorted({t for t in weak_tokens if t in low})
        if observed:
            findings.append({"type": "weak_ssh_algorithm_signal", "values": observed})
    if "rdp-enum-encryption" in script:
        if "network level authentication" in low:
            findings.append({"type": "rdp_encryption_metadata", "observed": "NLA/encryption metadata present in output"})
        if "ssl" in low or "credssp" in low or "rdp security" in low:
            findings.append({"type": "rdp_security_protocol_metadata", "observed": "security protocol metadata present in output"})
    status = "ok" if code in (0, 1) and not err else "tool_error"
    return ServiceEnumResult(
        host=host,
        port=port,
        service=service,
        module=f"nmap_{script}",
        tool="nmap",
        command=" ".join(cmd),
        status=status,
        findings=findings,
        stdout_excerpt=stdout[-8000:] if stdout else None,
        stderr_excerpt=stderr[-3000:] if stderr else None,
        error=err,
    )


def _smb_enum(host: str, port: int, timeout_sec: int) -> ServiceEnumResult:
    exe = shutil.which("smbclient")
    if not exe:
        return ServiceEnumResult(host, port, "smb", "smbclient_list_shares", "smbclient", None, "skipped", [], error="smbclient not found on PATH")
    target = f"//{host}/"
    cmd = [exe, "-L", target, "-N", "-g", "-p", str(port), "-m", "SMB3"]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    findings: List[Dict[str, Any]] = []
    shares: List[Dict[str, str]] = []
    for line in (stdout or "").splitlines():
        parts = line.split("|")
        if len(parts) >= 2 and parts[0].lower() in ("disk", "printer", "ipc"):
            shares.append({"type": parts[0], "name": parts[1]})
    if shares:
        findings.append({"type": "smb_anonymous_share_listing", "shares": shares[:40]})
    status = "ok" if code == 0 else "completed_nonzero"
    if err:
        status = "tool_error"
    return ServiceEnumResult(host, port, "smb", "smbclient_list_shares", "smbclient", " ".join(cmd), status, findings, stdout[-8000:] if stdout else None, stderr[-3000:] if stderr else None, err)


def _ftp_enum(host: str, port: int, timeout_sec: int) -> ServiceEnumResult:
    findings: List[Dict[str, Any]] = []
    banner = None
    error = None
    status = "ok"
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=max(5, int(timeout_sec)))
        banner = ftp.getwelcome()
        if banner:
            findings.append({"type": "ftp_banner", "banner": banner[:300]})
        try:
            ftp.login("anonymous", "blackbox-recon@example.invalid")
            findings.append({"type": "ftp_anonymous_login_allowed"})
            try:
                pwd = ftp.pwd()
                findings.append({"type": "ftp_anonymous_pwd", "path": pwd})
            except Exception:
                pass
        except ftplib.error_perm:
            findings.append({"type": "ftp_anonymous_login_not_allowed"})
        finally:
            try:
                ftp.quit()
            except Exception:
                ftp.close()
    except Exception as exc:
        status = "tool_error"
        error = str(exc)[:500]
    return ServiceEnumResult(host, port, "ftp", "ftp_banner_anonymous", "python_ftplib", f"FTP connect/login anonymous {host}:{port}", status, findings, banner, None, error)


def _smtp_enum(host: str, port: int, timeout_sec: int) -> ServiceEnumResult:
    findings: List[Dict[str, Any]] = []
    transcript: List[str] = []
    status = "ok"
    error = None
    try:
        with socket.create_connection((host, port), timeout=max(5, int(timeout_sec))) as sock:
            sock.settimeout(max(5, int(timeout_sec)))
            try:
                banner = sock.recv(1024).decode("utf-8", "replace").strip()
                if banner:
                    transcript.append(banner)
                    findings.append({"type": "smtp_banner", "banner": banner[:300]})
            except socket.timeout:
                pass
            sock.sendall(b"EHLO blackbox-recon.local\r\n")
            data = sock.recv(4096).decode("utf-8", "replace")
            if data:
                transcript.append(data.strip())
                caps = [ln.strip() for ln in data.splitlines() if ln.strip()]
                findings.append({"type": "smtp_ehlo_capabilities", "capabilities": caps[:50]})
                if "STARTTLS" in data.upper():
                    findings.append({"type": "smtp_starttls_offered"})
            try:
                sock.sendall(b"QUIT\r\n")
            except Exception:
                pass
    except Exception as exc:
        status = "tool_error"
        error = str(exc)[:500]
    return ServiceEnumResult(host, port, "smtp", "smtp_ehlo_starttls", "python_socket", f"SMTP banner/EHLO {host}:{port}", status, findings, "\n".join(transcript)[-5000:] if transcript else None, None, error)


def _generic_banner(host: str, port: int, service: str, timeout_sec: int) -> ServiceEnumResult:
    findings: List[Dict[str, Any]] = []
    banner = ""
    status = "ok"
    error = None
    try:
        with socket.create_connection((host, port), timeout=max(3, int(timeout_sec))) as sock:
            sock.settimeout(max(3, int(timeout_sec)))
            try:
                banner = sock.recv(1024).decode("utf-8", "replace").strip()
            except socket.timeout:
                banner = ""
        if banner:
            findings.append({"type": "service_banner", "banner": banner[:500]})
    except Exception as exc:
        status = "tool_error"
        error = str(exc)[:500]
    return ServiceEnumResult(host, port, service, "generic_banner", "python_socket", f"TCP connect/read banner {host}:{port}", status, findings, banner[-5000:] if banner else None, None, error)


def run_service_enumeration(port_rows: Iterable[Dict[str, Any]], *, timeout_sec: int = 60, max_services: int = 24) -> Dict[str, Any]:
    """Run service-aware recon modules for already-discovered open ports."""
    results: List[Dict[str, Any]] = []
    rows = [r for r in port_rows if isinstance(r, dict) and _is_open(r)]
    for row in rows[: max(1, int(max_services))]:
        host = str(row.get("host") or "").strip()
        port = int(row.get("port") or 0)
        service = _service_name(row)
        if not host or not port:
            continue
        try:
            if port == 22 or service == "ssh":
                results.append(asdict(_nmap_script(host, port, "ssh2-enum-algos", timeout_sec)))
            elif port in (139, 445) or service in ("smb", "microsoft-ds", "netbios-ssn"):
                results.append(asdict(_smb_enum(host, port, timeout_sec)))
            elif port == 21 or service == "ftp":
                results.append(asdict(_ftp_enum(host, port, timeout_sec)))
            elif port in (25, 465, 587) or service in ("smtp", "smtps", "submission"):
                results.append(asdict(_smtp_enum(host, port, timeout_sec)))
            elif port == 3389 or "rdp" in service or service == "ms-wbt-server":
                results.append(asdict(_nmap_script(host, port, "rdp-enum-encryption", timeout_sec)))
            elif port in (110, 143, 993, 995, 3306, 5432, 6379, 9200, 9300, 27017):
                results.append(asdict(_generic_banner(host, port, service, min(timeout_sec, 15))))
        except Exception as exc:
            results.append(
                asdict(
                    ServiceEnumResult(
                        host=host,
                        port=port,
                        service=service,
                        module="service_dispatcher",
                        tool="blackbox_recon",
                        command=None,
                        status="tool_error",
                        findings=[],
                        error=str(exc)[:500],
                    )
                )
            )
    return {"results": results, "services_considered": len(rows), "modules_run": len(results)}
