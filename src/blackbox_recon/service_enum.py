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
            80: "http",
            110: "pop3",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "smb",
            465: "smtps",
            587: "submission",
            993: "imaps",
            995: "pop3s",
            2049: "nfs",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            5985: "winrm",
            5986: "winrm",
            6379: "redis",
            27017: "mongodb",
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


def _result(host: str, port: int, service: str, module: str, tool: str, cmd: Optional[List[str]], status: str, findings: List[Dict[str, Any]], stdout: str = "", stderr: str = "", error: Optional[str] = None) -> ServiceEnumResult:
    return ServiceEnumResult(
        host=host,
        port=port,
        service=service,
        module=module,
        tool=tool,
        command=" ".join(cmd) if isinstance(cmd, list) else None,
        status=status,
        findings=findings,
        stdout_excerpt=stdout[-10000:] if stdout else None,
        stderr_excerpt=stderr[-4000:] if stderr else None,
        error=error,
    )


def _nmap_service_script(host: str, port: int, service: str, module: str, script_expr: str, timeout_sec: int) -> ServiceEnumResult:
    exe = shutil.which("nmap")
    if not exe:
        return ServiceEnumResult(host, port, service, module, "nmap", None, "skipped", [], error="nmap not found on PATH")
    cmd = [exe, "-Pn", "-n", "--max-retries", "1", "--host-timeout", f"{timeout_sec}s", "-sV", "--script", script_expr, "-p", str(port), host]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec + 10)
    low = stdout.lower()
    findings: List[Dict[str, Any]] = []

    if "ssh2-enum-algos" in script_expr:
        weak_tokens = ["diffie-hellman-group1-sha1", "ssh-rsa", "hmac-md5", "3des-cbc", "arcfour"]
        observed = sorted({t for t in weak_tokens if t in low})
        if observed:
            findings.append({"type": "weak_ssh_algorithm_signal", "values": observed})
        findings.append({"type": "ssh_algorithm_scan_completed"})

    if module == "nmap_http_safe_scripts":
        if "webdav is enabled" in low:
            findings.append({"type": "http_webdav_enabled"})
        if "http-server-header" in low or "server:" in low:
            findings.append({"type": "http_nse_server_metadata"})
        if "http-title" in low:
            findings.append({"type": "http_nse_title_metadata"})
        findings.append({"type": "http_nse_scan_completed"})

    if module == "nmap_smb_safe_scripts":
        for token, ftype in (("message signing enabled but not required", "smb_signing_not_required"), ("anonymous", "smb_anonymous_signal"), ("smb-os-discovery", "smb_os_metadata")):
            if token in low:
                findings.append({"type": ftype})
        findings.append({"type": "smb_nse_scan_completed"})

    if "rdp-enum-encryption" in script_expr:
        if "network level authentication" in low:
            findings.append({"type": "rdp_encryption_metadata", "observed": "NLA/encryption metadata present in output"})
        if "ssl" in low or "credssp" in low or "rdp security" in low:
            findings.append({"type": "rdp_security_protocol_metadata", "observed": "security protocol metadata present in output"})

    if module in ("nmap_mysql_safe_scripts", "nmap_postgres_safe_scripts", "nmap_redis_safe_scripts", "nmap_mongodb_safe_scripts", "nmap_vnc_safe_scripts", "nmap_nfs_safe_scripts"):
        findings.append({"type": f"{service}_nse_scan_completed"})

    status = "ok" if code in (0, 1) and not err else "tool_error"
    return _result(host, port, service, module, "nmap", cmd, status, findings, stdout, stderr, err)


def _nikto_http(host: str, port: int, service: str, timeout_sec: int) -> ServiceEnumResult:
    exe = shutil.which("nikto")
    if not exe:
        return ServiceEnumResult(host, port, service, "nikto_http", "nikto", None, "skipped", [], error="nikto not found on PATH")
    scheme = "https" if port in (443, 8443) or "ssl" in service or "https" in service else "http"
    url = f"{scheme}://{host}:{port}/"
    cmd = [exe, "-ask", "no", "-nointeractive", "-host", url]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    findings: List[Dict[str, Any]] = []
    interesting: List[str] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s.startswith("+"):
            continue
        low = s.lower()
        if any(tok in low for tok in ("server:", "x-frame-options", "x-content-type-options", "allowed http methods", "osvdb", "cve", "directory indexing", "admin", "backup", "default")):
            interesting.append(s[:300])
    if interesting:
        findings.append({"type": "nikto_interesting_observations", "values": interesting[:25]})
    elif stdout:
        findings.append({"type": "nikto_scan_completed"})
    status = "ok" if code in (0, 1, 2) and not err else "tool_error"
    return _result(host, port, service, "nikto_http", "nikto", cmd, status, findings, stdout, stderr, err)


def _smbclient_enum(host: str, port: int, timeout_sec: int) -> ServiceEnumResult:
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
    return _result(host, port, "smb", "smbclient_list_shares", "smbclient", cmd, status, findings, stdout, stderr, err)


def _enum4linux_enum(host: str, port: int, timeout_sec: int) -> ServiceEnumResult:
    exe = shutil.which("enum4linux-ng") or shutil.which("enum4linux")
    if not exe:
        return ServiceEnumResult(host, port, "smb", "enum4linux", "enum4linux", None, "skipped", [], error="enum4linux/enum4linux-ng not found on PATH")
    tool = "enum4linux-ng" if exe.endswith("enum4linux-ng") else "enum4linux"
    cmd = [exe, "-A", "-d", "-v", host] if tool == "enum4linux-ng" else [exe, "-a", "-M", "-l", "-d", host]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    low = stdout.lower()
    findings: List[Dict[str, Any]] = []
    if "null session" in low or "anonymous" in low:
        findings.append({"type": "smb_null_or_anonymous_metadata"})
    if "domain name" in low or "workgroup" in low:
        findings.append({"type": "smb_domain_workgroup_metadata"})
    if "user:" in low or "users" in low:
        findings.append({"type": "smb_user_enum_metadata"})
    if stdout and not findings:
        findings.append({"type": "enum4linux_scan_completed"})
    status = "ok" if code in (0, 1) and not err else "tool_error"
    return _result(host, port, "smb", "enum4linux", tool, cmd, status, findings, stdout, stderr, err)


def _smbmap_enum(host: str, port: int, timeout_sec: int) -> ServiceEnumResult:
    exe = shutil.which("smbmap")
    if not exe:
        return ServiceEnumResult(host, port, "smb", "smbmap_anonymous", "smbmap", None, "skipped", [], error="smbmap not found on PATH")
    cmd = [exe, "-H", host, "-P", str(port), "-u", "", "-p", ""]
    stdout, stderr, code, err = _run_cmd(cmd, timeout_sec)
    findings: List[Dict[str, Any]] = []
    if "read" in (stdout or "").lower() or "write" in (stdout or "").lower():
        findings.append({"type": "smbmap_access_metadata"})
    elif stdout:
        findings.append({"type": "smbmap_scan_completed"})
    status = "ok" if code in (0, 1) and not err else "tool_error"
    return _result(host, port, "smb", "smbmap_anonymous", "smbmap", cmd, status, findings, stdout, stderr, err)


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
                results.append(asdict(_nmap_service_script(host, port, "ssh", "nmap_ssh_algorithms", "ssh2-enum-algos", timeout_sec)))
            elif port in (80, 443, 8080, 8443) or service.startswith("http") or service in ("https", "ssl/http"):
                safe_http = "banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)"
                results.append(asdict(_nmap_service_script(host, port, service, "nmap_http_safe_scripts", safe_http, timeout_sec)))
                results.append(asdict(_nikto_http(host, port, service, max(timeout_sec, 90))))
            elif port in (139, 445) or service in ("smb", "microsoft-ds", "netbios-ssn"):
                smb_scripts = "banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)"
                results.append(asdict(_nmap_service_script(host, port, "smb", "nmap_smb_safe_scripts", smb_scripts, timeout_sec)))
                results.append(asdict(_smbclient_enum(host, port, timeout_sec)))
                results.append(asdict(_enum4linux_enum(host, port, max(timeout_sec, 120))))
                results.append(asdict(_smbmap_enum(host, port, timeout_sec)))
            elif port == 21 or service == "ftp":
                results.append(asdict(_ftp_enum(host, port, timeout_sec)))
                results.append(asdict(_nmap_service_script(host, port, "ftp", "nmap_ftp_safe_scripts", "ftp-* and not brute", timeout_sec)))
            elif port in (25, 465, 587) or service in ("smtp", "smtps", "submission"):
                results.append(asdict(_smtp_enum(host, port, timeout_sec)))
                results.append(asdict(_nmap_service_script(host, port, "smtp", "nmap_smtp_safe_scripts", "smtp-* and not brute", timeout_sec)))
            elif port == 3389 or "rdp" in service or service == "ms-wbt-server":
                results.append(asdict(_nmap_service_script(host, port, "rdp", "nmap_rdp_encryption", "rdp-enum-encryption", timeout_sec)))
            elif port == 2049 or service == "nfs":
                results.append(asdict(_nmap_service_script(host, port, "nfs", "nmap_nfs_safe_scripts", "nfs-* and not brute", timeout_sec)))
            elif port == 3306 or service == "mysql":
                results.append(asdict(_nmap_service_script(host, port, "mysql", "nmap_mysql_safe_scripts", "mysql-* and not brute", timeout_sec)))
            elif port == 5432 or service == "postgresql":
                results.append(asdict(_nmap_service_script(host, port, "postgresql", "nmap_postgres_safe_scripts", "pgsql-* and not brute", timeout_sec)))
            elif port == 6379 or service == "redis":
                results.append(asdict(_nmap_service_script(host, port, "redis", "nmap_redis_safe_scripts", "redis-info", timeout_sec)))
            elif port == 27017 or service == "mongodb":
                results.append(asdict(_nmap_service_script(host, port, "mongodb", "nmap_mongodb_safe_scripts", "mongodb-* and not brute", timeout_sec)))
            elif port in (5900, 5901) or service == "vnc":
                results.append(asdict(_nmap_service_script(host, port, "vnc", "nmap_vnc_safe_scripts", "vnc-info", timeout_sec)))
            elif port in (110, 143, 993, 995, 5985, 5986, 9200, 9300):
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
    # Drop pure skipped modules from the count but keep them in JSON for platform visibility.
    return {"results": results, "services_considered": len(rows), "modules_run": len([r for r in results if r.get("status") != "skipped"])}
