"""Service and version detection for open TCP ports (banner probe + optional nmap -sV)."""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import ssl


def find_nmap_executable(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve path to ``nmap`` (PATH, explicit path, or common Windows install dirs)."""
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        return shutil.which(explicit) or None
    found = shutil.which("nmap")
    if found:
        return found
    for candidate in (
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ):
        if Path(candidate).is_file():
            return candidate
    return None


def _parse_http_server_header(blob: str) -> str:
    for line in blob.split("\r\n"):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()[:400]
    return ""


def parse_banner_blob(blob: str, port: int, used_ssl: bool) -> Tuple[str, str]:
    """Infer (service, version_string) from raw bytes decoded as text."""
    if not blob:
        return "", ""

    blob_start = blob.lstrip()[:8000]
    first_line = blob_start.split("\r\n", 1)[0].strip()
    first_line_l = first_line.lower()

    if first_line_l.startswith("ssh-"):
        return "ssh", first_line.replace("SSH-2.0-", "").replace("SSH-1.99-", "").strip()[:300]

    if first_line_l.startswith("220 ") or first_line_l.startswith("220-"):
        return "smtp", first_line[:300]

    if first_line_l.startswith("+ok") or first_line_l.startswith("-err"):
        return "pop3", first_line[:200]

    if "imap4" in first_line_l or first_line_l.startswith("* ok"):
        return "imap", first_line[:200]

    if first_line_l.startswith("mysql") or first_line_l.startswith("\x4a\x00\x00"):
        return "mysql", first_line[:200]

    if first_line.upper().startswith("RFB "):
        return "vnc", first_line[:200]

    if re.match(r"HTTP/\d", first_line, re.I):
        svc = "https" if used_ssl else "http"
        srv = _parse_http_server_header(blob_start)
        return svc, srv

    # Fallback: first printable line as weak version hint
    if first_line and len(first_line) < 400:
        return "", first_line
    return "", blob_start[:200]


# Ports where we proactively send a minimal HTTP request (many services speak HTTP).
_HTTP_PROBE_PORTS = frozenset(
    {
        80,
        81,
        591,
        800,
        8008,
        8080,
        8081,
        8088,
        8180,
        8888,
        9080,
        9090,
        9443,
        8000,
        3000,
        5000,
        7001,
        8880,
    }
)
_SSL_PROBE_PORTS = frozenset({443, 8443, 9443, 4433, 8883})


async def probe_tcp_service(
    host: str,
    port: int,
    connect_timeout: float,
    read_timeout: float,
) -> Tuple[str, str, str]:
    """
    Connect, optionally send a minimal HTTP probe, read up to 8 KiB.

    Returns ``(service_name, version_summary, banner_snippet)``.
    """
    use_ssl = port in _SSL_PROBE_PORTS
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=connect_timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=connect_timeout,
            )
    except Exception:
        return "", "", ""

    banner = ""
    try:
        if port in _HTTP_PROBE_PORTS or use_ssl:
            req = (
                f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BlackboxRecon/1.0\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n"
            )
            writer.write(req.encode("ascii", errors="ignore"))
            await writer.drain()
        chunk = await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
        banner = chunk.decode("utf-8", errors="replace")
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

    svc, ver = parse_banner_blob(banner, port, use_ssl)
    snippet = banner.strip()[:500] if banner.strip() else ""
    return svc, ver, snippet


def apply_nmap_xml_to_results(host: str, open_ports: List[Any], xml_text: str) -> None:
    """Merge ``nmap -oX`` service scan output into existing ``PortScanResult`` rows (same host)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return

    by_port: Dict[int, Tuple[str, str]] = {}
    for h in root.findall("host"):
        matched = False
        for addr_el in h.findall("address"):
            if addr_el.get("addrtype") != "ipv4":
                continue
            if addr_el.get("addr") == host:
                matched = True
                break
        if not matched:
            continue
        ports_el = h.find("ports")
        if ports_el is None:
            continue
        for pel in ports_el.findall("port"):
            if pel.get("protocol") != "tcp":
                continue
            try:
                pnum = int(pel.get("portid", "0"))
            except ValueError:
                continue
            st = pel.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc_el = pel.find("service")
            if svc_el is None:
                continue
            name = (svc_el.get("name") or "").strip()
            product = (svc_el.get("product") or "").strip()
            version = (svc_el.get("version") or "").strip()
            extra = (svc_el.get("extrainfo") or "").strip()
            method = (svc_el.get("method") or "").strip()
            parts = [x for x in (product, version, extra) if x]
            ver_str = " ".join(parts)[:500]
            if not ver_str and method:
                ver_str = f"({method})"
            by_port[pnum] = (name or "unknown", ver_str)

    for pr in open_ports:
        if pr.host != host:
            continue
        hit = by_port.get(pr.port)
        if not hit:
            continue
        svc, ver = hit
        if svc:
            pr.service = svc
        if ver:
            pr.version = ver


def parse_nmap_xml_open_tcp_ports(xml_text: str) -> List[Dict[str, Any]]:
    """
    Parse ``nmap -oX`` output into open TCP port rows (full port scan / aggressive).

    Each row: host, port, state, service, version, banner (script excerpt), scripts (list).
    """
    rows: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return rows

    for h in root.findall("host"):
        host_ip = ""
        for addr_el in h.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                host_ip = addr_el.get("addr") or ""
                break
        if not host_ip:
            for addr_el in h.findall("address"):
                if addr_el.get("addrtype") == "ipv6":
                    host_ip = addr_el.get("addr") or ""
                    break
        if not host_ip:
            continue

        ports_el = h.find("ports")
        if ports_el is None:
            continue
        for pel in ports_el.findall("port"):
            if pel.get("protocol") != "tcp":
                continue
            try:
                pnum = int(pel.get("portid", "0"))
            except ValueError:
                continue
            st = pel.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc_el = pel.find("service")
            name = "unknown"
            product = ""
            version = ""
            extra = ""
            method = ""
            if svc_el is not None:
                name = (svc_el.get("name") or "").strip() or "unknown"
                product = (svc_el.get("product") or "").strip()
                version = (svc_el.get("version") or "").strip()
                extra = (svc_el.get("extrainfo") or "").strip()
                method = (svc_el.get("method") or "").strip()
            parts = [x for x in (product, version, extra) if x]
            ver_str = " ".join(parts)[:800]
            if not ver_str and method:
                ver_str = f"({method})"

            script_lines: List[str] = []
            for scr in pel.findall("script"):
                sid = (scr.get("id") or "").strip()
                out = (scr.get("output") or "").strip().replace("\n", " ")[:400]
                if sid or out:
                    script_lines.append(f"{sid}: {out}".strip(": ").strip()[:500])
                if len(script_lines) >= 8:
                    break

            banner = script_lines[0] if script_lines else None
            rows.append(
                {
                    "host": host_ip,
                    "port": pnum,
                    "state": "open",
                    "service": name,
                    "version": ver_str or None,
                    "banner": banner,
                    "scripts": script_lines[:12] or None,
                }
            )
    return rows


def run_nmap_aggressive_scan(
    target: str,
    nmap_exe: str,
    timeout_sec: int,
) -> Tuple[bool, str, str, str]:
    """
    Run ``nmap -v -p- -A --open`` against ``target`` (hostname or IP).

    Returns ``(ok, xml_stdout, stderr, command_string)``.
    XML is emitted to stdout via ``-oX -``; ``-v`` details go to stderr.
    """
    use_no_dns = _looks_like_ip(target)
    cmd = [
        nmap_exe,
        "-v",
        "-p-",
        "-A",
        "--open",
        "-Pn",
        "-oX",
        "-",
        target,
    ]
    if use_no_dns:
        cmd.insert(-1, "-n")

    cmd_str = " ".join(cmd)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(60, int(timeout_sec)),
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return False, "", f"nmap timed out after {timeout_sec}s", cmd_str
    except (FileNotFoundError, OSError) as exc:
        return False, "", str(exc), cmd_str

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    ok_xml = "<nmaprun" in stdout[:8000]
    ok = ok_xml and (proc.returncode == 0 or bool(stdout.strip()))
    return ok, stdout, stderr, cmd_str


def _looks_like_ip(target: str) -> bool:
    t = target.strip()
    if t.count(".") == 3 and all(p.isdigit() for p in t.split(".")):
        return True
    if ":" in t and not t.startswith("http"):
        return True
    return False


def run_nmap_service_scan(
    host: str,
    open_ports: List[Any],
    nmap_exe: str,
    timeout_sec: int,
) -> bool:
    """
    Run ``nmap -sV -p <ports> <host>`` and merge XML into ``open_ports`` in place.

    Returns True if nmap ran and XML was parsed (even if no extra data).
    """
    ours = [p for p in open_ports if p.host == host and p.state == "open"]
    if not ours:
        return False
    port_spec = ",".join(str(p.port) for p in sorted(ours, key=lambda x: x.port))
    cmd = [
        nmap_exe,
        "-Pn",
        "-n",
        "-sV",
        "--version-light",
        "-p",
        port_spec,
        "--host-timeout",
        f"{min(timeout_sec, 600)}s",
        "-oX",
        "-",
        host,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=min(timeout_sec + 30, 900),
            errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    if proc.returncode != 0 and not (proc.stdout and "<nmaprun" in proc.stdout[:2000]):
        return False
    stdout = proc.stdout or ""
    if "<nmaprun" not in stdout[:5000]:
        return False
    apply_nmap_xml_to_results(host, open_ports, stdout)
    return True
