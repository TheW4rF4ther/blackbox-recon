"""Fast target reachability checks for active recon.

The goal is to fail fast when VPN routes/lab IPs change, without relying only
on ICMP. Many lab boxes block ping, so we use TCP probes against common ports
and optional nmap host discovery as supporting evidence.
"""

from __future__ import annotations

import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional

from .service_detection import find_nmap_executable

DEFAULT_PROBE_PORTS = (22, 80, 443, 21, 25, 53, 110, 111, 135, 139, 445, 8080, 8443, 3389, 5900)


@dataclass
class ReachabilityResult:
    target: str
    resolved_ips: List[str]
    reachable: bool
    method: str
    evidence: List[str]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def resolve_ipv4(target: str, timeout_sec: float = 5.0) -> List[str]:
    """Resolve target to IPv4s. Literal IPs are returned directly."""
    t = target.strip()
    if t.count(".") == 3 and all(p.isdigit() for p in t.split(".")):
        return [t]
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_sec)
    try:
        infos = socket.getaddrinfo(t, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = []
        for inf in infos:
            ip = inf[4][0]
            if ip and ip not in ips:
                ips.append(ip)
        return ips
    finally:
        socket.setdefaulttimeout(old_timeout)


def _tcp_connect(ip: str, port: int, timeout_sec: float) -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)
    try:
        code = sock.connect_ex((ip, port))
        if code == 0:
            return f"tcp/{port} open on {ip}"
        # Connection refused proves the host route exists and host responded.
        if code in (111, 61, 10061):
            return f"tcp/{port} refused on {ip} (host reachable)"
        return None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _nmap_ping_probe(target: str, timeout_sec: int, nmap_exe: Optional[str]) -> Optional[str]:
    exe = find_nmap_executable(nmap_exe)
    if not exe:
        return None
    # Do not use -Pn here. This is specifically a host discovery sanity check.
    cmd = [exe, "-sn", "-n", "--max-retries", "1", "--host-timeout", f"{max(5, int(timeout_sec))}s", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=max(8, int(timeout_sec) + 4))
    except Exception:
        return None
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    low = out.lower()
    if "host is up" in low:
        return "nmap -sn reports host is up"
    if "0 hosts up" in low:
        return "nmap -sn reports 0 hosts up"
    return None


def check_target_reachability(
    target: str,
    *,
    ports: Iterable[int] = DEFAULT_PROBE_PORTS,
    connect_timeout_sec: float = 1.5,
    overall_timeout_sec: int = 20,
    nmap_executable: Optional[str] = None,
    nmap_ping: bool = True,
) -> ReachabilityResult:
    evidence: List[str] = []
    try:
        ips = resolve_ipv4(target)
    except Exception as exc:
        return ReachabilityResult(target=target, resolved_ips=[], reachable=False, method="dns", evidence=[], error=f"resolution failed: {exc}")

    if not ips:
        return ReachabilityResult(target=target, resolved_ips=[], reachable=False, method="dns", evidence=[], error="target did not resolve to an IPv4 address")

    probes = []
    for ip in ips[:4]:
        for port in list(ports)[:32]:
            probes.append((ip, int(port)))

    workers = min(32, max(4, len(probes)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_tcp_connect, ip, port, float(connect_timeout_sec)): (ip, port) for ip, port in probes}
        for fut in as_completed(futs, timeout=max(5, int(overall_timeout_sec))):
            try:
                hit = fut.result()
            except Exception:
                hit = None
            if hit:
                evidence.append(hit)
                return ReachabilityResult(target=target, resolved_ips=ips, reachable=True, method="tcp", evidence=evidence)

    if nmap_ping:
        np = _nmap_ping_probe(ips[0], min(12, max(5, int(overall_timeout_sec))), nmap_executable)
        if np:
            evidence.append(np)
            if "host is up" in np.lower():
                return ReachabilityResult(target=target, resolved_ips=ips, reachable=True, method="nmap_ping", evidence=evidence)

    return ReachabilityResult(
        target=target,
        resolved_ips=ips,
        reachable=False,
        method="tcp+nmap_ping" if nmap_ping else "tcp",
        evidence=evidence,
        error="no TCP response/refusal observed on common ports; target may be down, VPN route may be stale, or host may be fully filtered",
    )
