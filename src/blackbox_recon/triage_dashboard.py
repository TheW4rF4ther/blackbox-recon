"""Pentester-forward terminal output for Blackbox Recon.

Primary contract: tool used -> command -> pertinent output -> signals.
After the tools, show technical verification targets only when they add value.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .tool_results import build_tool_results

console = Console()


def _short(value: Any, n: int = 120) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _sev_style(sev: str) -> str:
    sev = (sev or "").lower()
    if sev in ("critical", "high"):
        return "bold red"
    if sev == "medium":
        return "bold yellow"
    if sev == "low":
        return "cyan"
    return "dim cyan"


def _status_style(status: str) -> str:
    status = (status or "").lower()
    if status in ("ok", "completed", "confirmed", "applied"):
        return "green"
    if status in ("skipped", "not_observed", "not applicable"):
        return "dim"
    if "error" in status or "fail" in status:
        return "red"
    return "yellow"


def _signal_badge(signal: str) -> str:
    low = (signal or "").lower()
    if "no weak signal" in low or "tls sampled" in low or "service script completed" in low:
        return "[dim cyan][INFO][/dim cyan]"
    if "ssh exposed" in low or "web service exposed" in low or "interesting paths found" in low:
        return "[bold yellow][EXPOSURE][/bold yellow]"
    if "weak" in low or "missing security headers" in low or "service disclosure" in low:
        return "[bold red][SIGNAL][/bold red]"
    if "no flagged" in low or "none observed" in low or "not captured" in low or "no useful" in low:
        return "[dim][NEGATIVE][/dim]"
    if "bare ip" in low or "coverage" in low or "screenshot not" in low:
        return "[bold magenta][LIMITATION][/bold magenta]"
    return "[dim cyan][INFO][/dim cyan]"


def _is_low_signal(row: Dict[str, Any]) -> bool:
    status = str(row.get("status") or "").lower()
    signals = " ".join(map(str, row.get("signals") or [])).lower()
    output = " ".join(map(str, row.get("important_output") or [])).lower()
    if "error" in status or "fail" in status:
        return False
    if any(x in signals or x in output for x in ("ssh exposed", "web service exposed", "weak tls signal", "missing security headers", "service disclosure", "interesting paths found", "waf_signal", "service script completed")):
        return False
    return any(x in signals or x in output or x in status for x in ("no flagged", "0 interesting", "none observed", "not captured", "skipped", "no useful", "completed/no flagged"))


def _findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [f for f in (results.get("deterministic_findings") or []) if isinstance(f, dict)]


def _ports(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [p for p in (results.get("ports") or []) if isinstance(p, dict)]


def _has_port(results: Dict[str, Any], port: int) -> bool:
    return any(int(p.get("port") or 0) == port for p in _ports(results))


def _finding_by_code(results: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
    return [f for f in _findings(results) if f.get("finding_code") == code]


def _verification_targets(results: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
    targets: List[Tuple[str, str, str, str]] = []
    if _has_port(results, 22):
        targets.append(("SSH", "22/tcp", "Auth methods, password policy, key-only enforcement, algorithm list", "ssh -o PreferredAuthentications=none -v USER@TARGET; review ssh2-enum-algos output"))
    if _has_port(results, 80) or _has_port(results, 443):
        targets.append(("HTTP/S", "80/443", "Hostname/vhost routing, app identity, default nginx, hidden content", "Re-run against scoped FQDN; add Host header/vhost discovery before vuln testing"))
    if results.get("tls_analysis"):
        targets.append(("TLS", "443/tcp", "Certificate CN/SAN/issuer/expiry, TLS versions, weak ciphers/protocols", "Use sslscan/testssl.sh against FQDN + IP; compare to client crypto standard"))
    if _finding_by_code(results, "BBR-COVERAGE-001"):
        targets.append(("Scope", "bare IP", "SNI/vhost/subdomain blindness", "Obtain apex domain or scoped hostname; repeat recon with DNS context"))
    return targets[:6]


def render_triage_dashboard(results: Dict[str, Any]) -> None:
    target = results.get("target") or "target"
    summary = results.get("summary") or {}
    findings = _findings(results)
    tool_results = build_tool_results(results)

    console.print()
    console.print(
        Panel(
            Text.from_markup(
                f"[bold bright_white]{target}[/bold bright_white]\n"
                "Tool results first. AI analysis follows only after evidence collection."
            ),
            title="[bold red]Blackbox Recon · Pentest Scanner Output[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )
    _render_scan_snapshot(summary, findings, tool_results)
    _render_open_ports(results)
    _render_tool_results(tool_results)
    _render_vulnerability_signals(findings)
    _render_verification_targets(results)
    _render_tester_takeaway(results)


def _render_scan_snapshot(summary: Dict[str, Any], findings: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]) -> None:
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    table = Table(title="Scan Snapshot", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Tools", justify="right", style="bold yellow")
    table.add_column("Open ports", justify="right", style="bold yellow")
    table.add_column("Web", justify="right", style="bold yellow")
    table.add_column("Content hits", justify="right", style="bold yellow")
    table.add_column("Findings", justify="right", style="bold yellow")
    table.add_column("Severity mix", style="bright_white")
    table.add_row(
        str(len(tool_results)),
        str(summary.get("total_open_ports", summary.get("open_tcp_ports", 0))),
        str(summary.get("http_services_detected", 0)),
        str(summary.get("interesting_paths_found", 0)),
        str(len(findings)),
        ", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items())) or "none",
    )
    console.print(table)


def _render_open_ports(results: Dict[str, Any]) -> None:
    ports = _ports(results)
    if not ports:
        return
    table = Table(title="Open Ports", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Host", style="white", no_wrap=True)
    table.add_column("Port", justify="right", style="bold yellow", no_wrap=True)
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Version / banner", style="bright_white", overflow="fold")
    table.add_column("State", style="green", no_wrap=True)
    for port in ports[:30]:
        table.add_row(
            str(port.get("host") or ""),
            str(port.get("port") or ""),
            str(port.get("service") or "unknown"),
            _short(port.get("version") or port.get("banner") or "-", 130),
            str(port.get("state") or "open"),
        )
    console.print(table)


def _render_tool_results(tool_results: List[Dict[str, Any]]) -> None:
    if not tool_results:
        return
    console.print("\n[bold cyan][+] Tool Results[/bold cyan]")
    for row in tool_results:
        title = f"{row.get('id')} · {row.get('tool')} · {row.get('purpose')}"
        signals = row.get("signals") or []
        outputs = row.get("important_output") or []
        status = str(row.get("status") or "unknown")
        if _is_low_signal(row):
            first_output = _short(outputs[0] if outputs else "completed/no useful signal", 140)
            badge = _signal_badge(", ".join(map(str, signals)) or first_output)
            console.print(f"  {badge} [bold cyan]{row.get('tool')}[/bold cyan]: [{_status_style(status)}]{status}[/] · {first_output}")
            continue

        body = Text()
        cmd = row.get("command") or "not recorded / internal helper"
        body.append("Command: ", style="bold dim")
        body.append(_short(cmd, 180) + "\n", style="dim")
        body.append("Status: ", style="bold dim")
        body.append(status + "\n", style=_status_style(status))
        if outputs:
            body.append("Pertinent output:\n", style="bold bright_white")
            for item in outputs[:6]:
                body.append(f"  - {_short(item, 190)}\n", style="bright_white")
        if signals:
            body.append("Signals:\n", style="bold dim")
            for sig in signals[:8]:
                body.append(f"  {_signal_badge(str(sig))} {_short(sig, 160)}\n")
        border = "red" if _status_style(status) == "red" else "yellow" if signals else "cyan"
        console.print(Panel(body, title=f"[bold cyan]{_short(title, 110)}[/bold cyan]", border_style=border, padding=(1, 2)))


def _render_vulnerability_signals(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        return
    useful = [f for f in findings if str(f.get("finding_code") or "").startswith(("BBR-WEB-HDR", "BBR-TLS", "BBR-SSH", "BBR-SMB", "BBR-FTP", "BBR-SMTP", "BBR-RDP"))]
    if not useful:
        return
    table = Table(title="Vulnerability Identification Signals", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Code", style="bold yellow", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Assets", style="bright_white", overflow="fold")
    table.add_column("Signal", style="bright_white", overflow="fold")
    ordered = sorted(useful, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(str(f.get("severity")).lower(), 9))
    for f in ordered[:10]:
        sev = str(f.get("severity") or "")
        assets = ", ".join(map(str, (f.get("affected_assets") or [])[:3])) or "-"
        table.add_row(str(f.get("finding_code") or "-"), f"[{_sev_style(sev)}]{sev}[/]", str(f.get("status") or ""), _short(assets, 90), _short(f.get("title"), 120))
    console.print(table)


def _render_verification_targets(results: Dict[str, Any]) -> None:
    targets = _verification_targets(results)
    if not targets:
        return
    table = Table(title="Technical Verification Targets", box=box.ROUNDED, header_style="bold red")
    table.add_column("Area", style="bold white", no_wrap=True)
    table.add_column("Asset", style="bold yellow", no_wrap=True)
    table.add_column("Verify", style="bright_white", overflow="fold")
    table.add_column("Command / method", style="cyan", overflow="fold")
    for row in targets:
        table.add_row(*row)
    console.print(table)


def _render_tester_takeaway(results: Dict[str, Any]) -> None:
    bullets: List[str] = []
    summary = results.get("summary") or {}
    if _has_port(results, 80) or _has_port(results, 443):
        bullets.append("Best next technical move: rerun web recon against the scoped hostname, not just the IP.")
    if _has_port(results, 22):
        bullets.append("SSH is worth hardening verification, but not a finding by itself without auth/crypto weakness evidence.")
    if int(summary.get("interesting_paths_found", 0) or 0) == 0:
        bullets.append("Directory brute force produced no useful paths on this target/profile.")
    if _finding_by_code(results, "BBR-COVERAGE-001"):
        bullets.append("Current scan is reconnaissance-limited by bare-IP scope; DNS/vhost context is required for serious web testing.")
    if not bullets:
        return
    text = Text()
    for item in bullets[:5]:
        text.append(f"- {_short(item, 180)}\n", style="bright_white")
    console.print(Panel(text, title="[bold green]Tester Takeaway[/bold green]", border_style="green", padding=(1, 2)))
