"""Pentester-forward terminal output for Blackbox Recon.

Primary contract: tool used -> command -> pertinent output -> signals.
After the tools, show vulnerability-identification signals and likely next moves.
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


def _findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [f for f in (results.get("deterministic_findings") or []) if isinstance(f, dict)]


def _ports(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [p for p in (results.get("ports") or []) if isinstance(p, dict)]


def _has_port(results: Dict[str, Any], port: int) -> bool:
    return any(int(p.get("port") or 0) == port for p in _ports(results))


def _finding_by_code(results: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
    return [f for f in _findings(results) if f.get("finding_code") == code]


def _likely_next_moves(results: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    moves: List[Tuple[str, str, str]] = []
    if _has_port(results, 22):
        moves.append(("1", "SSH", "Validate authentication policy, exposed users/process, and ssh2-enum-algos output."))
    if _has_port(results, 80) or _has_port(results, 443):
        moves.append(("2", "Web", "Rerun with hostname/apex domain for vhost/SNI-aware content discovery, headers, WAF, TLS, and screenshots."))
    if results.get("tls_analysis"):
        moves.append(("3", "TLS", "Review sslscan protocol/certificate output; map weak signals to client hardening standards."))
    if _finding_by_code(results, "BBR-COVERAGE-001"):
        moves.append(("4", "Scope", "Bare IP limits app recon. Obtain scoped DNS names before deeper web exploitation planning."))
    return moves[:6]


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
    _render_tool_results(tool_results)
    _render_vulnerability_signals(findings)
    _render_next_moves(results)


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


def _render_tool_results(tool_results: List[Dict[str, Any]]) -> None:
    if not tool_results:
        return
    console.print("\n[bold cyan][+] Tool Results[/bold cyan]")
    for row in tool_results:
        title = f"{row.get('id')} · {row.get('tool')} · {row.get('purpose')}"
        body = Text()
        cmd = row.get("command") or "not recorded / internal helper"
        body.append("Command: ", style="bold dim")
        body.append(_short(cmd, 180) + "\n", style="dim")
        body.append("Status: ", style="bold dim")
        body.append(str(row.get("status") or "unknown") + "\n", style="green" if str(row.get("status")).lower() in ("ok", "completed") else "yellow")
        outputs = row.get("important_output") or []
        if outputs:
            body.append("Pertinent output:\n", style="bold bright_white")
            for item in outputs[:6]:
                body.append(f"  - {_short(item, 190)}\n", style="bright_white")
        signals = row.get("signals") or []
        if signals:
            body.append("Signals: ", style="bold dim")
            body.append(", ".join(map(str, signals[:8])), style="yellow")
        console.print(Panel(body, title=f"[bold cyan]{_short(title, 110)}[/bold cyan]", border_style="cyan", padding=(1, 2)))


def _render_vulnerability_signals(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        return
    table = Table(title="Vulnerability Identification Signals", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Code", style="bold yellow", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Assets", style="bright_white", overflow="fold")
    table.add_column("Signal", style="bright_white", overflow="fold")
    ordered = sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(str(f.get("severity")).lower(), 9))
    for f in ordered[:10]:
        sev = str(f.get("severity") or "")
        assets = ", ".join(map(str, (f.get("affected_assets") or [])[:3])) or "-"
        table.add_row(str(f.get("finding_code") or "-"), f"[{_sev_style(sev)}]{sev}[/]", str(f.get("status") or ""), _short(assets, 90), _short(f.get("title"), 120))
    console.print(table)


def _render_next_moves(results: Dict[str, Any]) -> None:
    moves = _likely_next_moves(results)
    if not moves:
        return
    table = Table(title="Likely Way Forward", box=box.ROUNDED, header_style="bold red")
    table.add_column("#", justify="right", style="bold yellow", no_wrap=True)
    table.add_column("Area", style="bold white", no_wrap=True)
    table.add_column("Pentester action", style="cyan", overflow="fold")
    for row in moves:
        table.add_row(*row)
    console.print(table)
