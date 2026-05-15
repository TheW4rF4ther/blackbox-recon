"""Rich terminal dashboard for Blackbox Recon operator-facing results.

This module turns normalized recon results into concise, readable terminal
sections so the operator does not have to infer meaning from raw phase logs.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


def _sev_style(sev: str) -> str:
    sev = (sev or "").lower()
    return {
        "critical": "bold red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "cyan",
        "informational": "dim cyan",
        "info": "dim cyan",
    }.get(sev, "white")


def _status_style(status: str) -> str:
    status = (status or "").lower()
    if status in ("ok", "completed", "confirmed", "applied"):
        return "green"
    if status in ("skipped", "not_observed"):
        return "dim"
    if "error" in status or "failed" in status:
        return "red"
    return "yellow"


def _short(s: Any, n: int = 84) -> str:
    text = " ".join(str(s or "").split())
    return text if len(text) <= n else text[: n - 1] + "..."


def _count(rows: Iterable[Any]) -> int:
    return len(list(rows or []))


def render_operator_dashboard(results: Dict[str, Any]) -> None:
    """Print a structured, operator-readable dashboard for the completed run."""
    target = results.get("target") or "target"
    summary = results.get("summary") or {}
    findings = list(results.get("deterministic_findings") or [])

    console.print()
    console.print(
        Panel(
            Text.from_markup(
                f"[bold bright_white]{target}[/bold bright_white]\n"
                "Evidence-backed scan results summarized for operator triage. "
                "Detailed command provenance remains available in `recon_phase_trace`."
            ),
            title="[bold cyan]Operator Results Dashboard[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    _render_snapshot(summary, findings)
    _render_open_services(results)
    _render_findings(findings)
    _render_web_posture(results)
    _render_service_enrichment(results)
    _render_tool_coverage(results)


def _render_snapshot(summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    table = Table(title="Run Snapshot", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Area", style="bold white")
    table.add_column("Result", style="bright_white", justify="right")
    table.add_column("Operator meaning", style="dim")
    rows = [
        ("Open TCP ports", summary.get("total_open_ports", summary.get("open_tcp_ports", 0)), "Confirmed network exposure"),
        ("HTTP/S services", summary.get("http_services_detected", 0), "Web attack surface candidates"),
        ("HTTP header URLs", summary.get("http_header_urls_analyzed", 0), "Browser hardening sampled"),
        ("TLS services", summary.get("tls_services_analyzed", 0), "Transport posture sampled"),
        ("Service enum modules", summary.get("service_enum_modules_run", 0), "Service-specific checks executed"),
        ("Web fingerprint modules", summary.get("web_fingerprint_modules_run", 0), "WhatWeb/WAF style checks"),
        ("DNS queries", summary.get("dns_record_queries_run", 0), "DNS inventory checks"),
        ("Screenshots", summary.get("screenshots_captured", 0), "Visual triage evidence"),
        ("Findings", len(findings), ", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items())) or "none"),
    ]
    for area, result, meaning in rows:
        table.add_row(area, str(result), meaning)
    console.print(table)


def _render_open_services(results: Dict[str, Any]) -> None:
    ports = list(results.get("ports") or [])
    if not ports:
        return
    table = Table(title="Open Services", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Host", style="white", no_wrap=True)
    table.add_column("Port", style="bold yellow", justify="right")
    table.add_column("Service", style="cyan")
    table.add_column("Version / banner", style="dim", overflow="fold")
    table.add_column("Follow-up", style="bright_white")
    for row in ports[:20]:
        port = int(row.get("port") or 0)
        svc = row.get("service") or "unknown"
        ver = row.get("version") or row.get("banner") or "-"
        if port == 22 or str(svc).lower() == "ssh":
            follow = "Review SSH exposure and algos"
        elif port in (80, 443) or "http" in str(svc).lower():
            follow = "Review web/TLS/header posture"
        else:
            follow = "Service-specific enum if in scope"
        table.add_row(str(row.get("host") or ""), str(port), str(svc), _short(ver, 90), follow)
    console.print(table)


def _render_findings(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        return
    table = Table(title="Prioritized Evidence-Backed Findings", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Code", style="bold yellow", no_wrap=True, min_width=18)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title", style="white", overflow="fold")
    table.add_column("Evidence", style="dim", justify="right")
    table.add_column("Operator action", style="bright_white", overflow="fold")
    for f in findings[:15]:
        sev = str(f.get("severity") or "")
        code = str(f.get("finding_code") or "-")
        evidence = len(f.get("evidence_ids") or [])
        action = f.get("recommendation") or f.get("validation") or "Review evidence and validate scope."
        table.add_row(str(f.get("id") or ""), code, f"[{_sev_style(sev)}]{sev}[/]", _short(f.get("title"), 96), str(evidence), _short(action, 110))
    console.print(table)


def _render_web_posture(results: Dict[str, Any]) -> None:
    headers = list((results.get("http_header_analysis") or {}).get("results") or [])
    webfp = list((results.get("web_fingerprinting") or {}).get("results") or [])
    tls = list((results.get("tls_analysis") or {}).get("results") or [])
    if not headers and not webfp and not tls:
        return

    table = Table(title="Web, TLS, and Fingerprinting Posture", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Asset", style="white", overflow="fold")
    table.add_column("Status", style="bold")
    table.add_column("Signals", style="bright_white", overflow="fold")
    table.add_column("Recommended read", style="dim", overflow="fold")

    for row in headers[:10]:
        missing = row.get("missing_security_headers") or []
        disclosure = row.get("disclosure_headers") or {}
        sigs = []
        if missing:
            sigs.append("missing headers: " + ", ".join(missing[:4]))
        if disclosure:
            sigs.append("disclosure: " + ", ".join(disclosure.keys()))
        table.add_row(str(row.get("url") or row.get("final_url") or ""), str(row.get("status_code") or "-"), _short("; ".join(sigs) or "headers sampled", 130), "Defense-in-depth, not proof of vuln.")

    for row in tls[:8]:
        asset = f"{row.get('host')}:{row.get('port')}"
        weak = row.get("weak_signals") or []
        protos = row.get("supported_protocols") or []
        if weak:
            signal = "weak signals: " + ", ".join(map(str, weak[:4]))
        elif protos:
            signal = "protocols: " + ", ".join(map(str, protos[:6]))
        else:
            signal = "TLS sampled"
        table.add_row(asset, str(row.get("status") or "-"), _short(signal, 130), "Confirm cipher/protocol policy and cert validity.")

    for row in webfp[:12]:
        ftypes = [str(f.get("type")) for f in (row.get("findings") or []) if isinstance(f, dict)]
        signal = f"{row.get('tool')}: {', '.join(ftypes) or 'completed'}"
        table.add_row(str(row.get("url") or ""), str(row.get("status") or "-"), _short(signal, 130), "Fingerprinting supports inventory, not CVE proof.")
    console.print(table)


def _render_service_enrichment(results: Dict[str, Any]) -> None:
    rows = list((results.get("service_enumeration") or {}).get("results") or [])
    dns_rows = list((results.get("dns_record_enrichment") or {}).get("results") or [])
    screenshots = list((results.get("screenshot_triage") or {}).get("results") or [])
    if not rows and not dns_rows and not screenshots:
        return

    table = Table(title="Service-Specific Enumeration and Triage", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Phase", style="bold cyan", no_wrap=True)
    table.add_column("Asset", style="white", overflow="fold")
    table.add_column("Module", style="yellow")
    table.add_column("Status", style="bold")
    table.add_column("Result", style="bright_white", overflow="fold")

    for row in rows[:12]:
        asset = f"{row.get('host')}:{row.get('port')}"
        findings = row.get("findings") or []
        result = ", ".join(str(f.get("type")) for f in findings if isinstance(f, dict)) or "completed/no flagged signal"
        status = str(row.get("status") or "")
        table.add_row("M8", asset, str(row.get("module") or ""), f"[{_status_style(status)}]{status}[/]", _short(result, 110))

    for row in dns_rows[:12]:
        recs = row.get("records") or []
        result = ", ".join(map(str, recs[:5])) if recs else "no records returned"
        status = str(row.get("status") or "")
        table.add_row("M10", str(row.get("target") or ""), f"DNS {row.get('record_type')}", f"[{_status_style(status)}]{status}[/]", _short(result, 110))

    for row in screenshots[:8]:
        result = row.get("screenshot_path") or row.get("error") or "not captured"
        status = str(row.get("status") or "")
        table.add_row("M11", str(row.get("url") or ""), str(row.get("tool") or "screenshot"), f"[{_status_style(status)}]{status}[/]", _short(result, 110))
    console.print(table)


def _render_tool_coverage(results: Dict[str, Any]) -> None:
    trace = list(results.get("recon_phase_trace") or [])
    if not trace:
        return
    table = Table(title="Tool Coverage and Provenance", box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Phase", style="bold cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Commands", justify="right", style="yellow")
    table.add_column("Representative command", style="dim", overflow="fold")
    for row in trace:
        cmds = row.get("commands_executed") or []
        rep = "-"
        if cmds:
            first = cmds[0]
            rep = f"{first.get('label', '')}: {first.get('command') or ''}"
            if len(cmds) > 1:
                rep += f" (+{len(cmds)-1} more)"
        status = str(row.get("status") or "")
        table.add_row(str(row.get("phase_id") or ""), f"[{_status_style(status)}]{status}[/]", str(len(cmds)), _short(rep, 130))
    console.print(table)
