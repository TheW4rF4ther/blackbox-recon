"""Results-first Rich terminal dashboard for Blackbox Recon.

This module prints observed scan results directly. It intentionally avoids
advice-heavy wording in the primary terminal view: pentesters need facts first,
then can inspect JSON/report detail for context and recommendations.
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


def _short(value: Any, n: int = 90) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _count(rows: Iterable[Any]) -> int:
    return len(list(rows or []))


def _kv(d: Dict[str, Any], keys: List[str], limit: int = 5) -> str:
    parts: List[str] = []
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            parts.append(f"{k}={_short(v, 45)}")
        if len(parts) >= limit:
            break
    return "; ".join(parts) or "-"


def render_operator_dashboard(results: Dict[str, Any]) -> None:
    """Print observed results in tables for pentester triage."""
    target = results.get("target") or "target"
    summary = results.get("summary") or {}
    findings = list(results.get("deterministic_findings") or [])

    console.print()
    console.print(
        Panel(
            Text.from_markup(
                f"[bold bright_white]{target}[/bold bright_white]\n"
                "Observed scan results. Full raw output, exact commands, and evidence IDs are saved in JSON."
            ),
            title="[bold cyan]Blackbox Recon Results[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    _render_snapshot(summary, findings)
    _render_open_services(results)
    _render_findings(findings)
    _render_web_content(results)
    _render_http_results(results)
    _render_tls_results(results)
    _render_web_fingerprints(results)
    _render_service_dns_screenshots(results)
    _render_tool_execution(results)


def _render_snapshot(summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    table = Table(title="Result Counts", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Count", style="bright_white", justify="right")
    table.add_column("Detail", style="dim")
    rows = [
        ("Subdomains", summary.get("total_subdomains", 0), f"HTTP probes with status: {summary.get('subdomain_http_probes_with_status', 0)}"),
        ("Open TCP ports", summary.get("total_open_ports", summary.get("open_tcp_ports", 0)), ""),
        ("HTTP/S services", summary.get("http_services_detected", 0), f"URLs targeted: {summary.get('http_urls_targeted', summary.get('web_urls_targeted', 0))}"),
        ("Directory scans", summary.get("directory_scans", summary.get("web_directory_scans", 0)), f"interesting paths: {summary.get('interesting_paths_found', 0)}"),
        ("HTTP header checks", summary.get("http_header_urls_analyzed", 0), ""),
        ("TLS checks", summary.get("tls_services_analyzed", 0), ""),
        ("Service enum modules", summary.get("service_enum_modules_run", 0), ""),
        ("Web fingerprint modules", summary.get("web_fingerprint_modules_run", 0), ""),
        ("DNS queries", summary.get("dns_record_queries_run", 0), ""),
        ("Screenshots", summary.get("screenshots_captured", 0), ""),
        ("Findings", len(findings), ", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items())) or "none"),
    ]
    for metric, count, detail in rows:
        table.add_row(metric, str(count), str(detail or "-"))
    console.print(table)


def _render_open_services(results: Dict[str, Any]) -> None:
    ports = list(results.get("ports") or [])
    if not ports:
        return
    table = Table(title="Open TCP Services", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Host", style="white", no_wrap=True)
    table.add_column("Port", style="bold yellow", justify="right")
    table.add_column("Service", style="cyan")
    table.add_column("Version / banner", style="bright_white", overflow="fold")
    table.add_column("State", style="green")
    for row in ports[:30]:
        table.add_row(
            str(row.get("host") or ""),
            str(row.get("port") or ""),
            str(row.get("service") or "unknown"),
            _short(row.get("version") or row.get("banner") or "-", 120),
            str(row.get("state") or "open"),
        )
    console.print(table)


def _render_findings(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        return
    table = Table(title="Findings", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Code", style="bold yellow", no_wrap=True, min_width=18)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Status", style="cyan", no_wrap=True)
    table.add_column("Title", style="white", overflow="fold")
    table.add_column("Assets", style="bright_white", overflow="fold")
    table.add_column("Evidence", style="dim", justify="right")
    for f in findings[:20]:
        sev = str(f.get("severity") or "")
        assets = ", ".join(map(str, (f.get("affected_assets") or [])[:3])) or "-"
        table.add_row(
            str(f.get("id") or ""),
            str(f.get("finding_code") or "-"),
            f"[{_sev_style(sev)}]{sev}[/]",
            str(f.get("status") or ""),
            _short(f.get("title"), 100),
            _short(assets, 100),
            str(len(f.get("evidence_ids") or [])),
        )
    console.print(table)


def _render_web_content(results: Dict[str, Any]) -> None:
    scans = list((results.get("web_content_discovery") or {}).get("directory_scans") or [])
    if not scans:
        return
    table = Table(title="Web Content Discovery", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Base URL", style="white", overflow="fold")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", no_wrap=True)
    table.add_column("Interesting", justify="right", style="yellow")
    table.add_column("Observed paths / note", style="bright_white", overflow="fold")
    for scan in scans[:12]:
        hits = scan.get("findings_interesting") or []
        if hits:
            note = ", ".join(f"{h.get('path')}({h.get('status_code')})" for h in hits[:5] if isinstance(h, dict))
        else:
            note = scan.get("error") or "no flagged paths"
        table.add_row(
            str(scan.get("base_url") or ""),
            str(scan.get("tool") or ""),
            f"[{_status_style(str(scan.get('status')))}]{scan.get('status')}[/]",
            str(len(hits)),
            _short(note, 130),
        )
    console.print(table)


def _render_http_results(results: Dict[str, Any]) -> None:
    rows = list((results.get("http_header_analysis") or {}).get("results") or [])
    if not rows:
        return
    table = Table(title="HTTP Response and Header Results", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("URL", style="white", overflow="fold")
    table.add_column("Status", justify="right", style="yellow")
    table.add_column("Final URL", style="cyan", overflow="fold")
    table.add_column("Title", style="bright_white", overflow="fold")
    table.add_column("Missing security headers", style="magenta", overflow="fold")
    table.add_column("Disclosure headers", style="dim", overflow="fold")
    for row in rows[:12]:
        missing = ", ".join(map(str, row.get("missing_security_headers") or [])) or "-"
        disclosure = row.get("disclosure_headers") or {}
        disclosure_txt = ", ".join(f"{k}={v}" for k, v in list(disclosure.items())[:4]) or "-"
        table.add_row(
            str(row.get("url") or ""),
            str(row.get("status_code") or "-"),
            _short(row.get("final_url") or "-", 90),
            _short(row.get("title") or "-", 80),
            _short(missing, 120),
            _short(disclosure_txt, 100),
        )
    console.print(table)


def _render_tls_results(results: Dict[str, Any]) -> None:
    rows = list((results.get("tls_analysis") or {}).get("results") or [])
    if not rows:
        return
    table = Table(title="TLS Results", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Host:Port", style="white", no_wrap=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Status", no_wrap=True)
    table.add_column("Protocols", style="bright_white", overflow="fold")
    table.add_column("Certificate", style="dim", overflow="fold")
    table.add_column("Weak signals", style="magenta", overflow="fold")
    for row in rows[:10]:
        cert = row.get("certificate") or {}
        cert_txt = _kv(cert, ["subject", "issuer", "not_before", "not_after", "subject_alt_name"], limit=3)
        table.add_row(
            f"{row.get('host')}:{row.get('port')}",
            str(row.get("tool") or ""),
            f"[{_status_style(str(row.get('status')))}]{row.get('status')}[/]",
            ", ".join(map(str, row.get("supported_protocols") or [])) or "-",
            _short(cert_txt, 140),
            _short(", ".join(map(str, row.get("weak_signals") or [])) or "-", 110),
        )
    console.print(table)


def _render_web_fingerprints(results: Dict[str, Any]) -> None:
    rows = list((results.get("web_fingerprinting") or {}).get("results") or [])
    if not rows:
        return
    table = Table(title="Web Fingerprinting / WAF Results", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("URL", style="white", overflow="fold")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", no_wrap=True)
    table.add_column("Finding types", style="yellow", overflow="fold")
    table.add_column("Observed output", style="bright_white", overflow="fold")
    for row in rows[:16]:
        findings = [f for f in (row.get("findings") or []) if isinstance(f, dict)]
        ftypes = ", ".join(str(f.get("type")) for f in findings) or "-"
        observed = " | ".join(_short(f.get("summary") or f, 100) for f in findings[:2])
        if not observed:
            observed = _short(row.get("stdout_excerpt") or row.get("error") or "-", 160)
        table.add_row(
            str(row.get("url") or ""),
            str(row.get("tool") or ""),
            f"[{_status_style(str(row.get('status')))}]{row.get('status')}[/]",
            _short(ftypes, 90),
            _short(observed, 180),
        )
    console.print(table)


def _render_service_dns_screenshots(results: Dict[str, Any]) -> None:
    service_rows = list((results.get("service_enumeration") or {}).get("results") or [])
    dns_rows = list((results.get("dns_record_enrichment") or {}).get("results") or [])
    screenshots = list((results.get("screenshot_triage") or {}).get("results") or [])
    if not service_rows and not dns_rows and not screenshots:
        return
    table = Table(title="Service Enumeration, DNS, and Screenshots", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Phase", style="bold cyan", no_wrap=True)
    table.add_column("Asset", style="white", overflow="fold")
    table.add_column("Tool / Module", style="yellow")
    table.add_column("Status", no_wrap=True)
    table.add_column("Observed result", style="bright_white", overflow="fold")

    for row in service_rows[:12]:
        findings = [f for f in (row.get("findings") or []) if isinstance(f, dict)]
        observed = ", ".join(str(f.get("type")) for f in findings) or _short(row.get("stdout_excerpt") or row.get("error") or "completed/no flagged signal", 160)
        table.add_row("M8", f"{row.get('host')}:{row.get('port')}", str(row.get("module") or row.get("tool") or ""), f"[{_status_style(str(row.get('status')))}]{row.get('status')}[/]", _short(observed, 160))

    for row in dns_rows[:12]:
        records = row.get("records") or []
        observed = ", ".join(map(str, records[:8])) if records else (row.get("error") or "no records returned")
        table.add_row("M10", str(row.get("target") or ""), f"DNS {row.get('record_type')}", f"[{_status_style(str(row.get('status')))}]{row.get('status')}[/]", _short(observed, 160))

    for row in screenshots[:8]:
        observed = row.get("screenshot_path") or row.get("error") or "not captured"
        table.add_row("M11", str(row.get("url") or ""), str(row.get("tool") or "screenshot"), f"[{_status_style(str(row.get('status')))}]{row.get('status')}[/]", _short(observed, 160))
    console.print(table)


def _render_tool_execution(results: Dict[str, Any]) -> None:
    trace = list(results.get("recon_phase_trace") or [])
    if not trace:
        return
    table = Table(title="Executed Tooling", box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Phase", style="bold cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("#", justify="right", style="yellow")
    table.add_column("Command sample", style="dim", overflow="fold")
    for row in trace:
        cmds = row.get("commands_executed") or []
        rep = "-"
        if cmds:
            first = cmds[0]
            rep = f"{first.get('label', '')}: {first.get('command') or ''}"
            if len(cmds) > 1:
                rep += f" (+{len(cmds)-1} more)"
        status = str(row.get("status") or "")
        table.add_row(str(row.get("phase_id") or ""), f"[{_status_style(status)}]{status}[/]", str(len(cmds)), _short(rep, 150))
    console.print(table)
