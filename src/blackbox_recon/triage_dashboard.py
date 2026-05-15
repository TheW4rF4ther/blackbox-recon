"""Pentester-forward terminal triage for Blackbox Recon.

This view is intentionally compact. It answers: what is exposed, what matters,
what was negative/limiting, and where should the tester go next.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def _short(value: Any, n: int = 110) -> str:
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


def _ports(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [p for p in (results.get("ports") or []) if isinstance(p, dict)]


def _findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [f for f in (results.get("deterministic_findings") or []) if isinstance(f, dict)]


def _has_port(results: Dict[str, Any], port: int) -> bool:
    return any(int(p.get("port") or 0) == port for p in _ports(results))


def _service_version(results: Dict[str, Any], port: int) -> str:
    for p in _ports(results):
        if int(p.get("port") or 0) == port:
            return str(p.get("version") or p.get("banner") or p.get("service") or "observed")
    return "observed"


def _finding_by_code(results: Dict[str, Any], code: str) -> List[Dict[str, Any]]:
    return [f for f in _findings(results) if f.get("finding_code") == code]


def _dns_ptr(results: Dict[str, Any]) -> str:
    for row in (results.get("dns_record_enrichment") or {}).get("results") or []:
        if row.get("record_type") == "PTR" and row.get("records"):
            return ", ".join(map(str, row.get("records")[:3]))
    return ""


def _waf_signals(results: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for row in (results.get("web_fingerprinting") or {}).get("results") or []:
        for f in row.get("findings") or []:
            if isinstance(f, dict) and f.get("type") == "waf_signal":
                out.append(f"{row.get('url')}: {_short(f.get('summary'), 120)}")
    return out


def _whatweb_signals(results: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for row in (results.get("web_fingerprinting") or {}).get("results") or []:
        if row.get("tool") != "whatweb":
            continue
        for f in row.get("findings") or []:
            if isinstance(f, dict) and f.get("type") == "whatweb_fingerprint":
                out.append(f"{row.get('url')}: {_short(f.get('summary'), 130)}")
    return out


def _http_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("http_header_analysis") or {}).get("results") or [] if isinstance(r, dict)]


def _tls_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("tls_analysis") or {}).get("results") or [] if isinstance(r, dict)]


def _dir_scans(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [s for s in (results.get("web_content_discovery") or {}).get("directory_scans") or [] if isinstance(s, dict)]


def _screenshot_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [s for s in (results.get("screenshot_triage") or {}).get("results") or [] if isinstance(s, dict)]


def _ranked_paths(results: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
    rows: List[Tuple[str, str, str, str]] = []
    if _has_port(results, 22):
        rows.append(("SSH exposed", f"22/tcp - {_short(_service_version(results, 22), 80)}", "Validate auth policy, key-only enforcement, SSH hardening, and algorithm output.", "medium"))
    if _has_port(results, 80) or _has_port(results, 443):
        web_ports = ", ".join(str(p.get("port")) for p in _ports(results) if int(p.get("port") or 0) in (80, 443))
        rows.append(("Web surface exposed", f"ports {web_ports or '80/443'} - nginx/http observed", "Identify hostname/vhost/app context, then repeat content discovery and fingerprinting against hostnames.", "medium"))
    if _tls_rows(results):
        tls = _tls_rows(results)[0]
        protos = ", ".join(map(str, tls.get("supported_protocols") or [])) or "TLS sampled"
        rows.append(("TLS available", f"{tls.get('host')}:{tls.get('port')} - {protos}", "Confirm certificate metadata and cipher/protocol policy; current scan did not flag weak TLS signals.", "info"))
    ptr = _dns_ptr(results)
    if ptr:
        rows.append(("Cloud-hosted asset indicator", f"PTR - {ptr}", "Correlate the EC2 PTR with client asset inventory and scoped hostnames before deeper web testing.", "info"))
    if _finding_by_code(results, "BBR-COVERAGE-001"):
        rows.append(("Coverage limitation", "bare IP target", "Rerun against hostname/apex domain; subdomain, vhost, TLS/SNI, and web fingerprinting will be much better.", "info"))
    return rows[:6]


def render_triage_dashboard(results: Dict[str, Any]) -> None:
    target = results.get("target") or "target"
    summary = results.get("summary") or {}
    findings = _findings(results)
    console.print()
    console.print(Panel(Text.from_markup(f"[bold bright_white]{target}[/bold bright_white]\nVulnerability-triage view: likely paths forward, confirmed observations, and limiting signals."), title="[bold red]Blackbox Recon Triage[/bold red]", border_style="red", padding=(1, 2)))
    _render_triage_summary(summary, findings)
    _render_likely_paths(results)
    _render_attack_surface(results)
    _render_web_tls(results)
    _render_findings(results)
    _render_negative_limits(results)
    _render_artifacts(results)


def _render_triage_summary(summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    table = Table(title="Triage Snapshot", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Open ports", justify="right", style="bold yellow")
    table.add_column("Web", justify="right", style="bold yellow")
    table.add_column("Content hits", justify="right", style="bold yellow")
    table.add_column("TLS", justify="right", style="bold yellow")
    table.add_column("Findings", justify="right", style="bold yellow")
    table.add_column("Severity mix", style="bright_white")
    table.add_row(str(summary.get("total_open_ports", summary.get("open_tcp_ports", 0))), str(summary.get("http_services_detected", 0)), str(summary.get("interesting_paths_found", 0)), str(summary.get("tls_services_analyzed", 0)), str(len(findings)), ", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items())) or "none")
    console.print(table)


def _render_likely_paths(results: Dict[str, Any]) -> None:
    rows = _ranked_paths(results)
    if not rows:
        return
    table = Table(title="Likely Paths Forward", box=box.ROUNDED, header_style="bold red")
    table.add_column("Priority", justify="right", style="bold yellow", no_wrap=True)
    table.add_column("Path", style="bold white")
    table.add_column("Evidence", style="bright_white", overflow="fold")
    table.add_column("Next move", style="cyan", overflow="fold")
    for i, (path, evidence, next_move, sev) in enumerate(rows, start=1):
        table.add_row(str(i), f"[{_sev_style(sev)}]{path}[/]", evidence, next_move)
    console.print(table)


def _render_attack_surface(results: Dict[str, Any]) -> None:
    ports = _ports(results)
    if not ports:
        return
    table = Table(title="Confirmed Attack Surface", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Port", justify="right", style="bold yellow")
    table.add_column("Service", style="cyan")
    table.add_column("Observed version/banner", style="bright_white", overflow="fold")
    for p in ports[:12]:
        table.add_row(str(p.get("port") or ""), str(p.get("service") or "unknown"), _short(p.get("version") or p.get("banner") or "-", 130))
    console.print(table)


def _render_web_tls(results: Dict[str, Any]) -> None:
    table = Table(title="Web / TLS Observations", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Area", style="bold white", no_wrap=True)
    table.add_column("Observed result", style="bright_white", overflow="fold")
    scans = _dir_scans(results)
    if scans:
        hit_count = sum(len(s.get("findings_interesting") or []) for s in scans)
        statuses = ", ".join(f"{s.get('base_url')}={s.get('status')}" for s in scans[:3])
        table.add_row("Content discovery", f"{hit_count} interesting path(s); {statuses}")
    for row in _http_rows(results)[:3]:
        status = row.get("status_code") or "no status"
        title = row.get("title") or "no title"
        missing = ", ".join(map(str, row.get("missing_security_headers") or [])) or "no missing-header data"
        table.add_row("HTTP response", f"{row.get('url')} - {status} - {title} - {missing}")
    for row in _tls_rows(results)[:3]:
        protos = ", ".join(map(str, row.get("supported_protocols") or [])) or "protocols not parsed"
        weak = ", ".join(map(str, row.get("weak_signals") or [])) or "no weak signals recorded"
        table.add_row("TLS", f"{row.get('host')}:{row.get('port')} - {protos} - {weak}")
    whatweb = _whatweb_signals(results)
    if whatweb:
        for item in whatweb[:3]:
            table.add_row("WhatWeb", item)
    else:
        table.add_row("WhatWeb", "no useful fingerprint output recorded")
    waf = _waf_signals(results)
    if waf:
        for item in waf[:2]:
            table.add_row("WAF/CDN", item)
    else:
        table.add_row("WAF/CDN", "no confirmed WAF/CDN signal recorded")
    console.print(table)


def _render_findings(results: Dict[str, Any]) -> None:
    findings = _findings(results)
    actionable = [f for f in findings if f.get("severity") in ("critical", "high", "medium", "low")]
    if not actionable:
        actionable = findings[:6]
    table = Table(title="Finding Signals", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Code", style="bold yellow", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Evidence", justify="right", style="dim")
    table.add_column("Finding", style="bright_white", overflow="fold")
    for f in actionable[:8]:
        sev = str(f.get("severity") or "")
        table.add_row(str(f.get("finding_code") or "-"), f"[{_sev_style(sev)}]{sev}[/]", str(f.get("status") or ""), str(len(f.get("evidence_ids") or [])), _short(f.get("title"), 120))
    console.print(table)


def _render_negative_limits(results: Dict[str, Any]) -> None:
    notes: List[str] = []
    if not (results.get("subdomains") or []):
        notes.append("No subdomains discovered; expected for bare IP targets.")
    if _dir_scans(results) and sum(len(s.get("findings_interesting") or []) for s in _dir_scans(results)) == 0:
        notes.append("Gobuster completed but found 0 flagged interesting paths.")
    if not _whatweb_signals(results):
        notes.append("WhatWeb produced no useful fingerprint signal for this target.")
    if not _waf_signals(results):
        notes.append("WAFW00F produced no confirmed WAF/CDN signal after banner/noise filtering.")
    if any(s.get("status") == "skipped" for s in _screenshot_rows(results)):
        notes.append("Screenshots skipped because gowitness is not installed or unavailable.")
    if _finding_by_code(results, "BBR-COVERAGE-001"):
        notes.append("Bare IP limits vhost/SNI/subdomain discovery; hostname scope is needed for better web recon.")
    if not notes:
        return
    table = Table(title="Negative / Limiting Signals", box=box.ROUNDED, header_style="bold yellow")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Signal", style="bright_white", overflow="fold")
    for i, note in enumerate(notes[:8], start=1):
        table.add_row(str(i), note)
    console.print(table)


def _render_artifacts(results: Dict[str, Any]) -> None:
    rows: List[Tuple[str, str]] = []
    ptr = _dns_ptr(results)
    if ptr:
        rows.append(("PTR", ptr))
    for row in _screenshot_rows(results):
        if row.get("screenshot_path"):
            rows.append(("screenshot", row.get("screenshot_path")))
    if not rows:
        return
    table = Table(title="Artifacts / Correlation Data", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="bright_white", overflow="fold")
    for k, v in rows[:8]:
        table.add_row(k, _short(v, 150))
    console.print(table)
