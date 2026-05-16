"""Service-centric terminal output for Blackbox Recon.

The dashboard intentionally separates evidence, interpretation, negative results,
verification targets, and artifacts. Raw tool output belongs in artifacts/JSON,
not the normal operator terminal.
"""

from __future__ import annotations

from typing import Any, Dict, List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .service_assessment import build_service_assessments

console = Console()


def _short(value: Any, n: int = 120) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _ports(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [p for p in (results.get("ports") or []) if isinstance(p, dict)]


def _display_service(port: int, svc: str) -> str:
    svc_l = str(svc or "unknown").lower()
    if port in (443, 8443) and svc_l in ("http", "ssl/http", "unknown"):
        return "https"
    return svc_l


def _exposure_label(port: int, svc: str) -> str:
    svc_l = str(svc or "").lower()
    if port == 22 or svc_l == "ssh":
        return "Remote admin"
    if port in (443, 8443) or "https" in svc_l or "ssl" in svc_l:
        return "Web/TLS"
    if port in (80, 8080, 8000, 8888) or svc_l.startswith("http"):
        return "Web"
    return "Network service"


def _service_sort_key(row: Dict[str, Any]) -> tuple:
    order = {"SSH": 10, "HTTP": 20, "HTTPS": 21, "SMB": 30, "FTP": 40, "SMTP": 50, "RDP": 60}
    return (order.get(str(row.get("service")), 99), int(row.get("port") or 0))


def _sev_style(sev: str) -> str:
    sev = (sev or "").lower()
    if sev in ("critical", "high"):
        return "bold red"
    if sev == "medium":
        return "bold yellow"
    if sev == "low":
        return "cyan"
    return "dim cyan"


def render_triage_dashboard(results: Dict[str, Any]) -> None:
    assessment = build_service_assessments(results)
    target = assessment.get("target") or results.get("target") or "target"

    console.print()
    console.print(
        Panel(
            Text.from_markup(
                f"[bold bright_white]{target}[/bold bright_white]\n"
                "Service-first recon triage. Findings are evidence-bound; raw tool output is stored as artifacts."
            ),
            title="[bold #b45309]Blackbox Recon · Operator Assessment[/bold #b45309]",
            border_style="#b45309",
            padding=(1, 2),
        )
    )
    _render_scope(assessment)
    _render_snapshot(assessment, results)
    _render_attack_surface(results)
    _render_service_assessments(assessment)
    _render_candidate_findings(assessment)
    _render_negative_results(assessment)
    _render_verification_targets(assessment)
    _render_artifacts(assessment)
    _render_tester_takeaway(assessment)


def _render_scope(assessment: Dict[str, Any]) -> None:
    limitations = assessment.get("limitations") or []
    table = Table(title="Scope & Limitations", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Target", style="bold white")
    table.add_column("Type", style="cyan")
    table.add_column("Material limitations", style="bright_white", overflow="fold")
    table.add_row(str(assessment.get("target") or ""), str(assessment.get("target_type") or "unknown"), "\n".join(f"- {x}" for x in limitations) or "none observed")
    console.print(table)


def _render_snapshot(assessment: Dict[str, Any], results: Dict[str, Any]) -> None:
    summary = results.get("summary") or {}
    a_sum = assessment.get("summary") or {}
    table = Table(title="Executive Recon Snapshot", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Services", justify="right", style="bold yellow")
    table.add_column("Open ports", justify="right", style="bold yellow")
    table.add_column("Web", justify="right", style="bold yellow")
    table.add_column("Content hits", justify="right", style="bold yellow")
    table.add_column("Candidate findings", justify="right", style="bold yellow")
    table.add_column("Artifacts", justify="right", style="bold yellow")
    table.add_row(str(a_sum.get("services", 0)), str(summary.get("total_open_ports", summary.get("open_tcp_ports", len(_ports(results))))), str(summary.get("http_services_detected", 0)), str(summary.get("interesting_paths_found", 0)), str(a_sum.get("candidate_findings", 0)), str(a_sum.get("artifacts", 0)))
    console.print(table)


def _render_attack_surface(results: Dict[str, Any]) -> None:
    ports = _ports(results)
    if not ports:
        return
    table = Table(title="Attack Surface", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Host", style="white", no_wrap=True)
    table.add_column("Port", justify="right", style="bold yellow", no_wrap=True)
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Version / banner", style="bright_white", overflow="fold")
    table.add_column("Exposure", style="yellow", overflow="fold")
    for p in ports[:30]:
        port = int(p.get("port") or 0)
        svc = str(p.get("service") or "unknown")
        table.add_row(str(p.get("host") or ""), str(port), _display_service(port, svc), _short(p.get("version") or p.get("banner") or "-", 130), _exposure_label(port, svc))
    console.print(table)


def _render_service_assessments(assessment: Dict[str, Any]) -> None:
    rows = sorted(assessment.get("assessments") or [], key=_service_sort_key)
    if not rows:
        return
    console.print("\n[bold cyan][+] Service Assessments[/bold cyan]")
    for svc in rows:
        body = Text()
        observed = svc.get("observed") or []
        negatives = svc.get("negative_results") or []
        notes = svc.get("operator_notes") or []
        candidates = svc.get("candidate_findings") or []
        if observed:
            body.append("Observed:\n", style="bold bright_white")
            for item in observed[:5]:
                body.append(f"  - {_short(item, 180)}\n", style="bright_white")
        if candidates:
            body.append("Candidate findings:\n", style="bold yellow")
            for item in candidates[:4]:
                body.append(f"  - {_short(item.get('title'), 120)}: {_short(item.get('evidence'), 160)}\n", style="yellow")
        if negatives:
            body.append("Negative / inconclusive results:\n", style="bold dim")
            for item in negatives[:4]:
                body.append(f"  - {_short(item, 180)}\n", style="dim")
        if notes:
            body.append("Operator interpretation:\n", style="bold cyan")
            for item in notes[:3]:
                body.append(f"  - {_short(item, 180)}\n", style="cyan")
        title = f"{svc.get('service')} · {svc.get('host')}:{svc.get('port')}"
        border = "yellow" if candidates else "cyan"
        console.print(Panel(body, title=f"[bold white]{title}[/bold white]", border_style=border, padding=(1, 2)))


def _render_candidate_findings(assessment: Dict[str, Any]) -> None:
    rows = assessment.get("candidate_findings") or []
    if not rows:
        console.print(Panel("No candidate or confirmed service findings from current evidence.", title="[bold green]Service Findings[/bold green]", border_style="green", padding=(1, 2)))
        return
    table = Table(title="Candidate Findings", box=box.ROUNDED, header_style="bold yellow")
    table.add_column("Service", no_wrap=True, style="bold white")
    table.add_column("Asset", no_wrap=True, style="cyan")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Signal", style="bright_white", overflow="fold")
    table.add_column("Evidence", style="yellow", overflow="fold")
    for row in rows[:12]:
        sev = str(row.get("severity") or "candidate")
        table.add_row(str(row.get("service") or ""), str(row.get("asset") or ""), f"[{_sev_style(sev)}]{sev}[/]", _short(row.get("title"), 100), _short(row.get("evidence"), 160))
    console.print(table)


def _compress_negative_results(rows: List[str]) -> List[str]:
    if not rows:
        return []
    buckets: List[str] = []
    joined = "\n".join(rows).lower()
    if "weak ssh" in joined:
        buckets.append("SSH: no weak SSH algorithm signal confirmed from parsed evidence.")
    if "interesting paths" in joined:
        buckets.append("HTTP/S: content discovery completed with 0 interesting paths across tested web services.")
    if "weak tls" in joined:
        buckets.append("TLS: no weak TLS protocol/cipher signal extracted by current parser/tool output.")
    if not buckets:
        buckets = rows[:5]
    return buckets


def _render_negative_results(assessment: Dict[str, Any]) -> None:
    rows = _compress_negative_results(assessment.get("negative_results") or [])
    if not rows:
        return
    table = Table(title="Negative / Inconclusive Summary", box=box.ROUNDED, header_style="bold dim")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Summary", style="bright_white", overflow="fold")
    for idx, item in enumerate(rows[:6], start=1):
        table.add_row(str(idx), _short(item, 220))
    console.print(table)


def _render_verification_targets(assessment: Dict[str, Any]) -> None:
    rows = assessment.get("verification_targets") or []
    if not rows:
        return
    table = Table(title="Technical Verification Targets", box=box.ROUNDED, header_style="bold red")
    table.add_column("Priority", justify="right", style="bold yellow", no_wrap=True)
    table.add_column("Service", style="bold white", no_wrap=True)
    table.add_column("Asset", style="cyan", no_wrap=True)
    table.add_column("Action", style="bright_white", overflow="fold")
    for idx, row in enumerate(rows[:10], start=1):
        table.add_row(str(idx), str(row.get("service") or ""), str(row.get("asset") or ""), _short(row.get("action"), 220))
    console.print(table)


def _render_artifacts(assessment: Dict[str, Any]) -> None:
    artifacts = assessment.get("artifacts") or []
    if not artifacts:
        return
    table = Table(title="Evidence Artifacts", box=box.SIMPLE, header_style="bold cyan")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Path", style="bright_white", overflow="fold")
    for idx, path in enumerate(artifacts[:8], start=1):
        table.add_row(str(idx), _short(path, 220))
    if len(artifacts) > 8:
        table.add_row("…", f"+{len(artifacts) - 8} more artifact(s) in JSON report")
    console.print(table)


def _render_tester_takeaway(assessment: Dict[str, Any]) -> None:
    bullets: List[str] = []
    if assessment.get("target_type") == "bare_ip":
        bullets.append("Highest-value next move: obtain scoped hostname/FQDN and rerun web + TLS recon with Host/SNI context.")
    if not assessment.get("candidate_findings"):
        bullets.append("No confirmed or candidate service vulnerability was identified from parsed evidence; preserve this as recon status, not a finding.")
    ssh = [a for a in assessment.get("assessments") or [] if a.get("service") == "SSH"]
    if ssh:
        bullets.append("SSH remains a remote administration surface; validate authentication policy and crypto baseline before writing any finding.")
    if not bullets:
        return
    text = Text()
    for item in bullets[:5]:
        text.append(f"- {_short(item, 190)}\n", style="bright_white")
    console.print(Panel(text, title="[bold green]Tester Takeaway[/bold green]", border_style="green", padding=(1, 2)))
