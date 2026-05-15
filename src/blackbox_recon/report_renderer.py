"""Deterministic Markdown technical reports from evidence (no LLM as source of truth)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _md_cell(text: str, max_len: int = 220) -> str:
    t = (text or "").replace("|", "\\|").replace("\n", " ").replace("\r", "")
    return (t[: max_len - 3] + "...") if len(t) > max_len else t


def _ensure_evidence_bundle(results: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return ``(package, evidence, findings, paths)``, building the package on demand for legacy JSON."""
    pkg = results.get("evidence_package")
    if not isinstance(pkg, dict) or not pkg:
        from .evidence import build_evidence_package

        eng = results.get("engagement") or {}
        mods = list(eng.get("modules_requested") or ["subdomain", "portscan", "technology"])
        lab_mode = not bool(eng.get("record"))
        pkg = build_evidence_package(results, mods, lab_mode=lab_mode)
    evidence = list(pkg.get("evidence") or [])
    findings = list(pkg.get("deterministic_findings") or [])
    paths = list(pkg.get("deterministic_attack_paths") or [])
    return pkg, evidence, findings, paths


def _priority_from_severity(sev: str) -> str:
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return "P1"
    if s == "medium":
        return "P2"
    return "P3"


def render_technical_assessment_markdown(results: Dict[str, Any]) -> str:
    """
    Render the client-facing **technical assessment** body from structured evidence.

    This output is deterministic Python; it does not depend on LLM prose.
    """
    pkg, evidence, findings, paths = _ensure_evidence_bundle(results)
    assessment = pkg.get("assessment") or {}
    summary = results.get("summary") or {}
    snap = results.get("executive_snapshot") or {}
    target = str(results.get("target") or "")
    cov = list(pkg.get("coverage_notes") or [])

    lines: List[str] = []
    lines.append("## Technical assessment (evidence-backed)\n")
    lines.append(
        "*This section is generated deterministically from normalized scan output. "
        "It is the authoritative factual summary for this run.*\n"
    )

    # Scope and methodology
    lines.append("### Scope and methodology\n")
    lines.append("| Field | Value |\n")
    lines.append("| --- | --- |\n")
    lines.append(f"| **Target** | `{_md_cell(target, 80)}` |\n")
    lines.append(f"| **Assessment mode** | {_md_cell(str(assessment.get('mode', '—')))} |\n")
    lines.append(f"| **Authorization context** | {_md_cell(str(assessment.get('authorization_context', '—')), 120)} |\n")
    mods = assessment.get("modules_executed") or (results.get("engagement") or {}).get("modules_requested") or []
    lines.append(f"| **Modules executed** | {_md_cell(', '.join(str(m) for m in mods), 120)} |\n")
    lines.append(f"| **Recon started (UTC)** | `{assessment.get('recon_started_utc') or results.get('recon_started_utc', '—')}` |\n")
    lines.append(f"| **Recon completed (UTC)** | `{assessment.get('recon_completed_utc') or results.get('recon_completed_utc', '—')}` |\n")
    sm = assessment.get("summary_metrics") or {}
    lines.append(f"| **Open TCP ports** | {sm.get('open_tcp_ports', summary.get('total_open_ports', 0))} |\n")
    lines.append(f"| **HTTP(S) services (from ports)** | {sm.get('http_services_detected', summary.get('http_services_detected', 0))} |\n")
    lines.append(
        f"| **Subdomain HTTP probes w/ status** | "
        f"{sm.get('subdomain_http_probes_with_status', summary.get('subdomain_http_probes_with_status', 0))} |\n"
    )
    lines.append(
        f"| **HTTP URLs targeted** | {sm.get('http_urls_targeted', summary.get('http_urls_targeted', 0))} |\n"
    )
    lines.append(
        f"| **Technology profiles stored** | "
        f"{sm.get('technology_profiles_stored', summary.get('technology_profiles_stored', 0))} |\n"
    )
    lines.append("\n")

    # Executive summary (deterministic)
    lines.append("### Executive summary\n")
    nports = int(summary.get("open_tcp_ports", summary.get("total_open_ports", 0)) or 0)
    http_n = int(summary.get("http_services_detected", 0) or 0)
    dir_hits = int(summary.get("directory_interesting_hits", 0) or 0)
    para = [
        f"Reconnaissance for `{_md_cell(target, 60)}` recorded **{nports}** open TCP port(s) "
        f"and **{http_n}** HTTP/HTTPS-oriented listener(s) inferred from port/service mapping.",
    ]
    if dir_hits:
        para.append(f"Web directory discovery flagged **{dir_hits}** interesting path(s) under the configured wordlist and scope.")
    else:
        para.append(
            "Web directory discovery did not flag interesting paths under the configured wordlist for the URLs exercised."
        )
    para.append(
        "No exploit validation or authenticated application testing was performed as part of this recon pass unless "
        "otherwise noted in engagement parameters."
    )
    if cov:
        para.append("**Coverage notes:** " + " ".join(_md_cell(c, 300) for c in cov[:5]))
    lines.append(" ".join(para) + "\n\n")

    # Attack surface from evidence (port / service)
    port_ev = [
        e
        for e in evidence
        if e.get("phase_id") == "M3" and e.get("observation_type") in ("open_port", "service_banner")
    ]
    lines.append("### Confirmed attack surface (from tool observations)\n")
    if port_ev:
        lines.append("| Asset | Service / product | Version | Evidence ID | Confidence |\n")
        lines.append("| --- | --- | --- | --- | --- |\n")
        for e in port_ev[:40]:
            ov = e.get("observed_value") or {}
            lines.append(
                f"| `{_md_cell(e.get('asset', ''), 40)}` | "
                f"{_md_cell(str(ov.get('service') or '—'), 24)} | "
                f"{_md_cell(str(ov.get('version') or '—'), 40)} | "
                f"`{e.get('id', '')}` | {e.get('confidence', 'medium')} |\n"
            )
        if len(port_ev) > 40:
            lines.append(f"\n*({len(port_ev) - 40} additional port observation(s) omitted; see full `evidence` in JSON.)*\n")
    else:
        lines.append("*No open-port evidence rows were recorded in this bundle.*\n")
    lines.append("\n")

    # Key findings
    lines.append("### Key findings\n")
    if findings:
        lines.append(
            "| ID | Code | Severity | Status | Title | Evidence IDs | Impact (abridged) | Recommendation (abridged) |\n"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
        for f in findings[:30]:
            eids = ", ".join(f.get("evidence_ids") or [])
            if len(eids) > 48:
                eids = eids[:45] + "…"
            lines.append(
                f"| `{f.get('id', '')}` | `{_md_cell(str(f.get('finding_code') or ''), 14)}` | "
                f"{f.get('severity', '')} | {f.get('status', '')} | "
                f"{_md_cell(str(f.get('title', '')), 48)} | `{_md_cell(eids, 52)}` | "
                f"{_md_cell(str(f.get('impact', '')), 56)} | {_md_cell(str(f.get('recommendation', '')), 56)} |\n"
            )
        lines.append("\n")
    else:
        lines.append("*No deterministic findings were produced (insufficient structured observations).*\n\n")

    # CVE assessment
    lines.append("### CVE assessment\n")
    lines.append(
        "**No CVE is stated as confirmed** unless scan output explicitly names a CVE ID tied to an observed "
        "product/version. For this run, correlation was limited to banners and service names captured in evidence; "
        "where versions are missing, CVE mapping is intentionally conservative.\n\n"
    )

    # Attack paths
    lines.append("### Plausible attack paths (high-level, defensive framing)\n")
    if paths:
        for i, p in enumerate(paths, 1):
            lines.append(f"**Path {i}**\n")
            lines.append(f"- **Entry point:** {_md_cell(str(p.get('entry_point', '')), 200)}\n")
            lines.append(f"- **Risk chain:** {_md_cell(str(p.get('risk_chain', '')), 280)}\n")
            lines.append(f"- **Potential impact:** {_md_cell(str(p.get('potential_impact', '')), 220)}\n")
            lines.append(f"- **Defensive priority:** `{p.get('defensive_priority', '—')}` | **Evidence:** `{_md_cell(', '.join(p.get('evidence_ids') or []), 80)}`\n\n")
    else:
        lines.append("*No derived attack-path narratives were generated (no qualifying exposure findings).*\n\n")

    # Remediations table
    lines.append("### Recommended remediations (from findings)\n")
    if findings:
        lines.append("| Priority | Finding | Action | Validation |\n")
        lines.append("| --- | --- | --- | --- |\n")
        for f in findings[:25]:
            pr = _priority_from_severity(str(f.get("severity", "")))
            lines.append(
                f"| {pr} | {_md_cell(str(f.get('title', '')), 44)} | "
                f"{_md_cell(str(f.get('recommendation', '')), 72)} | "
                f"{_md_cell(str(f.get('validation', '')), 72)} |\n"
            )
        lines.append("\n")
    else:
        lines.append("*No remediation rows (no findings).* \n\n")

    # Limitations
    lines.append("### Assessment limitations\n")
    if snap.get("dns_names_observed"):
        lines.append(
            f"- **DNS names observed (snapshot):** {', '.join(_md_cell(n, 80) for n in snap['dns_names_observed'][:10])}\n"
        )
    for c in cov:
        lines.append(f"- {_md_cell(c, 400)}\n")
    lines.append(
        "- **Unauthenticated perspective:** internal-only or credentialed issues may not be visible.\n"
        "- **Timing and rate limits:** results reflect a single pass under configured timeouts and thread counts.\n\n"
    )

    # Evidence index (compact)
    lines.append("### Evidence index (compact)\n")
    if evidence:
        lines.append("| ID | Phase | Type | Asset | Source |\n")
        lines.append("| --- | --- | --- | --- | --- |\n")
        for e in evidence[:60]:
            lines.append(
                f"| `{e.get('id', '')}` | {e.get('phase_id', '')} | {e.get('observation_type', '')} | "
                f"{_md_cell(str(e.get('asset', '')), 36)} | {_md_cell(str(e.get('source_tool', '')), 28)} |\n"
            )
        if len(evidence) > 60:
            lines.append(f"\n*({len(evidence) - 60} more evidence row(s) in JSON `evidence_package.evidence`.)*\n")
    else:
        lines.append("*No evidence rows.*\n")

    return "".join(lines)
