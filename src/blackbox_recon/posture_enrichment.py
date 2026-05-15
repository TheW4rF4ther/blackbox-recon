"""Post-scan posture and service enrichment hook for ReconEngine.

This module wires M6/M7/M8 style enrichment into the existing run loop without
changing the scanner's core phases. It is intentionally observational: it runs
HTTP header sampling, TLS posture sampling, and service-specific enumeration
only against services discovered by the current run, then refreshes the evidence
package and deterministic findings.
"""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Any, Dict, Iterable, List

from rich import print as rprint
from rich.markup import escape

from .evidence import build_evidence_package
from .http_headers import HttpHeaderAnalyzer
from .reporting import build_executive_snapshot, utc_now_iso
from .service_enum import run_service_enumeration
from .tls_scan import scan_tls_url


def _dedupe(seq: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in seq:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _trace_append(
    results: Dict[str, Any],
    *,
    phase_id: str,
    phase_name: str,
    status: str,
    detail: str,
    stack_lines: List[str],
    commands: List[Dict[str, Any]],
) -> None:
    results.setdefault("recon_phase_trace", []).append(
        {
            "phase_id": phase_id,
            "phase_name": phase_name,
            "status": status,
            "detail": detail,
            "stack_lines": stack_lines,
            "commands_executed": commands,
        }
    )


def _host_from_url(url: str) -> str:
    u = url.replace("http://", "").replace("https://", "")
    return u.split("/", 1)[0].split(":", 1)[0].strip().lower()


def _web_urls_from_results(results: Dict[str, Any], engine: Any) -> List[str]:
    web = results.get("web_content_discovery") or {}
    urls = list(web.get("urls_targeted") or [])
    if not urls:
        try:
            from .recon import web_urls_from_port_rows

            urls = web_urls_from_port_rows(results.get("ports") or [])
        except Exception:
            urls = []
    if getattr(engine, "_rt", None) is not None:
        urls = [u for u in urls if engine._host_allowed_for_active_scan(_host_from_url(u))]
    max_urls = int(getattr(engine, "config", {}).get("directory_max_urls", 6) or 6)
    return _dedupe(urls)[:max_urls]


async def _run_http_header_enrichment(engine: Any, results: Dict[str, Any], urls: List[str]) -> None:
    if not bool(getattr(engine, "config", {}).get("http_headers_enabled", True)):
        _trace_append(results, phase_id="M6", phase_name="HTTP security header posture", status="skipped", detail="http_headers_enabled is false", stack_lines=["Stack: Python requests header sampling"], commands=[])
        return

    rprint("\n────────────────────────────────────────────────────────────────────────")
    rprint("  PTES M6 · HTTP security header posture")
    rprint("  Vulnerability Analysis › Web application hardening review")
    rprint("────────────────────────────────────────────────────────────────────────")
    rprint("    · Objective: Sample discovered HTTP(S) services for security headers, disclosure headers, cookies, redirects, and titles.")
    rprint("    · Stack: Python requests (GET, redirects enabled, TLS verification disabled for lab/authorized testing)")

    if not urls:
        results["http_header_analysis"] = {"results": []}
        _trace_append(results, phase_id="M6", phase_name="HTTP security header posture", status="completed", detail="No HTTP(S) URLs available for header analysis", stack_lines=["Stack: Python requests header sampling"], commands=[])
        rprint("  → Phase complete (completed): 0 URL(s) analyzed")
        return

    timeout = int(getattr(engine, "config", {}).get("http_headers_timeout_sec", 10) or 10)
    analyzer = HttpHeaderAnalyzer(timeout=timeout)
    loop = asyncio.get_running_loop()
    commands: List[Dict[str, Any]] = []
    out: List[Dict[str, Any]] = []
    for url in urls:
        rprint(f"     requests_headers: GET {escape(url)} timeout={timeout} verify=False allow_redirects=True")
        row = await loop.run_in_executor(None, partial(analyzer.analyze, url))
        out.append(row)
        commands.append({"label": "requests_headers", "command": f"GET {url} timeout={timeout} verify=False allow_redirects=True", "url": url, "status": row.get("status_code"), "error": row.get("error")})
    results["http_header_analysis"] = {"results": out}
    _trace_append(results, phase_id="M6", phase_name="HTTP security header posture", status="completed", detail=f"{len(out)} HTTP(S) URL(s) analyzed for security/disclosure headers", stack_lines=["Stack: Python requests header sampling"], commands=commands)
    rprint(f"  → Phase complete (completed): {len(out)} URL(s) analyzed")


async def _run_tls_enrichment(engine: Any, results: Dict[str, Any], urls: List[str]) -> None:
    if not bool(getattr(engine, "config", {}).get("tls_scan_enabled", True)):
        _trace_append(results, phase_id="M7", phase_name="TLS posture sampling", status="skipped", detail="tls_scan_enabled is false", stack_lines=["Stack: sslscan when available; Python ssl fallback"], commands=[])
        return

    https_urls = [u for u in urls if u.lower().startswith("https://")]
    rprint("\n────────────────────────────────────────────────────────────────────────")
    rprint("  PTES M7 · TLS posture sampling")
    rprint("  Vulnerability Analysis › Transport security review")
    rprint("────────────────────────────────────────────────────────────────────────")
    rprint("    · Objective: Sample HTTPS services for certificate metadata, protocol support, and weak TLS signals.")
    rprint("    · Stack: sslscan when installed; Python ssl certificate fallback")

    if not https_urls:
        results["tls_analysis"] = {"results": []}
        _trace_append(results, phase_id="M7", phase_name="TLS posture sampling", status="completed", detail="No HTTPS URLs available for TLS sampling", stack_lines=["Stack: sslscan when available; Python ssl fallback"], commands=[])
        rprint("  → Phase complete (completed): 0 HTTPS service(s) analyzed")
        return

    timeout = int(getattr(engine, "config", {}).get("tls_scan_timeout_sec", 60) or 60)
    loop = asyncio.get_running_loop()
    commands: List[Dict[str, Any]] = []
    out: List[Dict[str, Any]] = []
    for url in https_urls:
        row = await loop.run_in_executor(None, partial(scan_tls_url, url, timeout_sec=timeout))
        if row:
            out.append(row)
            cmd = row.get("command") or f"python_ssl_cert_probe {row.get('host')}:{row.get('port')}"
            rprint(f"     tls_probe: {escape(cmd)}")
            commands.append({"label": row.get("tool") or "tls_scan", "command": cmd, "url": url, "status": row.get("status"), "weak_signals": row.get("weak_signals") or []})
    results["tls_analysis"] = {"results": out}
    _trace_append(results, phase_id="M7", phase_name="TLS posture sampling", status="completed", detail=f"{len(out)} HTTPS service(s) analyzed for TLS posture", stack_lines=["Stack: sslscan when available; Python ssl fallback"], commands=commands)
    rprint(f"  → Phase complete (completed): {len(out)} HTTPS service(s) analyzed")


async def _run_service_enrichment(engine: Any, results: Dict[str, Any]) -> None:
    if not bool(getattr(engine, "config", {}).get("service_enum_enabled", True)):
        _trace_append(results, phase_id="M8", phase_name="Service-specific enumeration", status="skipped", detail="service_enum_enabled is false", stack_lines=["Stack: service-aware safe enumeration dispatcher"], commands=[])
        return

    rprint("\n────────────────────────────────────────────────────────────────────────")
    rprint("  PTES M8 · Service-specific enumeration")
    rprint("  Vulnerability Analysis › Service-aware safe enumeration")
    rprint("────────────────────────────────────────────────────────────────────────")
    rprint("    · Objective: Run safe, focused enumeration modules only for services already confirmed open.")
    rprint("    · Stack: nmap NSE where appropriate, smbclient, Python ftplib/socket helpers")

    port_rows = results.get("ports") or []
    timeout = int(getattr(engine, "config", {}).get("service_enum_timeout_sec", 60) or 60)
    max_services = int(getattr(engine, "config", {}).get("service_enum_max_services", 24) or 24)
    loop = asyncio.get_running_loop()
    enum = await loop.run_in_executor(None, partial(run_service_enumeration, port_rows, timeout_sec=timeout, max_services=max_services))
    results["service_enumeration"] = enum

    commands: List[Dict[str, Any]] = []
    for row in enum.get("results") or []:
        cmd = row.get("command") or row.get("module") or "service_enum"
        rprint(f"     {escape(str(row.get('module') or 'service_enum'))}: {escape(str(cmd))}")
        commands.append({"label": row.get("module") or "service_enum", "command": cmd, "host": row.get("host"), "port": row.get("port"), "status": row.get("status"), "findings": len(row.get("findings") or [])})

    _trace_append(results, phase_id="M8", phase_name="Service-specific enumeration", status="completed", detail=f"{enum.get('modules_run', 0)} service module(s) run across {enum.get('services_considered', 0)} open service(s)", stack_lines=["Stack: service-aware safe enumeration dispatcher"], commands=commands)
    rprint(f"  → Phase complete (completed): {enum.get('modules_run', 0)} service module(s) run")


def _service_findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    rows = (results.get("service_enumeration") or {}).get("results") or []
    idx = len(results.get("deterministic_findings") or []) + 1

    def _add(code: str, title: str, severity: str, asset: str, evidence_ref: str, impact: str, recommendation: str, validation: str, confidence: str = "medium") -> None:
        nonlocal idx
        out.append({"id": f"DET-FIND-{idx:03d}", "finding_code": code, "title": title, "severity": severity, "status": "confirmed", "affected_assets": [asset], "evidence_ids": [evidence_ref], "impact": impact, "recommendation": recommendation, "validation": validation, "confidence": confidence})
        idx += 1

    for i, row in enumerate(rows):
        asset = f"{row.get('host')}:{row.get('port')}/tcp"
        evidence_ref = f"SERVICE-ENUM-{i+1:03d}"
        ftypes = {f.get("type") for f in (row.get("findings") or []) if isinstance(f, dict)}
        if "ftp_anonymous_login_allowed" in ftypes:
            _add("BBR-FTP-001", "FTP anonymous login allowed", "high", asset, evidence_ref, "Anonymous FTP access may expose files or allow unauthorized staging depending on permissions.", "Disable anonymous FTP unless explicitly required; restrict writable directories and review exposed content.", "Re-run FTP anonymous login check and confirm access is denied or tightly restricted.", "high")
        if "smb_anonymous_share_listing" in ftypes:
            _add("BBR-SMB-001", "SMB anonymous share listing observed", "medium", asset, evidence_ref, "Anonymous SMB share enumeration can disclose share names and guide follow-on access attempts.", "Disable null-session share listing and restrict SMB exposure to trusted networks/VPN.", "Re-run smbclient anonymous listing and confirm shares are not disclosed.", "high")
        if "weak_ssh_algorithm_signal" in ftypes:
            _add("BBR-SSH-001", "Weak SSH algorithm signal observed", "medium", asset, evidence_ref, "Legacy SSH algorithms can weaken cryptographic posture and may enable downgrade or compatibility risks.", "Disable legacy SSH KEX, host-key, cipher, and MAC algorithms according to current hardening guidance.", "Re-run ssh2-enum-algos and confirm weak algorithms are absent.", "medium")
        if "smtp_starttls_offered" in ftypes:
            _add("BBR-SMTP-INFO-001", "SMTP STARTTLS capability observed", "informational", asset, evidence_ref, "SMTP service advertises STARTTLS, which should be validated for certificate and protocol strength.", "Review SMTP TLS posture and mail relay configuration under authorized scope.", "Confirm STARTTLS configuration aligns with organizational mail security requirements.", "medium")
        elif "smtp_ehlo_capabilities" in ftypes:
            _add("BBR-SMTP-INFO-002", "SMTP service capabilities observed", "informational", asset, evidence_ref, "SMTP EHLO capabilities provide service metadata for defensive inventory and hardening review.", "Review exposed SMTP service role, relay policy, and STARTTLS availability.", "Confirm SMTP exposure is required and restricted appropriately.", "medium")
        if "rdp_encryption_metadata" in ftypes or "rdp_security_protocol_metadata" in ftypes:
            _add("BBR-RDP-INFO-001", "RDP encryption metadata observed", "informational", asset, evidence_ref, "RDP security metadata was captured for follow-up hardening review.", "Confirm Network Level Authentication and strong TLS settings are required for exposed RDP services.", "Re-run RDP encryption enumeration and verify expected controls.", "medium")
        if "service_banner" in ftypes:
            _add("BBR-SVC-BANNER-001", "Service banner captured", "informational", asset, evidence_ref, "Banners can aid asset inventory and may disclose product details to unauthenticated users.", "Review whether banner disclosure is necessary and whether service versions are current.", "Re-run banner collection and confirm expected disclosure level.", "medium")
    return out


def _refresh_summary_and_evidence(engine: Any, results: Dict[str, Any], modules: List[str]) -> None:
    summary = results.setdefault("summary", {})
    summary["http_header_urls_analyzed"] = len((results.get("http_header_analysis") or {}).get("results") or [])
    summary["tls_services_analyzed"] = len((results.get("tls_analysis") or {}).get("results") or [])
    summary["service_enum_modules_run"] = int((results.get("service_enumeration") or {}).get("modules_run") or 0)

    modules_executed = list(dict.fromkeys(list(modules) + ["http_headers", "tls", "service_enum"]))
    results["evidence_package"] = build_evidence_package(results, modules_executed, lab_mode=getattr(engine, "_rt", None) is None)
    base_findings = list(results["evidence_package"].get("deterministic_findings", []))
    svc_findings = _service_findings(results)
    findings = base_findings + svc_findings
    results["deterministic_findings"] = findings
    results["evidence_package"]["deterministic_findings"] = findings
    results["evidence_package"].setdefault("service_enumeration", results.get("service_enumeration") or {})
    results["deterministic_attack_paths"] = results["evidence_package"].get("deterministic_attack_paths", [])
    results["recon_completed_utc"] = utc_now_iso()
    results["executive_snapshot"] = build_executive_snapshot(results)


async def _posture_enriched_run(engine: Any, original_run: Any, target: str, modules: List[str]) -> Dict[str, Any]:
    results = await original_run(target, modules)
    if "portscan" not in modules:
        return results
    urls = _web_urls_from_results(results, engine)
    await _run_http_header_enrichment(engine, results, urls)
    await _run_tls_enrichment(engine, results, urls)
    await _run_service_enrichment(engine, results)
    _refresh_summary_and_evidence(engine, results, modules)
    rprint("\n[bold green][+][/bold green] Service and web posture enrichment complete")
    rprint(f"    [yellow]HTTP header URLs:[/yellow] [white]{results['summary'].get('http_header_urls_analyzed', 0)}[/white]  [yellow]TLS services:[/yellow] [white]{results['summary'].get('tls_services_analyzed', 0)}[/white]  [yellow]Service modules:[/yellow] [white]{results['summary'].get('service_enum_modules_run', 0)}[/white]")
    return results


def patch_recon_engine(ReconEngine: Any) -> None:
    """Patch ReconEngine.run once so M6/M7/M8 execute after the core run."""
    if getattr(ReconEngine, "_blackbox_posture_enrichment_patched", False):
        return
    original_run = ReconEngine.run

    async def run_with_posture_enrichment(self: Any, target: str, modules: List[str]) -> Dict[str, Any]:
        return await _posture_enriched_run(self, original_run.__get__(self, self.__class__), target, modules)

    ReconEngine.run = run_with_posture_enrichment
    ReconEngine._blackbox_posture_enrichment_patched = True
