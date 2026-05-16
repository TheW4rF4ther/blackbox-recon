"""Post-scan posture and service enrichment hook for ReconEngine.

This module wires enrichment into the existing run loop without changing the
scanner's core phases. It is intentionally observational and service-aware:
it runs HTTP/TLS/service/web/DNS/screenshot enrichment only against assets
discovered by the current run, then refreshes evidence and findings.
"""

from __future__ import annotations

import asyncio
from functools import partial
from pathlib import Path
from typing import Any, Dict, Iterable, List

from rich import print as rprint

from .dns_enum import run_dns_enrichment
from .evidence import build_evidence_package
from .http_headers import HttpHeaderAnalyzer
from .reporting import build_executive_snapshot, utc_now_iso
from .screenshots import run_screenshot_triage
from .service_enum import run_service_enumeration
from .tls_scan import scan_tls_url
from .vuln_intel import run_vulnerability_intel
from .web_cms import run_cms_enumeration
from .web_fingerprint import run_web_fingerprinting


def _dedupe(seq: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in seq:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _trace_append(results: Dict[str, Any], *, phase_id: str, phase_name: str, status: str, detail: str, stack_lines: List[str], commands: List[Dict[str, Any]]) -> None:
    results.setdefault("recon_phase_trace", []).append({"phase_id": phase_id, "phase_name": phase_name, "status": status, "detail": detail, "stack_lines": stack_lines, "commands_executed": commands})


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
    timeout = int(getattr(engine, "config", {}).get("http_headers_timeout_sec", 10) or 10)
    if not urls:
        results["http_header_analysis"] = {"results": []}
        _trace_append(results, phase_id="M6", phase_name="HTTP security header posture", status="completed", detail="No HTTP(S) URLs available for header analysis", stack_lines=["Stack: Python requests header sampling"], commands=[])
        return
    analyzer = HttpHeaderAnalyzer(timeout=timeout)
    loop = asyncio.get_running_loop()
    commands: List[Dict[str, Any]] = []
    out: List[Dict[str, Any]] = []
    for url in urls:
        row = await loop.run_in_executor(None, partial(analyzer.analyze, url))
        out.append(row)
        commands.append({"label": "requests_headers", "command": f"GET {url} timeout={timeout} verify=False allow_redirects=True", "url": url, "status": row.get("status_code"), "error": row.get("error")})
    results["http_header_analysis"] = {"results": out}
    _trace_append(results, phase_id="M6", phase_name="HTTP security header posture", status="completed", detail=f"{len(out)} HTTP(S) URL(s) analyzed for security/disclosure headers", stack_lines=["Stack: Python requests header sampling"], commands=commands)


async def _run_tls_enrichment(engine: Any, results: Dict[str, Any], urls: List[str]) -> None:
    if not bool(getattr(engine, "config", {}).get("tls_scan_enabled", True)):
        _trace_append(results, phase_id="M7", phase_name="TLS posture sampling", status="skipped", detail="tls_scan_enabled is false", stack_lines=["Stack: sslscan when available; Python ssl fallback"], commands=[])
        return
    https_urls = [u for u in urls if u.lower().startswith("https://")]
    if not https_urls:
        results["tls_analysis"] = {"results": []}
        _trace_append(results, phase_id="M7", phase_name="TLS posture sampling", status="completed", detail="No HTTPS URLs available for TLS sampling", stack_lines=["Stack: sslscan when available; Python ssl fallback"], commands=[])
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
            commands.append({"label": row.get("tool") or "tls_scan", "command": cmd, "url": url, "status": row.get("status"), "weak_signals": row.get("weak_signals") or []})
    results["tls_analysis"] = {"results": out}
    _trace_append(results, phase_id="M7", phase_name="TLS posture sampling", status="completed", detail=f"{len(out)} HTTPS service(s) analyzed for TLS posture", stack_lines=["Stack: sslscan when available; Python ssl fallback"], commands=commands)


async def _run_service_enrichment(engine: Any, results: Dict[str, Any]) -> None:
    if not bool(getattr(engine, "config", {}).get("service_enum_enabled", True)):
        _trace_append(results, phase_id="M8", phase_name="Service-specific enumeration", status="skipped", detail="service_enum_enabled is false", stack_lines=["Stack: service-aware safe enumeration dispatcher"], commands=[])
        return
    port_rows = results.get("ports") or []
    timeout = int(getattr(engine, "config", {}).get("service_enum_timeout_sec", 60) or 60)
    max_services = int(getattr(engine, "config", {}).get("service_enum_max_services", 24) or 24)
    loop = asyncio.get_running_loop()
    enum = await loop.run_in_executor(None, partial(run_service_enumeration, port_rows, timeout_sec=timeout, max_services=max_services))
    results["service_enumeration"] = enum
    commands: List[Dict[str, Any]] = []
    for row in enum.get("results") or []:
        cmd = row.get("command") or row.get("module") or "service_enum"
        commands.append({"label": row.get("module") or "service_enum", "command": cmd, "host": row.get("host"), "port": row.get("port"), "status": row.get("status"), "findings": len(row.get("findings") or [])})
    _trace_append(results, phase_id="M8", phase_name="Service-specific enumeration", status="completed", detail=f"{enum.get('modules_run', 0)} service module(s) run across {enum.get('services_considered', 0)} open service(s)", stack_lines=["Stack: service-aware safe enumeration dispatcher"], commands=commands)


async def _run_web_fingerprint_enrichment(engine: Any, results: Dict[str, Any], urls: List[str]) -> None:
    if not bool(getattr(engine, "config", {}).get("web_fingerprint_enabled", True)):
        _trace_append(results, phase_id="M9", phase_name="Web fingerprinting", status="skipped", detail="web_fingerprint_enabled is false", stack_lines=["Stack: whatweb and wafw00f when installed"], commands=[])
        return
    timeout = int(getattr(engine, "config", {}).get("web_fingerprint_timeout_sec", 60) or 60)
    loop = asyncio.get_running_loop()
    fp = await loop.run_in_executor(None, partial(run_web_fingerprinting, urls, timeout_sec=timeout, max_urls=len(urls) or 1))
    results["web_fingerprinting"] = fp
    commands: List[Dict[str, Any]] = []
    for row in fp.get("results") or []:
        cmd = row.get("command") or f"{row.get('tool')} skipped"
        commands.append({"label": row.get("module") or "web_fp", "command": cmd, "url": row.get("url"), "status": row.get("status"), "findings": len(row.get("findings") or [])})
    _trace_append(results, phase_id="M9", phase_name="Web fingerprinting", status="completed", detail=f"{fp.get('modules_run', 0)} web fingerprint module(s) run across {fp.get('urls_considered', 0)} URL(s)", stack_lines=["Stack: whatweb and wafw00f when installed"], commands=commands)


async def _run_cms_enrichment(engine: Any, results: Dict[str, Any], urls: List[str]) -> None:
    if not bool(getattr(engine, "config", {}).get("cms_enum_enabled", True)):
        _trace_append(results, phase_id="M9B", phase_name="CMS and app-aware web enumeration", status="skipped", detail="cms_enum_enabled is false", stack_lines=["Stack: CMS path probes + WPScan when WordPress is detected"], commands=[])
        return
    timeout = int(getattr(engine, "config", {}).get("cms_enum_timeout_sec", 12) or 12)
    wpscan_timeout = int(getattr(engine, "config", {}).get("wpscan_timeout_sec", 240) or 240)
    loop = asyncio.get_running_loop()
    cms = await loop.run_in_executor(None, partial(run_cms_enumeration, urls, timeout_sec=timeout, wpscan_timeout_sec=wpscan_timeout, max_urls=len(urls) or 1))
    results["cms_enumeration"] = cms
    commands: List[Dict[str, Any]] = []
    for row in cms.get("results") or []:
        commands.append({"label": "cms_path_probe", "command": f"CMS known-path probes against {row.get('url')}", "url": row.get("url"), "status": row.get("status"), "findings": len(row.get("findings") or [])})
        wps = row.get("wpscan") or {}
        if isinstance(wps, dict) and wps.get("command"):
            commands.append({"label": "wpscan", "command": wps.get("command"), "url": row.get("url"), "status": wps.get("status"), "findings": len(wps.get("findings") or [])})
    _trace_append(results, phase_id="M9B", phase_name="CMS and app-aware web enumeration", status="completed", detail=f"{cms.get('cms_signals', 0)} CMS/app signal group(s) observed across {cms.get('urls_considered', 0)} URL(s)", stack_lines=["Stack: CMS path probes + WPScan when WordPress is detected"], commands=commands)


async def _run_vuln_intel_enrichment(engine: Any, results: Dict[str, Any]) -> None:
    if not bool(getattr(engine, "config", {}).get("vuln_intel_enabled", True)):
        _trace_append(results, phase_id="M12", phase_name="Vulnerability intelligence lookup", status="skipped", detail="vuln_intel_enabled is false", stack_lines=["Stack: searchsploit + NVD keyword lookups"], commands=[])
        return
    ss_timeout = int(getattr(engine, "config", {}).get("searchsploit_timeout_sec", 30) or 30)
    nvd_timeout = int(getattr(engine, "config", {}).get("nvd_timeout_sec", 12) or 12)
    max_signals = int(getattr(engine, "config", {}).get("vuln_intel_max_signals", 12) or 12)
    loop = asyncio.get_running_loop()
    intel = await loop.run_in_executor(None, partial(run_vulnerability_intel, results, searchsploit_timeout_sec=ss_timeout, nvd_timeout_sec=nvd_timeout, max_signals=max_signals))
    results["vulnerability_intel"] = intel
    commands: List[Dict[str, Any]] = []
    for lookup in intel.get("lookups") or []:
        commands.append({"label": lookup.get("source"), "command": lookup.get("query"), "status": lookup.get("status"), "matches": len(lookup.get("matches") or [])})
    _trace_append(results, phase_id="M12", phase_name="Vulnerability intelligence lookup", status="completed", detail=f"{len(intel.get('candidate_leads') or [])} candidate vulnerability/exploit lead(s) from {len(intel.get('signals') or [])} version signal(s)", stack_lines=["Stack: searchsploit + NVD keyword lookups"], commands=commands)


async def _run_dns_enrichment(engine: Any, results: Dict[str, Any], target: str) -> None:
    if not bool(getattr(engine, "config", {}).get("dns_enrichment_enabled", True)):
        _trace_append(results, phase_id="M10", phase_name="DNS record enrichment", status="skipped", detail="dns_enrichment_enabled is false", stack_lines=["Stack: dig when installed; Python socket fallback"], commands=[])
        return
    timeout = int(getattr(engine, "config", {}).get("dns_enrichment_timeout_sec", 20) or 20)
    loop = asyncio.get_running_loop()
    dns = await loop.run_in_executor(None, partial(run_dns_enrichment, target, timeout_sec=timeout))
    results["dns_record_enrichment"] = dns
    commands: List[Dict[str, Any]] = []
    for row in dns.get("results") or []:
        cmd = row.get("command") or f"{row.get('tool')} {row.get('record_type')} {row.get('target')}"
        commands.append({"label": f"dns_{row.get('record_type')}", "command": cmd, "status": row.get("status"), "records": len(row.get("records") or [])})
    _trace_append(results, phase_id="M10", phase_name="DNS record enrichment", status="completed", detail=f"{dns.get('queries_run', 0)} DNS record query/queries executed", stack_lines=["Stack: dig when installed; Python socket fallback"], commands=commands)


async def _run_screenshot_triage(engine: Any, results: Dict[str, Any], urls: List[str], target: str) -> None:
    if not bool(getattr(engine, "config", {}).get("screenshot_enabled", True)):
        _trace_append(results, phase_id="M11", phase_name="Screenshot triage", status="skipped", detail="screenshot_enabled is false", stack_lines=["Stack: gowitness when installed"], commands=[])
        return
    base = Path.home() / ".blackbox-recon" / "screenshots" / str(target).replace("/", "_")
    timeout = int(getattr(engine, "config", {}).get("screenshot_timeout_sec", 90) or 90)
    loop = asyncio.get_running_loop()
    ss = await loop.run_in_executor(None, partial(run_screenshot_triage, urls, output_dir=str(base), timeout_sec=timeout, max_urls=len(urls) or 1))
    results["screenshot_triage"] = ss
    commands: List[Dict[str, Any]] = []
    for row in ss.get("results") or []:
        cmd = row.get("command") or f"{row.get('tool')} skipped"
        commands.append({"label": "screenshot", "command": cmd, "url": row.get("url"), "status": row.get("status"), "path": row.get("screenshot_path")})
    _trace_append(results, phase_id="M11", phase_name="Screenshot triage", status="completed", detail=f"{ss.get('screenshots_captured', 0)} screenshot(s) captured across {ss.get('urls_considered', 0)} URL(s)", stack_lines=["Stack: gowitness when installed"], commands=commands)


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
    return out


def _cms_findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    idx = len(results.get("deterministic_findings") or []) + 1
    def _add(code: str, title: str, severity: str, asset: str, evidence_ref: str, impact: str, recommendation: str, validation: str, confidence: str = "medium") -> None:
        nonlocal idx
        out.append({"id": f"DET-FIND-{idx:03d}", "finding_code": code, "title": title, "severity": severity, "status": "confirmed", "affected_assets": [asset], "evidence_ids": [evidence_ref], "impact": impact, "recommendation": recommendation, "validation": validation, "confidence": confidence})
        idx += 1
    for i, row in enumerate((results.get("cms_enumeration") or {}).get("results") or []):
        asset = row.get("url") or "web"
        evidence_ref = f"CMS-ENUM-{i+1:03d}"
        findings = [f for f in (row.get("findings") or []) if isinstance(f, dict)]
        types = {f.get("type") for f in findings}
        cms = row.get("cms") or []
        if cms:
            _add("BBR-CMS-001", f"CMS detected: {', '.join(map(str, cms))}", "medium", asset, evidence_ref, "CMS identification gives the tester a specific application enumeration path and version/plugin/user checks.", "Continue CMS-aware enumeration and validate exact version, themes/plugins, and exposed login/XML-RPC endpoints.", "Confirm CMS identity using source, known paths, and CMS-native scanner artifacts.", "high")
        versions = [f.get("version") for f in findings if f.get("type") == "wordpress_version" and f.get("version")]
        if versions:
            _add("BBR-WP-001", f"WordPress version identified: {versions[0]}", "medium", asset, evidence_ref, "A precise WordPress version enables targeted vulnerability research and patch-level validation.", "Validate WordPress core version and review known issues in the context of the target and available plugins/themes.", "Confirm version through WPScan, feed generator, readme, or authenticated admin inventory.", "high")
        if "wordpress_login_found" in types:
            _add("BBR-WP-LOGIN-001", "WordPress login endpoint exposed", "medium", asset, evidence_ref, "The WordPress login endpoint is a primary authentication surface and may enable username validation or password policy testing under ROE.", "Validate authentication controls, MFA/lockout, and username exposure; do not brute force unless explicitly authorized.", "Open /wp-login.php and verify expected access controls under scope.", "high")
        if "wordpress_xmlrpc_enabled" in types:
            _add("BBR-WP-XMLRPC-001", "WordPress XML-RPC endpoint enabled", "medium", asset, evidence_ref, "XML-RPC can expand authentication and pingback attack surface depending on configuration.", "Validate whether XML-RPC is required; restrict or disable if not needed and review rate limiting.", "Request /xmlrpc.php and confirm methods/configuration under ROE.", "high")
        users = []
        for f in findings:
            if f.get("type") == "wordpress_users_identified":
                users.extend(f.get("users") or [])
        if users:
            _add("BBR-WP-USERS-001", f"WordPress usernames identified: {', '.join(users[:6])}", "medium", asset, evidence_ref, "Enumerated usernames provide valid account targets for password policy validation if authorized.", "Review username exposure and validate login protections; do not perform password attacks without explicit ROE authorization.", "Confirm enumerated users with WPScan artifact and application responses.", "high")
        interesting = [f for f in findings if f.get("type") == "interesting_path"]
        if interesting:
            paths = ", ".join(str(f.get("path")) for f in interesting[:8])
            _add("BBR-WEB-PATH-001", f"Interesting web paths discovered: {paths}", "medium", asset, evidence_ref, "Interesting paths can reveal application functionality, hidden content, or administrative surface.", "Manually browse and validate access control, content sensitivity, and application behavior for discovered paths.", "Review CMS/path enumeration artifacts and manually validate each path.", "high")
    return out


def _web_dns_findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    idx = len(results.get("deterministic_findings") or []) + 1
    def _add(code: str, title: str, severity: str, asset: str, evidence_ref: str, impact: str, recommendation: str, validation: str, confidence: str = "medium") -> None:
        nonlocal idx
        out.append({"id": f"DET-FIND-{idx:03d}", "finding_code": code, "title": title, "severity": severity, "status": "confirmed", "affected_assets": [asset], "evidence_ids": [evidence_ref], "impact": impact, "recommendation": recommendation, "validation": validation, "confidence": confidence})
        idx += 1
    for i, row in enumerate((results.get("web_fingerprinting") or {}).get("results") or []):
        ftypes = {f.get("type") for f in (row.get("findings") or []) if isinstance(f, dict)}
        asset = row.get("url") or "web"
        if "whatweb_fingerprint" in ftypes:
            _add("BBR-WEB-FP-001", "Web technology fingerprint observed", "informational", asset, f"WEB-FP-{i+1:03d}", "Technology fingerprinting improves inventory and helps prioritize version verification without confirming a vulnerability by itself.", "Review fingerprinted technologies and confirm precise versions through authorized configuration or package review.", "Re-run WhatWeb and compare against authenticated asset inventory.", "medium")
    return out


def _refresh_summary_and_evidence(engine: Any, results: Dict[str, Any], modules: List[str]) -> None:
    summary = results.setdefault("summary", {})
    summary["http_header_urls_analyzed"] = len((results.get("http_header_analysis") or {}).get("results") or [])
    summary["tls_services_analyzed"] = len((results.get("tls_analysis") or {}).get("results") or [])
    summary["service_enum_modules_run"] = int((results.get("service_enumeration") or {}).get("modules_run") or 0)
    summary["web_fingerprint_modules_run"] = int((results.get("web_fingerprinting") or {}).get("modules_run") or 0)
    summary["cms_signals_observed"] = int((results.get("cms_enumeration") or {}).get("cms_signals") or 0)
    summary["vuln_intel_leads"] = len((results.get("vulnerability_intel") or {}).get("candidate_leads") or [])
    summary["dns_record_queries_run"] = int((results.get("dns_record_enrichment") or {}).get("queries_run") or 0)
    summary["screenshots_captured"] = int((results.get("screenshot_triage") or {}).get("screenshots_captured") or 0)
    modules_executed = list(dict.fromkeys(list(modules) + ["http_headers", "tls", "service_enum", "web_fingerprint", "cms_enum", "vuln_intel", "dns_enrichment", "screenshot_triage"]))
    results["evidence_package"] = build_evidence_package(results, modules_executed, lab_mode=getattr(engine, "_rt", None) is None)
    base_findings = list(results["evidence_package"].get("deterministic_findings", []))
    results["deterministic_findings"] = base_findings
    findings = base_findings + _service_findings(results)
    results["deterministic_findings"] = findings
    findings = findings + _cms_findings(results)
    results["deterministic_findings"] = findings
    findings = findings + _web_dns_findings(results)
    results["deterministic_findings"] = findings
    results["evidence_package"]["deterministic_findings"] = findings
    for key in ("service_enumeration", "web_fingerprinting", "cms_enumeration", "vulnerability_intel", "dns_record_enrichment", "screenshot_triage"):
        results["evidence_package"].setdefault(key, results.get(key) or {})
    results["deterministic_attack_paths"] = results["evidence_package"].get("deterministic_attack_paths", [])
    results["recon_completed_utc"] = utc_now_iso()
    results["executive_snapshot"] = build_executive_snapshot(results)


async def _posture_enriched_run(engine: Any, original_run: Any, target: str, modules: List[str]) -> Dict[str, Any]:
    results = await original_run(target, modules)
    if "portscan" not in modules:
        await _run_dns_enrichment(engine, results, target)
        await _run_vuln_intel_enrichment(engine, results)
        _refresh_summary_and_evidence(engine, results, modules)
        return results
    urls = _web_urls_from_results(results, engine)
    await _run_http_header_enrichment(engine, results, urls)
    await _run_tls_enrichment(engine, results, urls)
    await _run_service_enrichment(engine, results)
    await _run_web_fingerprint_enrichment(engine, results, urls)
    await _run_cms_enrichment(engine, results, urls)
    await _run_vuln_intel_enrichment(engine, results)
    await _run_dns_enrichment(engine, results, target)
    await _run_screenshot_triage(engine, results, urls, target)
    _refresh_summary_and_evidence(engine, results, modules)
    return results


def patch_recon_engine(ReconEngine: Any) -> None:
    """Patch ReconEngine.run once so enrichment phases execute after the core run."""
    if getattr(ReconEngine, "_blackbox_posture_enrichment_patched", False):
        return
    original_run = ReconEngine.run
    async def run_with_posture_enrichment(self: Any, target: str, modules: List[str]) -> Dict[str, Any]:
        return await _posture_enriched_run(self, original_run.__get__(self, self.__class__), target, modules)
    ReconEngine.run = run_with_posture_enrichment
    ReconEngine._blackbox_posture_enrichment_patched = True
