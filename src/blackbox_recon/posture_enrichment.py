"""Post-scan web posture enrichment hook for ReconEngine.

This module wires M6/M7 style enrichment into the existing run loop without
changing the scanner's core phases. It is intentionally observational: it runs
HTTP header sampling and TLS posture sampling only against discovered HTTP(S)
URLs from the current run, then rebuilds the evidence package and deterministic
findings.
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
        _trace_append(
            results,
            phase_id="M6",
            phase_name="HTTP security header posture",
            status="skipped",
            detail="http_headers_enabled is false",
            stack_lines=["Stack: Python requests header sampling"],
            commands=[],
        )
        return

    rprint("\n────────────────────────────────────────────────────────────────────────")
    rprint("  PTES M6 · HTTP security header posture")
    rprint("  Vulnerability Analysis › Web application hardening review")
    rprint("────────────────────────────────────────────────────────────────────────")
    rprint("    · Objective: Sample discovered HTTP(S) services for security headers, disclosure headers, cookies, redirects, and titles.")
    rprint("    · Stack: Python requests (GET, redirects enabled, TLS verification disabled for lab/authorized testing)")

    if not urls:
        results["http_header_analysis"] = {"results": []}
        _trace_append(
            results,
            phase_id="M6",
            phase_name="HTTP security header posture",
            status="completed",
            detail="No HTTP(S) URLs available for header analysis",
            stack_lines=["Stack: Python requests header sampling"],
            commands=[],
        )
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
        commands.append(
            {
                "label": "requests_headers",
                "command": f"GET {url} timeout={timeout} verify=False allow_redirects=True",
                "url": url,
                "status": row.get("status_code"),
                "error": row.get("error"),
            }
        )
    results["http_header_analysis"] = {"results": out}
    _trace_append(
        results,
        phase_id="M6",
        phase_name="HTTP security header posture",
        status="completed",
        detail=f"{len(out)} HTTP(S) URL(s) analyzed for security/disclosure headers",
        stack_lines=["Stack: Python requests header sampling"],
        commands=commands,
    )
    rprint(f"  → Phase complete (completed): {len(out)} URL(s) analyzed")


async def _run_tls_enrichment(engine: Any, results: Dict[str, Any], urls: List[str]) -> None:
    if not bool(getattr(engine, "config", {}).get("tls_scan_enabled", True)):
        _trace_append(
            results,
            phase_id="M7",
            phase_name="TLS posture sampling",
            status="skipped",
            detail="tls_scan_enabled is false",
            stack_lines=["Stack: sslscan when available; Python ssl fallback"],
            commands=[],
        )
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
        _trace_append(
            results,
            phase_id="M7",
            phase_name="TLS posture sampling",
            status="completed",
            detail="No HTTPS URLs available for TLS sampling",
            stack_lines=["Stack: sslscan when available; Python ssl fallback"],
            commands=[],
        )
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
            commands.append(
                {
                    "label": row.get("tool") or "tls_scan",
                    "command": cmd,
                    "url": url,
                    "status": row.get("status"),
                    "weak_signals": row.get("weak_signals") or [],
                }
            )
    results["tls_analysis"] = {"results": out}
    _trace_append(
        results,
        phase_id="M7",
        phase_name="TLS posture sampling",
        status="completed",
        detail=f"{len(out)} HTTPS service(s) analyzed for TLS posture",
        stack_lines=["Stack: sslscan when available; Python ssl fallback"],
        commands=commands,
    )
    rprint(f"  → Phase complete (completed): {len(out)} HTTPS service(s) analyzed")


def _refresh_summary_and_evidence(engine: Any, results: Dict[str, Any], modules: List[str]) -> None:
    summary = results.setdefault("summary", {})
    summary["http_header_urls_analyzed"] = len((results.get("http_header_analysis") or {}).get("results") or [])
    summary["tls_services_analyzed"] = len((results.get("tls_analysis") or {}).get("results") or [])

    modules_executed = list(dict.fromkeys(list(modules) + ["http_headers", "tls"]))
    results["evidence_package"] = build_evidence_package(
        results,
        modules_executed,
        lab_mode=getattr(engine, "_rt", None) is None,
    )
    results["deterministic_findings"] = results["evidence_package"].get("deterministic_findings", [])
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
    _refresh_summary_and_evidence(engine, results, modules)
    rprint("\n[bold green][+][/bold green] Web posture enrichment complete")
    rprint(
        f"    [yellow]HTTP header URLs:[/yellow] [white]{results['summary'].get('http_header_urls_analyzed', 0)}[/white]  "
        f"[yellow]TLS services:[/yellow] [white]{results['summary'].get('tls_services_analyzed', 0)}[/white]"
    )
    return results


def patch_recon_engine(ReconEngine: Any) -> None:
    """Patch ReconEngine.run once so M6/M7 execute after the core run."""
    if getattr(ReconEngine, "_blackbox_posture_enrichment_patched", False):
        return
    original_run = ReconEngine.run

    async def run_with_posture_enrichment(self: Any, target: str, modules: List[str]) -> Dict[str, Any]:
        return await _posture_enriched_run(self, original_run.__get__(self, self.__class__), target, modules)

    ReconEngine.run = run_with_posture_enrichment
    ReconEngine._blackbox_posture_enrichment_patched = True
