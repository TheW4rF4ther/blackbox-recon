"""Human-oriented report helpers (pretty JSON, executive snapshots)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from .execution_trace import summarize_execution_trace


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _looks_like_recon_results(data: Any) -> bool:
    return isinstance(data, dict) and (
        "target" in data
        and (
            "ports" in data
            or "deterministic_findings" in data
            or "web_content_discovery" in data
            or "evidence_package" in data
        )
    )


def dumps_pretty(data: Any) -> str:
    """Stable, UTF-8 JSON suitable for operator/client review.

    The scanner's internal result object is intentionally large and contains raw
    execution detail. For default JSON output, emit the clean pentest report
    schema instead. Development/debug consumers can still inspect the in-memory
    result object or extend the CLI with a raw-output flag later.
    """
    if _looks_like_recon_results(data):
        try:
            from .pentest_report import build_pentest_report
            data = build_pentest_report(data)
        except Exception:
            # Reporting should never break the scan; fall back to raw data if the
            # clean report builder has a bug.
            pass
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def build_executive_snapshot(results: Dict[str, Any]) -> Dict[str, Any]:
    """Short, scan-lead friendly summary block for the top of the JSON report."""
    ports = results.get("ports") or []
    dns_block = results.get("dns_intelligence") or {}
    ns_entries = dns_block.get("nslookups") or []
    web_block = results.get("web_content_discovery") or {}
    dir_runs = web_block.get("directory_scans") or []

    names: List[str] = []
    for entry in ns_entries:
        parsed = entry.get("parsed") or {}
        for n in parsed.get("ptr_or_canonical_names") or []:
            if n and n not in names:
                names.append(n)

    interesting_paths: List[Dict[str, Any]] = []
    for run in dir_runs:
        for hit in run.get("findings_interesting") or []:
            interesting_paths.append(
                {
                    "base_url": run.get("base_url"),
                    "path": hit.get("path"),
                    "status_code": hit.get("status_code"),
                }
            )
        if len(interesting_paths) >= 40:
            break

    services_glance: List[Dict[str, Any]] = []
    for p in ports[:60]:
        if not isinstance(p, dict):
            continue
        ver = p.get("version") or ""
        if isinstance(ver, str) and len(ver) > 120:
            ver = ver[:117] + "..."
        services_glance.append(
            {
                "host": p.get("host"),
                "port": p.get("port"),
                "service": p.get("service"),
                "version": ver,
            }
        )

    summary = results.get("summary") or {}
    trace = results.get("recon_phase_trace") or []
    ptes_execution = summarize_execution_trace(trace)
    return {
        "target": results.get("target"),
        "recon_completed_utc": results.get("recon_completed_utc"),
        "open_port_count": summary.get("total_open_ports", len(ports)),
        "http_services_detected": summary.get("http_services_detected", 0),
        "subdomain_http_probes_with_status": summary.get(
            "subdomain_http_probes_with_status", summary.get("web_services", 0)
        ),
        "web_url_candidates": summary.get("web_urls_targeted", 0),
        "dns_names_observed": names[:25],
        "notable_paths_from_bruteforce": interesting_paths[:25],
        "services_glance": services_glance[:25],
        "modules_executed": (results.get("engagement") or {}).get("modules_requested", []),
        "ptes_execution": ptes_execution,
    }
