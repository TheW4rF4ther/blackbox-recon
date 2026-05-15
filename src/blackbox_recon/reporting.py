"""Human-oriented report helpers (pretty JSON, executive snapshots)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .execution_trace import summarize_execution_trace


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def dumps_pretty(data: Any) -> str:
    """Stable, UTF-8 JSON suitable for client deliverables."""
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
        "web_url_candidates": summary.get("web_urls_targeted", 0),
        "dns_names_observed": names[:25],
        "notable_paths_from_bruteforce": interesting_paths[:25],
        "modules_executed": (results.get("engagement") or {}).get("modules_requested", []),
        "ptes_execution": ptes_execution,
    }
