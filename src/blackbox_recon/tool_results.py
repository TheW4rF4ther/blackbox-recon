"""Normalize scanner output into pentester-readable tool results.

Contract: tool used -> command -> pertinent output -> signals.
This is the primary operational view. Raw excerpts/evidence stay elsewhere.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _short(value: Any, n: int = 220) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _phase_command(results: Dict[str, Any], phase_id: str, label_contains: Optional[str] = None) -> Optional[str]:
    for phase in results.get("recon_phase_trace") or []:
        if phase.get("phase_id") != phase_id:
            continue
        for cmd in phase.get("commands_executed") or []:
            label = str(cmd.get("label") or "")
            command = cmd.get("command")
            if not command:
                continue
            if label_contains is None or label_contains.lower() in label.lower():
                return str(command)
    return None


def _ports(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [p for p in (results.get("ports") or []) if isinstance(p, dict)]


def _dir_scans(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [s for s in (results.get("web_content_discovery") or {}).get("directory_scans") or [] if isinstance(s, dict)]


def _http_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("http_header_analysis") or {}).get("results") or [] if isinstance(r, dict)]


def _tls_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("tls_analysis") or {}).get("results") or [] if isinstance(r, dict)]


def _service_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("service_enumeration") or {}).get("results") or [] if isinstance(r, dict)]


def _webfp_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("web_fingerprinting") or {}).get("results") or [] if isinstance(r, dict)]


def _dns_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("dns_record_enrichment") or {}).get("results") or [] if isinstance(r, dict)]


def _screenshot_rows(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("screenshot_triage") or {}).get("results") or [] if isinstance(r, dict)]


def _result(tool: str, purpose: str, status: str, command: Optional[str], important_output: List[str], signals: Optional[List[str]] = None, assets: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "tool": tool,
        "purpose": purpose,
        "status": status or "unknown",
        "command": command,
        "assets": assets or [],
        "important_output": [str(x) for x in important_output if str(x or "").strip()],
        "signals": [str(x) for x in (signals or []) if str(x or "").strip()],
    }


def _nmap_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ports = _ports(results)
    if not ports:
        return None
    lines = []
    for p in ports[:20]:
        ver = p.get("version") or p.get("banner") or ""
        lines.append(f"{p.get('host')}:{p.get('port')}/tcp {p.get('service') or 'unknown'} {p.get('state') or 'open'} {_short(ver, 120)}".strip())
    signals = []
    if any(int(p.get("port") or 0) == 22 for p in ports):
        signals.append("SSH exposed")
    if any(int(p.get("port") or 0) in (80, 443) for p in ports):
        signals.append("Web service exposed")
    return _result("nmap", "Port and service discovery", "completed", _phase_command(results, "M3", "nmap"), lines, signals, list({str(p.get("host")) for p in ports if p.get("host")}))


def _dns_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = _dns_rows(results)
    if not rows:
        return None
    lines = []
    for row in rows[:10]:
        records = row.get("records") or []
        if records:
            lines.append(f"{row.get('record_type')} {row.get('target')}: {', '.join(map(str, records[:8]))}")
        else:
            lines.append(f"{row.get('record_type')} {row.get('target')}: no records ({row.get('status')})")
    return _result("dig", "DNS record enrichment", "completed", _phase_command(results, "M10"), lines, [], [])


def _gobuster_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for scan in _dir_scans(results):
        hits = scan.get("findings_interesting") or []
        lines = []
        if hits:
            for h in hits[:15]:
                if isinstance(h, dict):
                    lines.append(f"{h.get('path')} status={h.get('status_code')} size={h.get('size', '-')}")
        else:
            lines.append("0 interesting paths found")
        if scan.get("error"):
            lines.append(f"error: {_short(scan.get('error'), 180)}")
        out.append(_result(str(scan.get("tool") or "gobuster"), f"Web content discovery for {scan.get('base_url')}", str(scan.get("status") or "completed"), scan.get("command") or _phase_command(results, "M4"), lines, ["interesting paths found" if hits else "no flagged paths"], [str(scan.get("base_url"))]))
    return out


def _http_header_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for row in _http_rows(results):
        lines = [
            f"status={row.get('status_code') or 'n/a'} final_url={row.get('final_url') or row.get('url')}",
            f"title={row.get('title') or 'n/a'}",
        ]
        missing = row.get("missing_security_headers") or []
        if missing:
            lines.append("missing_security_headers=" + ", ".join(map(str, missing)))
        disclosure = row.get("disclosure_headers") or {}
        if disclosure:
            lines.append("disclosure_headers=" + ", ".join(f"{k}={v}" for k, v in list(disclosure.items())[:6]))
        if row.get("error"):
            lines.append(f"error={_short(row.get('error'), 180)}")
        signals = []
        if missing:
            signals.append("missing security headers")
        if disclosure:
            signals.append("service disclosure headers")
        out.append(_result("requests", f"HTTP response and header review for {row.get('url')}", "completed" if not row.get("error") else "tool_error", row.get("command") or f"GET {row.get('url')}", lines, signals, [str(row.get("url"))]))
    return out


def _tls_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for row in _tls_rows(results):
        cert = row.get("certificate") or {}
        lines = [
            "supported_protocols=" + (", ".join(map(str, row.get("supported_protocols") or [])) or "not parsed"),
            "weak_signals=" + (", ".join(map(str, row.get("weak_signals") or [])) or "none observed"),
        ]
        if cert:
            for key in ("subject", "issuer", "not_after"):
                if cert.get(key):
                    lines.append(f"cert_{key}={_short(cert.get(key), 160)}")
        signals = ["weak TLS signal" for _ in row.get("weak_signals") or []]
        out.append(_result(str(row.get("tool") or "sslscan"), f"TLS posture sampling for {row.get('host')}:{row.get('port')}", str(row.get("status") or "completed"), row.get("command"), lines, signals or ["TLS sampled"], [f"{row.get('host')}:{row.get('port')}"]))
    return out


def _service_enum_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for row in _service_rows(results):
        findings = [f for f in (row.get("findings") or []) if isinstance(f, dict)]
        lines = []
        if findings:
            for f in findings[:8]:
                lines.append(f"{f.get('type')}: {_short(f.get('values') or f.get('observed') or f.get('banner') or f, 160)}")
        else:
            lines.append("completed/no flagged service-specific signal")
        if row.get("error"):
            lines.append(f"error={_short(row.get('error'), 180)}")
        out.append(_result(str(row.get("tool") or row.get("module") or "service_enum"), f"Service-specific enumeration for {row.get('host')}:{row.get('port')} ({row.get('service')})", str(row.get("status") or "completed"), row.get("command"), lines, [str(f.get("type")) for f in findings], [f"{row.get('host')}:{row.get('port')}"]))
    return out


def _webfp_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for row in _webfp_rows(results):
        findings = [f for f in (row.get("findings") or []) if isinstance(f, dict)]
        lines = []
        if findings:
            for f in findings[:4]:
                lines.append(f"{f.get('type')}: {_short(f.get('summary') or f, 220)}")
        else:
            lines.append(_short(row.get("stdout_excerpt") or row.get("error") or "completed/no useful fingerprint signal", 220))
        out.append(_result(str(row.get("tool") or "web_fingerprint"), f"Web fingerprinting for {row.get('url')}", str(row.get("status") or "completed"), row.get("command"), lines, [str(f.get("type")) for f in findings], [str(row.get("url"))]))
    return out


def _screenshot_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for row in _screenshot_rows(results):
        path = row.get("screenshot_path")
        lines = [f"screenshot={path}" if path else f"not captured: {row.get('error') or row.get('status')}"]
        out.append(_result(str(row.get("tool") or "gowitness"), f"Screenshot triage for {row.get('url')}", str(row.get("status") or "skipped"), row.get("command"), lines, ["screenshot captured" if path else "screenshot not captured"], [str(row.get("url"))]))
    return out


def build_tool_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build ordered, concise tool results for terminal and report output."""
    out: List[Dict[str, Any]] = []
    nmap = _nmap_result(results)
    if nmap:
        out.append(nmap)
    dns = _dns_result(results)
    if dns:
        out.append(dns)
    out.extend(_gobuster_results(results))
    out.extend(_http_header_results(results))
    out.extend(_tls_results(results))
    out.extend(_service_enum_results(results))
    out.extend(_webfp_results(results))
    out.extend(_screenshot_results(results))
    for idx, row in enumerate(out, start=1):
        row["id"] = f"TOOL-{idx:03d}"
    return out
