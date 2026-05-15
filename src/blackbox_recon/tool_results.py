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
    candidates: List[str] = []
    for phase in results.get("recon_phase_trace") or []:
        if phase.get("phase_id") != phase_id:
            continue
        for cmd in phase.get("commands_executed") or []:
            label = str(cmd.get("label") or "")
            command = cmd.get("command")
            if not command:
                continue
            if label_contains is None or label_contains.lower() in label.lower():
                candidates.append(str(command))
    if not candidates:
        return None
    # Prefer actual command lines over binary-path metadata like /usr/bin/nmap.
    candidates.sort(key=lambda c: (" " not in c, len(c)))
    return candidates[0]


def _phase_commands(results: Dict[str, Any], phase_id: str, label_contains: Optional[str] = None) -> List[str]:
    out: List[str] = []
    for phase in results.get("recon_phase_trace") or []:
        if phase.get("phase_id") != phase_id:
            continue
        for cmd in phase.get("commands_executed") or []:
            label = str(cmd.get("label") or "")
            command = cmd.get("command")
            if not command:
                continue
            if label_contains is None or label_contains.lower() in label.lower():
                out.append(str(command))
    return out


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
    for p in ports[:30]:
        ver = p.get("version") or p.get("banner") or ""
        lines.append(f"{p.get('host')}:{p.get('port')}/tcp {p.get('service') or 'unknown'} {p.get('state') or 'open'} {_short(ver, 140)}".strip())
    signals = []
    if any(int(p.get("port") or 0) == 22 for p in ports):
        signals.append("SSH exposed")
    if any(int(p.get("port") or 0) in (80, 443) for p in ports):
        signals.append("Web service exposed")
    return _result("nmap", "Port and service discovery", "completed", _phase_command(results, "M3", "nmap_aggressive") or _phase_command(results, "M3", "nmap"), lines, signals, list({str(p.get("host")) for p in ports if p.get("host")}))


def _dns_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = _dns_rows(results)
    if not rows:
        return None
    lines = []
    for row in rows[:10]:
        records = row.get("records") or []
        if records:
            lines.append(f"{row.get('record_type')} {row.get('target')}: {', '.join(map(str, records[:8]))}")
    if not lines:
        return None
    return _result("dig", "DNS record enrichment", "completed", _phase_command(results, "M10"), lines, [], [])


def _gobuster_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    scans = _dir_scans(results)
    if not scans:
        return None
    lines: List[str] = []
    assets: List[str] = []
    total_hits = 0
    for scan in scans:
        base = str(scan.get("base_url") or "")
        assets.append(base)
        hits = scan.get("findings_interesting") or []
        total_hits += len(hits)
        if hits:
            lines.append(f"{base}: {len(hits)} interesting path(s)")
            for h in hits[:10]:
                if isinstance(h, dict):
                    lines.append(f"  {h.get('path')} status={h.get('status_code')} size={h.get('size', '-')}")
        else:
            lines.append(f"{base}: 0 interesting paths found")
        if scan.get("error"):
            lines.append(f"{base}: error={_short(scan.get('error'), 180)}")
    cmds = _phase_commands(results, "M4")
    command = " | ".join(cmds[:3]) if cmds else None
    if len(cmds) > 3:
        command += f" | +{len(cmds)-3} more"
    return _result("gobuster/dirb", "Web content discovery across discovered HTTP(S) services", "completed", command, lines, ["interesting paths found" if total_hits else "no flagged paths"], sorted(set(assets)))


def _http_header_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = _http_rows(results)
    lines: List[str] = []
    signals: List[str] = []
    assets: List[str] = []
    for row in rows:
        missing = row.get("missing_security_headers") or []
        disclosure = row.get("disclosure_headers") or {}
        status = row.get("status_code")
        title = row.get("title")
        if not (missing or disclosure or status or title or row.get("error")):
            continue
        assets.append(str(row.get("url") or row.get("final_url") or ""))
        pieces = [str(row.get("url") or "")]
        if status:
            pieces.append(f"status={status}")
        if title:
            pieces.append(f"title={_short(title, 80)}")
        if missing:
            pieces.append("missing=" + ", ".join(map(str, missing[:8])))
            signals.append("missing security headers")
        if disclosure:
            pieces.append("disclosure=" + ", ".join(f"{k}={v}" for k, v in list(disclosure.items())[:4]))
            signals.append("service disclosure headers")
        if row.get("error"):
            pieces.append(f"error={_short(row.get('error'), 120)}")
        lines.append(" | ".join(pieces))
    if not lines or not signals:
        return None
    return _result("requests", "HTTP response/header signals", "completed", _phase_command(results, "M6"), lines, sorted(set(signals)), sorted(set(a for a in assets if a)))


def _tls_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = _tls_rows(results)
    if not rows:
        return None
    lines: List[str] = []
    signals: List[str] = []
    assets: List[str] = []
    for row in rows:
        asset = f"{row.get('host')}:{row.get('port')}"
        assets.append(asset)
        cert = row.get("certificate") or {}
        protos = ", ".join(map(str, row.get("supported_protocols") or [])) or "not parsed"
        weak = ", ".join(map(str, row.get("weak_signals") or [])) or "none observed"
        lines.append(f"{asset}: protocols={protos}; weak_signals={weak}")
        for key in ("subject", "issuer", "not_after"):
            if cert.get(key):
                lines.append(f"{asset}: cert_{key}={_short(cert.get(key), 170)}")
        if row.get("weak_signals"):
            signals.append("weak TLS signal")
        else:
            signals.append("TLS sampled; no weak signal recorded")
    if not lines:
        return None
    cmd = _phase_command(results, "M7")
    return _result("sslscan", "TLS protocol/certificate review", "completed", cmd, lines, sorted(set(signals)), sorted(set(assets)))


def _meaningful_script_lines(text: str) -> List[str]:
    out: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("Starting Nmap") or line.startswith("Nmap scan report") or line.startswith("Host is up") or line.startswith("Nmap done"):
            continue
        if line in ("PORT   STATE SERVICE", "PORT     STATE SERVICE"):
            continue
        out.append(line)
        if len(out) >= 12:
            break
    return out


def _service_enum_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = _service_rows(results)
    if not rows:
        return None
    lines: List[str] = []
    signals: List[str] = []
    assets: List[str] = []
    cmds: List[str] = []
    for row in rows:
        asset = f"{row.get('host')}:{row.get('port')}"
        assets.append(asset)
        if row.get("command"):
            cmds.append(str(row.get("command")))
        findings = [f for f in (row.get("findings") or []) if isinstance(f, dict)]
        if findings:
            for f in findings[:8]:
                typ = str(f.get("type"))
                lines.append(f"{asset} {row.get('module')}: {typ} {_short(f.get('values') or f.get('observed') or f.get('banner') or f, 160)}")
                signals.append(typ)
        else:
            script_lines = _meaningful_script_lines(str(row.get("stdout_excerpt") or ""))
            if script_lines:
                lines.append(f"{asset} {row.get('module')}: script completed; no blacklist weak-signal matched")
                for s in script_lines[:8]:
                    lines.append(f"  {s}")
                signals.append("service script completed")
            elif row.get("error"):
                lines.append(f"{asset} {row.get('module')}: error={_short(row.get('error'), 140)}")
                signals.append("service enum error")
    if not lines:
        return None
    cmd = " | ".join(cmds[:3]) if cmds else None
    return _result("nmap/service helpers", "Service-specific enumeration details", "completed", cmd, lines, sorted(set(signals)), sorted(set(assets)))


def _webfp_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = _webfp_rows(results)
    lines: List[str] = []
    signals: List[str] = []
    assets: List[str] = []
    cmds: List[str] = []
    for row in rows:
        findings = [f for f in (row.get("findings") or []) if isinstance(f, dict)]
        keep_findings = [f for f in findings if f.get("type") in ("whatweb_fingerprint", "waf_signal")]
        if not keep_findings:
            continue
        if row.get("command"):
            cmds.append(str(row.get("command")))
        assets.append(str(row.get("url") or ""))
        for f in keep_findings[:4]:
            lines.append(f"{row.get('url')} {row.get('tool')}: {f.get('type')} {_short(f.get('summary') or f, 220)}")
            signals.append(str(f.get("type")))
    if not lines:
        return None
    command = " | ".join(cmds[:3]) if cmds else None
    return _result("whatweb/wafw00f", "Web stack and WAF fingerprint signals", "completed", command, lines, sorted(set(signals)), sorted(set(a for a in assets if a)))


def _screenshot_result(results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rows = _screenshot_rows(results)
    lines: List[str] = []
    assets: List[str] = []
    cmds: List[str] = []
    for row in rows:
        path = row.get("screenshot_path")
        if not path:
            continue
        assets.append(str(row.get("url") or ""))
        if row.get("command"):
            cmds.append(str(row.get("command")))
        lines.append(f"{row.get('url')}: screenshot={path}")
    if not lines:
        return None
    return _result("gowitness", "Screenshot triage", "completed", " | ".join(cmds[:3]) if cmds else None, lines, ["screenshot captured"], sorted(set(assets)))


def build_tool_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build ordered, concise tool results for terminal and report output."""
    out: List[Dict[str, Any]] = []
    for item in (
        _nmap_result(results),
        _dns_result(results),
        _gobuster_result(results),
        _http_header_result(results),
        _tls_result(results),
        _service_enum_result(results),
        _webfp_result(results),
        _screenshot_result(results),
    ):
        if item and item.get("important_output"):
            out.append(item)
    for idx, row in enumerate(out, start=1):
        row["id"] = f"TOOL-{idx:03d}"
    return out
