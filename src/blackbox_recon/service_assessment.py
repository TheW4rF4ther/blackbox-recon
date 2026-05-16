"""Service-centric assessment model for Blackbox Recon.

This layer converts raw scanner/tool output into professional recon intelligence:
what exists, what was observed, what is negative/inconclusive, what should be
validated next, and where the evidence lives.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _short(value: Any, n: int = 220) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _ports(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [p for p in (results.get("ports") or []) if isinstance(p, dict)]


def _service_key(host: str, port: int, service: str) -> str:
    clean = "".join(c if c.isalnum() else "_" for c in str(service or "unknown").lower()).strip("_") or "unknown"
    return f"{host}:tcp/{port}/{clean}"


def _service_label(service: str, port: int) -> str:
    svc = (service or "unknown").lower()
    if port == 22 or svc == "ssh":
        return "SSH"
    if port in (443, 8443) or "https" in svc or "ssl" in svc:
        return "HTTPS"
    if port in (80, 8080, 8000, 8888) or svc.startswith("http"):
        return "HTTP"
    if port in (139, 445) or svc in ("smb", "microsoft-ds", "netbios-ssn"):
        return "SMB"
    if port == 21 or svc == "ftp":
        return "FTP"
    if port in (25, 465, 587) or svc in ("smtp", "smtps", "submission"):
        return "SMTP"
    if port == 3389 or "rdp" in svc:
        return "RDP"
    return svc.upper()


def _http_asset_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host}/" if default else f"{scheme}://{host}:{port}/"


def _web_scans_for(host: str, port: int, results: Dict[str, Any]) -> List[Dict[str, Any]]:
    base = _http_asset_url(host, port).rstrip("/")
    return [s for s in (results.get("web_content_discovery") or {}).get("directory_scans") or [] if isinstance(s, dict) and str(s.get("base_url") or "").rstrip("/") == base]


def _headers_for(host: str, port: int, results: Dict[str, Any]) -> List[Dict[str, Any]]:
    base = _http_asset_url(host, port).rstrip("/")
    return [r for r in (results.get("http_header_analysis") or {}).get("results") or [] if isinstance(r, dict) and str(r.get("url") or "").rstrip("/") == base]


def _tls_for(host: str, port: int, results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("tls_analysis") or {}).get("results") or [] if isinstance(r, dict) and str(r.get("host")) == str(host) and int(r.get("port") or 0) == int(port)]


def _service_rows_for(host: str, port: int, results: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (results.get("service_enumeration") or {}).get("results") or [] if isinstance(r, dict) and str(r.get("host")) == str(host) and int(r.get("port") or 0) == int(port)]


def _screenshots_for(host: str, port: int, results: Dict[str, Any]) -> List[Dict[str, Any]]:
    base = _http_asset_url(host, port).rstrip("/")
    return [r for r in (results.get("screenshot_triage") or {}).get("results") or [] if isinstance(r, dict) and str(r.get("url") or "").rstrip("/") == base]


def _finding_type(f: Dict[str, Any]) -> str:
    return str(f.get("type") or "").strip()


def _completion_only(ftype: str) -> bool:
    ft = (ftype or "").lower()
    return ft.endswith("_scan_completed") or ft in ("ssh_algorithm_scan_completed", "http_nse_scan_completed", "nikto_scan_completed", "ssh_audit_completed", "testssl_scan_completed")


def _finding_values(f: Dict[str, Any]) -> str:
    for key in ("values", "shares", "capabilities", "banner", "observed"):
        if key in f and f.get(key):
            val = f.get(key)
            if isinstance(val, list):
                return _short(", ".join(map(str, val)), 240)
            return _short(val, 240)
    return ""


def _add_unique(lst: List[str], item: Optional[str]) -> None:
    text = _short(item, 260)
    if text and text not in lst:
        lst.append(text)


def _service_tools(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            tools.append({"tool": row.get("tool") or row.get("module") or "tool", "module": row.get("module"), "status": row.get("status"), "artifact_path": row.get("artifact_path")})
    return tools


def _assess_ssh(host: str, port: int, port_row: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
    observed: List[str] = []
    negative: List[str] = []
    candidates: List[Dict[str, Any]] = []
    notes: List[str] = []
    verify: List[str] = ["Validate password-authentication exposure and key-only enforcement.", "Review ssh-audit/ssh2-enum-algos artifacts against the client crypto baseline."]
    artifacts: List[str] = []

    _add_unique(observed, port_row.get("version") or port_row.get("banner") or "SSH service exposed")
    rows = _service_rows_for(host, port, results)
    weak_seen = False
    audit_seen = False
    for row in rows:
        if row.get("artifact_path"):
            _add_unique(artifacts, row.get("artifact_path"))
        for f in row.get("findings") or []:
            if not isinstance(f, dict):
                continue
            typ = _finding_type(f)
            if _completion_only(typ):
                if typ == "ssh_audit_completed":
                    audit_seen = True
                continue
            if typ in ("weak_ssh_algorithm_signal", "ssh_audit_fail", "ssh_audit_warn"):
                weak_seen = True
                candidates.append({"status": "candidate", "severity": "medium", "title": "SSH cryptographic hardening issue requires validation", "evidence": _finding_values(f) or typ})
    if audit_seen and not weak_seen:
        _add_unique(negative, "ssh-audit completed; no fail/warn signal extracted by parser.")
    if not weak_seen:
        _add_unique(negative, "No weak SSH algorithm signal confirmed from parsed evidence.")
    _add_unique(notes, "SSH exposure alone is not a vulnerability; treat it as remote administration surface requiring policy validation.")
    return {"observed": observed, "negative_results": negative, "candidate_findings": candidates, "operator_notes": notes, "verification_targets": verify, "artifacts": artifacts, "tools": _service_tools(rows)}


def _assess_http(host: str, port: int, port_row: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
    observed: List[str] = []
    negative: List[str] = []
    candidates: List[Dict[str, Any]] = []
    notes: List[str] = []
    verify: List[str] = []
    artifacts: List[str] = []

    url = _http_asset_url(host, port)
    _add_unique(observed, f"{url} exposed; banner/version: {port_row.get('version') or port_row.get('banner') or port_row.get('service') or 'unknown'}")
    for scan in _web_scans_for(host, port, results):
        if scan.get("artifact_path"):
            _add_unique(artifacts, scan.get("artifact_path"))
        hits = scan.get("findings_interesting") or []
        if hits:
            candidates.append({"status": "candidate", "severity": "medium", "title": "Interesting web content discovered", "evidence": _short(hits, 240)})
            verify.append("Manually review discovered web paths and authentication boundaries.")
        else:
            _add_unique(negative, f"{scan.get('tool') or 'content discovery'} completed; 0 interesting paths found.")
    for row in _headers_for(host, port, results):
        missing = row.get("missing_security_headers") or []
        disclosure = row.get("disclosure_headers") or {}
        if row.get("title"):
            _add_unique(observed, f"HTTP title: {row.get('title')}")
        if missing:
            candidates.append({"status": "candidate", "severity": "low", "title": "Missing HTTP security headers observed", "evidence": ", ".join(map(str, missing[:8]))})
            verify.append("Validate missing security headers against application context and client standard.")
        if disclosure:
            candidates.append({"status": "candidate", "severity": "low", "title": "HTTP disclosure headers observed", "evidence": _short(disclosure, 220)})
    service_rows = _service_rows_for(host, port, results)
    for row in service_rows:
        if row.get("artifact_path"):
            _add_unique(artifacts, row.get("artifact_path"))
        for f in row.get("findings") or []:
            if isinstance(f, dict) and not _completion_only(_finding_type(f)) and _finding_type(f) in ("nikto_interesting_observations", "http_webdav_enabled"):
                typ = _finding_type(f)
                candidates.append({"status": "candidate", "severity": "medium", "title": typ.replace("_", " ").title(), "evidence": _finding_values(f) or typ})
    for ss in _screenshots_for(host, port, results):
        if ss.get("screenshot_path"):
            _add_unique(artifacts, ss.get("screenshot_path"))
            _add_unique(observed, "Screenshot captured for visual triage.")
    _add_unique(notes, "If this was a bare-IP scan, web application coverage is incomplete until Host-header/SNI/vhost context is tested.")
    verify.append("Rerun web recon against scoped FQDN; add vhost discovery before vulnerability testing.")
    return {"observed": observed, "negative_results": negative, "candidate_findings": candidates, "operator_notes": notes, "verification_targets": list(dict.fromkeys(verify)), "artifacts": artifacts, "tools": _service_tools(service_rows)}


def _assess_tls(host: str, port: int, results: Dict[str, Any]) -> Dict[str, Any]:
    observed: List[str] = []
    negative: List[str] = []
    candidates: List[Dict[str, Any]] = []
    notes: List[str] = []
    verify: List[str] = ["Run/review testssl.sh or sslscan against the scoped FQDN for SNI-aware certificate/cipher validation."]
    artifacts: List[str] = []
    tools: List[Dict[str, Any]] = []
    for row in _tls_for(host, port, results):
        tools.append({"tool": row.get("tool"), "status": row.get("status"), "artifact_path": row.get("artifact_path")})
        if row.get("artifact_path"):
            _add_unique(artifacts, row.get("artifact_path"))
        protos = ", ".join(map(str, row.get("supported_protocols") or []))
        if protos:
            _add_unique(observed, f"TLS protocols observed: {protos}")
        weak = row.get("weak_signals") or []
        if weak:
            candidates.append({"status": "candidate", "severity": "medium", "title": "TLS weak signal requires validation", "evidence": ", ".join(map(str, weak[:8]))})
        else:
            _add_unique(negative, "No weak TLS protocol/cipher signal extracted by sslscan/testssl parser.")
        cert = row.get("certificate") or {}
        for key in ("subject", "issuer", "not_after"):
            if cert.get(key):
                _add_unique(observed, f"Certificate {key}: {cert.get(key)}")
        for extra in row.get("additional_tls_tools") or []:
            if isinstance(extra, dict):
                tools.append({"tool": extra.get("tool"), "status": extra.get("status"), "artifact_path": extra.get("artifact_path")})
                if extra.get("artifact_path"):
                    _add_unique(artifacts, extra.get("artifact_path"))
    _add_unique(notes, "Certificate interpretation may be inaccurate on bare IP targets; validate with the scoped hostname/SNI.")
    return {"observed": observed, "negative_results": negative, "candidate_findings": candidates, "operator_notes": notes, "verification_targets": verify, "artifacts": artifacts, "tools": tools}


def build_service_assessments(results: Dict[str, Any]) -> Dict[str, Any]:
    """Build service-centric recon assessment data."""
    target = str(results.get("target") or "target")
    target_type = "bare_ip" if all(c.isdigit() or c == "." for c in target) else "hostname"
    limitations: List[str] = []
    if target_type == "bare_ip":
        limitations.append("Bare IP target: subdomain, Host-header, vhost, and SNI-aware testing are limited.")
    if not results.get("subdomains"):
        limitations.append("No subdomains discovered from current input/scope.")

    assessments: List[Dict[str, Any]] = []
    for p in _ports(results):
        host = str(p.get("host") or target)
        port = int(p.get("port") or 0)
        svc = str(p.get("service") or "unknown")
        label = _service_label(svc, port)
        base = {"service_id": _service_key(host, port, label), "host": host, "port": port, "service": label, "state": p.get("state") or "open", "version_or_banner": p.get("version") or p.get("banner") or ""}
        if label == "SSH":
            detail = _assess_ssh(host, port, p, results)
        elif label in ("HTTP", "HTTPS"):
            detail = _assess_http(host, port, p, results)
            if port in (443, 8443) or label == "HTTPS":
                tls_detail = _assess_tls(host, port, results)
                for k in ("observed", "negative_results", "operator_notes", "verification_targets", "artifacts"):
                    for item in tls_detail.get(k) or []:
                        _add_unique(detail[k], item)
                detail["candidate_findings"].extend(tls_detail.get("candidate_findings") or [])
                detail["tools"].extend(tls_detail.get("tools") or [])
        else:
            rows = _service_rows_for(host, port, results)
            detail = {"observed": [p.get("version") or p.get("banner") or f"{label} service exposed"], "negative_results": [], "candidate_findings": [], "operator_notes": [], "verification_targets": [f"Review {label} service-specific artifacts and validate configuration manually."], "artifacts": [], "tools": _service_tools(rows)}
            for row in rows:
                if row.get("artifact_path"):
                    _add_unique(detail["artifacts"], row.get("artifact_path"))
                for f in row.get("findings") or []:
                    if isinstance(f, dict) and not _completion_only(_finding_type(f)):
                        detail["candidate_findings"].append({"status": "candidate", "severity": "medium", "title": _finding_type(f).replace("_", " ").title(), "evidence": _finding_values(f) or _finding_type(f)})
        base.update(detail)
        assessments.append(base)

    candidates: List[Dict[str, Any]] = []
    negatives: List[str] = []
    verification: List[Dict[str, Any]] = []
    artifacts: List[str] = []
    for a in assessments:
        for c in a.get("candidate_findings") or []:
            row = dict(c)
            row.update({"service": a["service"], "asset": f"{a['host']}:{a['port']}"})
            candidates.append(row)
        for n in a.get("negative_results") or []:
            negatives.append(f"{a['service']} {a['host']}:{a['port']}: {n}")
        for v in a.get("verification_targets") or []:
            verification.append({"service": a["service"], "asset": f"{a['host']}:{a['port']}", "action": v})
        for art in a.get("artifacts") or []:
            _add_unique(artifacts, art)

    return {"target": target, "target_type": target_type, "limitations": limitations, "assessments": assessments, "candidate_findings": candidates, "negative_results": negatives, "verification_targets": verification, "artifacts": artifacts, "summary": {"services": len(assessments), "candidate_findings": len(candidates), "limitations": len(limitations), "artifacts": len(artifacts)}}
