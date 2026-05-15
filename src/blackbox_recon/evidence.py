"""Typed evidence and deterministic findings — application-owned, AI-enrichable only."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

ObservationType = Literal[
    "open_port",
    "service_banner",
    "http_response",
    "dns_record",
    "directory_hit",
    "tls_observation",
    "technology_fingerprint",
    "negative_result",
    "tool_error",
    "coverage_context",
    "vulnerability_signal",
]

Confidence = Literal["high", "medium", "low"]
Severity = Literal["critical", "high", "medium", "low", "informational"]
FindingStatus = Literal["confirmed", "candidate", "not_observed", "unclear"]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _target_is_bare_ip(target: str) -> bool:
    t = (target or "").strip()
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def _http_like_port_row(p: Dict[str, Any]) -> bool:
    port = int(p.get("port") or 0)
    svc = (p.get("service") or "").lower()
    if port in (80, 443, 8080, 8443, 8000, 8888, 8880, 9443):
        return True
    if "http" in svc or svc in ("https", "ssl/http", "http-proxy"):
        return True
    return False


def _version_is_precise(version: Any) -> bool:
    """True when a banner is version-specific enough to support CVE triage."""
    if version is None:
        return False
    v = str(version).strip().lower()
    if not v or v in ("unknown", "none", "null", "n/a"):
        return False
    # Product-only banners such as "nginx" are useful inventory but not precise
    # enough for patch or CVE confidence.
    return bool(re.search(r"\d", v))


class EvidenceRecord(BaseModel):
    id: str
    phase_id: str
    source_tool: str
    command: Optional[str] = None
    target: str
    asset: str
    observation_type: ObservationType
    observed_value: Dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence = "medium"
    timestamp_utc: str = Field(default_factory=_utc_now_iso)
    raw_ref: Optional[str] = None


class Finding(BaseModel):
    id: str
    finding_code: Optional[str] = None
    title: str
    severity: Severity
    status: FindingStatus
    affected_assets: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    impact: str
    recommendation: str
    validation: str
    confidence: Confidence = "medium"


def build_evidence_records(results: Dict[str, Any]) -> List[EvidenceRecord]:
    """Normalize recon ``results`` into stable evidence rows with EVID-* identifiers."""
    target = str(results.get("target") or "")
    out: List[EvidenceRecord] = []
    counters: Dict[str, int] = {}

    def _next_id(phase: str) -> str:
        counters[phase] = counters.get(phase, 0) + 1
        return f"EVID-{phase}-{counters[phase]:03d}"

    if _target_is_bare_ip(target):
        out.append(
            EvidenceRecord(
                id=_next_id("CTX"),
                phase_id="CTX",
                source_tool="blackbox_recon",
                command=None,
                target=target,
                asset=target,
                observation_type="coverage_context",
                observed_value={
                    "target_type": "bare_ip",
                    "dns_bruteforce_expected_yield": "low",
                    "recommended_scope_input": "apex hostname or explicit hostname list when available",
                },
                confidence="high",
                raw_ref="scan_context",
            )
        )

    # M1 — subdomains (only rows with DNS or HTTP signal to avoid empty-label noise)
    for i, s in enumerate(results.get("subdomains") or []):
        if not isinstance(s, dict):
            continue
        host = str(s.get("subdomain") or "")
        ips = s.get("ip_addresses") or []
        if not ips and s.get("status_code") is None:
            continue
        out.append(
            EvidenceRecord(
                id=_next_id("M1"),
                phase_id="M1",
                source_tool="blackbox_recon.subdomain",
                command=None,
                target=target,
                asset=host or target,
                observation_type="dns_record",
                observed_value={"a_records": ips, "http_status": s.get("status_code")},
                confidence="high" if ips else "medium",
                raw_ref=f"subdomains[{i}]",
            )
        )

    # M2 — nslookup
    for i, row in enumerate((results.get("dns_intelligence") or {}).get("nslookups") or []):
        if not isinstance(row, dict):
            continue
        tgt = str(row.get("target") or target)
        out.append(
            EvidenceRecord(
                id=_next_id("M2"),
                phase_id="M2",
                source_tool="nslookup",
                command=str(row.get("command") or "") or None,
                target=target,
                asset=tgt,
                observation_type="dns_record",
                observed_value={
                    "status": row.get("status"),
                    "parsed": row.get("parsed") or {},
                },
                confidence="high" if row.get("status") == "ok" else "medium",
                raw_ref=f"dns_intelligence.nslookups[{i}]",
            )
        )

    # M3 — ports
    for i, p in enumerate(results.get("ports") or []):
        if not isinstance(p, dict):
            continue
        host = str(p.get("host") or "")
        port = int(p.get("port") or 0)
        asset = f"{host}:{port}/tcp" if host and port else host or target
        obs_type: ObservationType = "open_port"
        if p.get("banner") or p.get("version"):
            obs_type = "service_banner"
        out.append(
            EvidenceRecord(
                id=_next_id("M3"),
                phase_id="M3",
                source_tool="nmap",
                command=None,
                target=target,
                asset=asset,
                observation_type=obs_type,
                observed_value={
                    "state": p.get("state"),
                    "service": p.get("service"),
                    "version": p.get("version"),
                    "banner": (p.get("banner") or "")[:400] or None,
                },
                confidence="high",
                raw_ref=f"ports[{i}]",
            )
        )

    # M4 — directory scans
    scans = (results.get("web_content_discovery") or {}).get("directory_scans") or []
    for i, run in enumerate(scans):
        if not isinstance(run, dict):
            continue
        base = str(run.get("base_url") or "")
        hits = run.get("findings_interesting") or []
        if hits:
            for j, h in enumerate(hits[:20]):
                if not isinstance(h, dict):
                    continue
                out.append(
                    EvidenceRecord(
                        id=_next_id("M4"),
                        phase_id="M4",
                        source_tool=str(run.get("tool") or "gobuster"),
                        command=str(run.get("command") or "") or None,
                        target=target,
                        asset=f"{base}{h.get('path', '')}",
                        observation_type="directory_hit",
                        observed_value=dict(h),
                        confidence="high",
                        raw_ref=f"web_content_discovery.directory_scans[{i}].findings_interesting[{j}]",
                    )
                )
        else:
            out.append(
                EvidenceRecord(
                    id=_next_id("M4"),
                    phase_id="M4",
                    source_tool=str(run.get("tool") or "directory_scan"),
                    command=str(run.get("command") or "") or None,
                    target=target,
                    asset=base or target,
                    observation_type="negative_result",
                    observed_value={
                        "interesting_paths_found": 0,
                        "status": run.get("status"),
                    },
                    confidence="medium",
                    raw_ref=f"web_content_discovery.directory_scans[{i}]",
                )
            )

    # M5 — technologies
    for i, tech in enumerate(results.get("technologies") or []):
        if not isinstance(tech, dict):
            continue
        url = str(tech.get("url") or "")
        out.append(
            EvidenceRecord(
                id=_next_id("M5"),
                phase_id="M5",
                source_tool="requests_fingerprint",
                command=None,
                target=target,
                asset=url,
                observation_type="technology_fingerprint",
                observed_value={"technologies": tech.get("technologies") or []},
                confidence="medium",
                raw_ref=f"technologies[{i}]",
            )
        )

    return out


def build_deterministic_findings(evidence: List[EvidenceRecord], results: Dict[str, Any]) -> List[Finding]:
    """Application-owned findings derived only from evidence (no LLM)."""
    target = str(results.get("target") or "")
    findings: List[Finding] = []
    n = 1

    def _fid() -> str:
        nonlocal n
        cur = f"DET-FIND-{n:03d}"
        n += 1
        return cur

    # Exposed SSH (aggregate all SSH listeners)
    ssh_rows: List[EvidenceRecord] = []
    for e in evidence:
        if e.phase_id != "M3" or e.observation_type not in ("open_port", "service_banner"):
            continue
        svc = str((e.observed_value or {}).get("service") or "").lower()
        m = re.search(r":(\d+)/tcp", e.asset)
        port = int(m.group(1)) if m else 0
        if port == 22 or svc == "ssh":
            ssh_rows.append(e)
    if ssh_rows:
        findings.append(
            Finding(
                id=_fid(),
                finding_code="BBR-EXPOSURE-001",
                title="Internet-exposed SSH service",
                severity="medium",
                status="confirmed",
                affected_assets=[e.asset for e in ssh_rows],
                evidence_ids=[e.id for e in ssh_rows],
                impact="Remote administration surface reachable from the scanned perspective.",
                recommendation="Restrict by firewall/VPN, enforce key-based auth, disable weak ciphers, keep OpenSSH patched.",
                validation="Re-scan from an authorized vantage; verify sshd_config and listening interfaces.",
                confidence="high",
            )
        )

    # Exposed HTTP(S)
    web_evidence: List[EvidenceRecord] = []
    for e in evidence:
        if e.phase_id != "M3" or e.observation_type not in ("open_port", "service_banner"):
            continue
        m = re.search(r":(\d+)/tcp", e.asset)
        port = int(m.group(1)) if m else 0
        svc = str((e.observed_value or {}).get("service") or "")
        if _http_like_port_row({"port": port, "service": svc}):
            web_evidence.append(e)
    if web_evidence:
        assets = [e.asset for e in web_evidence]
        findings.append(
            Finding(
                id=_fid(),
                finding_code="BBR-EXPOSURE-002",
                title="Internet-exposed HTTP/HTTPS service",
                severity="medium",
                status="confirmed",
                affected_assets=assets,
                evidence_ids=[e.id for e in web_evidence],
                impact="Public web surface increases exposure to misconfiguration and application-layer risk.",
                recommendation="Verify patch level, TLS configuration, security headers, and attack surface of deployed apps.",
                validation="Review nginx/http configs and dependency versions from an authenticated assessment if in scope.",
                confidence="medium",
            )
        )

    # Version fingerprint incomplete (HTTP-like services with product-only or missing version detail)
    for e in web_evidence:
        ver = (e.observed_value or {}).get("version")
        svc = str((e.observed_value or {}).get("service") or "").lower()
        m = re.search(r":(\d+)/tcp", e.asset)
        port = int(m.group(1)) if m else 0
        if _http_like_port_row({"port": port, "service": svc}) and not _version_is_precise(ver):
            findings.append(
                Finding(
                    id=_fid(),
                    finding_code="BBR-FP-001",
                    title="Service fingerprint incomplete for web stack",
                    severity="informational",
                    status="confirmed",
                    affected_assets=[e.asset],
                    evidence_ids=[e.id],
                    impact="CVE correlation and patch urgency are harder to establish without a precise product version.",
                    recommendation="Run an in-scope version probe (e.g. authenticated config review or allowed banner enrichment).",
                    validation="Confirm whether a precise version string becomes available with additional safe probes.",
                    confidence="high",
                )
            )
            break

    # Directory bruteforce interesting hits
    dir_hits = [e for e in evidence if e.observation_type == "directory_hit"]
    if dir_hits:
        findings.append(
            Finding(
                id=_fid(),
                finding_code="BBR-WEB-001",
                title="Web content discovery identified sensitive or notable paths",
                severity="medium",
                status="confirmed",
                affected_assets=[e.asset for e in dir_hits[:25]],
                evidence_ids=[e.id for e in dir_hits[:25]],
                impact="Exposed paths may indicate backup files, admin interfaces, or unintended content.",
                recommendation="Validate ownership and sensitivity of each path; remove or restrict as appropriate.",
                validation="Manually review each hit under ROE before interaction.",
                confidence="high",
            )
        )

    # Negative directory result (aggregate one informational)
    neg_dirs = [e for e in evidence if e.observation_type == "negative_result" and e.phase_id == "M4"]
    if neg_dirs and not dir_hits:
        findings.append(
            Finding(
                id=_fid(),
                finding_code="BBR-WEB-NEG-001",
                title="Directory discovery found no flagged interesting paths",
                severity="informational",
                status="not_observed",
                affected_assets=list({e.asset for e in neg_dirs}),
                evidence_ids=[e.id for e in neg_dirs],
                impact="Reduces evidence of common sensitive paths; does not prove absence of sensitive endpoints.",
                recommendation="Continue assessment with authenticated crawling or manual review if authorized.",
                validation="Compare against application map and unauthenticated crawl limits.",
                confidence="medium",
            )
        )

    # Bare IP — DNS coverage
    if _target_is_bare_ip(target):
        ctx_ids = [e.id for e in evidence if e.observation_type == "coverage_context" and e.phase_id == "CTX"]
        findings.append(
            Finding(
                id=_fid(),
                finding_code="BBR-COVERAGE-001",
                title="Bare IP target limits hostname-oriented discovery",
                severity="informational",
                status="confirmed",
                affected_assets=[target],
                evidence_ids=ctx_ids,
                impact="Subdomain-style labels against an IP are usually low-yield versus an apex domain.",
                recommendation="When possible, scope an apex hostname for DNS and web asset mapping.",
                validation="Re-run subdomain module against the domain apex if in scope.",
                confidence="high",
            )
        )

    return findings


def build_deterministic_attack_paths(findings: List[Finding]) -> List[Dict[str, Any]]:
    """High-level, non-operational paths derived from confirmed exposure findings."""
    paths: List[Dict[str, Any]] = []
    ssh = next((f for f in findings if f.finding_code == "BBR-EXPOSURE-001"), None)
    web = next((f for f in findings if f.finding_code == "BBR-EXPOSURE-002"), None)
    if ssh:
        paths.append(
            {
                "entry_point": ssh.affected_assets[0] if ssh.affected_assets else "SSH",
                "risk_chain": "Network-reachable SSH may be targeted for authentication attacks if weak controls exist.",
                "potential_impact": "Host compromise and lateral movement if credentials or configuration are weak.",
                "confidence": "medium",
                "defensive_priority": "P1",
                "evidence_ids": ssh.evidence_ids,
            }
        )
    if web:
        paths.append(
            {
                "entry_point": ", ".join(web.affected_assets[:6]) if web.affected_assets else "HTTP(S)",
                "risk_chain": "Public web services may expose misconfigurations or vulnerable application components.",
                "potential_impact": "Data exposure, defacement, or downstream compromise depending on application risk.",
                "confidence": "medium",
                "defensive_priority": "P2",
                "evidence_ids": web.evidence_ids,
            }
        )
    return paths


def build_coverage_notes(results: Dict[str, Any], evidence: List[EvidenceRecord]) -> List[str]:
    notes: List[str] = []
    target = str(results.get("target") or "")
    if _target_is_bare_ip(target):
        notes.append("Target is a bare IP; hostname-oriented subdomain discovery is expected to be low-yield.")
    tech_ct = len(results.get("technologies") or [])
    if tech_ct == 0:
        notes.append("No enriched technology profiles were stored (fingerprinting may be inconclusive or blocked).")
    for e in evidence:
        if e.phase_id != "M3":
            continue
        v = (e.observed_value or {}).get("version")
        svc = str((e.observed_value or {}).get("service") or "").lower()
        m = re.search(r":(\d+)/tcp", e.asset)
        port = int(m.group(1)) if m else 0
        if _http_like_port_row({"port": port, "service": svc}) and not _version_is_precise(v):
            notes.append("At least one HTTP-like service was detected without a precise version string in scan output.")
            break
    return notes


def build_evidence_package(
    results: Dict[str, Any], modules: List[str], *, lab_mode: bool = False
) -> Dict[str, Any]:
    """Single machine-readable bundle for automation, AI input, and audit."""
    evidence = build_evidence_records(results)
    findings = build_deterministic_findings(evidence, results)
    attack_paths = build_deterministic_attack_paths(findings)
    target = str(results.get("target") or "")
    summary = results.get("summary") or {}
    return {
        "schema_version": "1.1",
        "assessment": {
            "target": target,
            "mode": "lab" if lab_mode else "engaged",
            "authorization_context": (
                "Lab mode; engagement gates disabled" if lab_mode else "Engagement-gated execution"
            ),
            "modules_executed": modules,
            "recon_started_utc": results.get("recon_started_utc"),
            "recon_completed_utc": results.get("recon_completed_utc"),
            "summary_metrics": {
                "open_tcp_ports": summary.get("total_open_ports", 0),
                "http_services_detected": summary.get("http_services_detected", 0),
                "http_urls_targeted": summary.get("http_urls_targeted", summary.get("web_urls_targeted", 0)),
                "subdomain_http_probes_with_status": summary.get("subdomain_http_probes_with_status", 0),
                "technology_profiles_stored": summary.get("technology_profiles_stored", 0),
            },
        },
        "evidence": [e.model_dump() for e in evidence],
        "deterministic_findings": [f.model_dump() for f in findings],
        "deterministic_attack_paths": attack_paths,
        "coverage_notes": build_coverage_notes(results, evidence),
    }
