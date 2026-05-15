"""Penetration-test recon methodology metadata (aligned with common PTES-style phases)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass(frozen=True)
class MethodologyPhase:
    phase_id: str
    name: str
    ptes_mapping: str
    description: str
    engine_hooks: Tuple[str, ...]
    external_tools: Tuple[str, ...]


# Ordered phases the ReconEngine currently implements (vulnscan reserved).
DEFAULT_PHASES: Tuple[MethodologyPhase, ...] = (
    MethodologyPhase(
        "M1",
        "Attack surface mapping (DNS names)",
        "Intelligence Gathering > Identify the Target > DNS analysis",
        "Brute-force common subhost labels against the apex domain and resolve A records.",
        ("subdomain_enumeration",),
        (),
    ),
    MethodologyPhase(
        "M2",
        "DNS intelligence",
        "Intelligence Gathering > Network footprinting",
        "Forward/reverse DNS hints via nslookup for each in-scope IP and the apex string.",
        ("nslookup",),
        ("nslookup",),
    ),
    MethodologyPhase(
        "M3",
        "Network service enumeration",
        "Threat Modeling / Vulnerability Analysis > Network-level discovery",
        "Full TCP discovery with Nmap (-p- -A --open) when available, else frequency-ordered TCP connect scan.",
        ("port_scan",),
        ("nmap",),
    ),
    MethodologyPhase(
        "M4",
        "Web content discovery",
        "Intelligence Gathering > Web application reconnaissance",
        "Directory and file brute-force on discovered HTTP(S) URLs using Kali-native gobuster or dirb.",
        ("directory_scan",),
        ("gobuster", "dirb"),
    ),
    MethodologyPhase(
        "M5",
        "Technology identification",
        "Intelligence Gathering > Fingerprinting",
        "Passive HTTP header / HTML fingerprinting for apex and key subdomains.",
        ("technology_detection",),
        (),
    ),
    MethodologyPhase(
        "M6",
        "Attack surface synthesis (AI-assisted)",
        "Reporting / Risk analysis",
        "Optional LLM-assisted correlation of structured recon JSON (provider-configured).",
        ("ai_analysis",),
        (),
    ),
)


def _phase_satisfied(
    phase: MethodologyPhase,
    modules: List[str],
    cfg: Dict[str, Any],
    toolchain: Dict[str, Any],
) -> Tuple[bool, str]:
    tools = toolchain.get("tools") or {}

    if "subdomain_enumeration" in phase.engine_hooks:
        if "subdomain" not in modules:
            return False, "module subdomain not selected"
        return True, "subdomain enumeration enabled"

    if "nslookup" in phase.engine_hooks:
        if "portscan" not in modules:
            return False, "portscan module not selected (nslookup runs with portscan pipeline)"
        if not bool(cfg.get("run_nslookup", True)):
            return False, "recon.run_nslookup is false"
        if not (tools.get("nslookup") or {}).get("present"):
            return False, "nslookup missing on PATH (install dnsutils on Debian/Kali)"
        return True, "nslookup available"

    if "port_scan" in phase.engine_hooks:
        if "portscan" not in modules:
            return False, "portscan module not selected"
        mode = str(cfg.get("port_scan_mode", "nmap_aggressive")).lower()
        if mode == "nmap_aggressive":
            nmap = (tools.get("nmap") or {}).get("present")
            if not nmap:
                return False, "nmap not on PATH (aggressive mode will fall back to TCP connect)"
            return True, "nmap aggressive scan configured"
        return True, "tcp_connect port scan configured"

    if "directory_scan" in phase.engine_hooks:
        if "portscan" not in modules:
            return False, "directory scan is part of portscan pipeline"
        if not bool(cfg.get("directory_scan_enabled", True)):
            return False, "directory_scan_enabled is false"
        pref = str(cfg.get("directory_tool", "auto")).lower()
        if pref == "none":
            return False, "directory_tool is none"
        go = (tools.get("gobuster") or {}).get("present")
        db = (tools.get("dirb") or {}).get("present")
        if pref == "auto":
            if not go and not db:
                return False, "neither gobuster nor dirb on PATH"
            return True, "directory bruteforce tool available"
        if pref == "gobuster" and not go:
            return False, "gobuster not on PATH"
        if pref == "dirb" and not db:
            return False, "dirb not on PATH"
        return True, "directory bruteforce tool available"

    if "technology_detection" in phase.engine_hooks:
        if "technology" not in modules:
            return False, "technology module not selected"
        return True, "HTTP fingerprinting via Python stack"

    if "ai_analysis" in phase.engine_hooks:
        return True, "optional post-processing (CLI ai-mode)"

    return True, "n/a"


def build_methodology_block(
    modules: List[str],
    cfg: Dict[str, Any],
    toolchain_snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for ph in DEFAULT_PHASES:
        ok, detail = _phase_satisfied(ph, modules, cfg, toolchain_snapshot)
        rows.append(
            {
                "phase_id": ph.phase_id,
                "name": ph.name,
                "ptes_mapping": ph.ptes_mapping,
                "description": ph.description,
                "engine_hooks": list(ph.engine_hooks),
                "external_tools": list(ph.external_tools),
                "ready": ok,
                "detail": detail,
            }
        )
    return {
        "framework": "PTES-style recon phases (mapped to Blackbox Recon engine hooks)",
        "phases": rows,
    }
