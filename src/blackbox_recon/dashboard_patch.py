"""Runtime patch to print compact pentester triage after recon enrichment."""

from __future__ import annotations

import sys
from typing import Any, Dict, List

from .triage_dashboard import render_triage_dashboard


def _install_legacy_terminal_suppressor() -> None:
    """Suppress legacy CLI sections after the new triage dashboard renders."""
    cli_mod = sys.modules.get("blackbox_recon.cli") or sys.modules.get("src.blackbox_recon.cli")
    if cli_mod is None or not hasattr(cli_mod, "console"):
        return
    console = cli_mod.console
    if getattr(console, "_blackbox_legacy_suppressor", False):
        return

    original_print = console.print
    state = {"suppress_open_port_lines": 0}

    def _title_of(obj: Any) -> str:
        title = getattr(obj, "title", "")
        return str(title or "")

    def filtered_print(*objects: Any, **kwargs: Any) -> None:
        if state["suppress_open_port_lines"] > 0:
            text = " ".join(str(o) for o in objects)
            if text.strip().startswith("-") or text.strip().startswith("•"):
                state["suppress_open_port_lines"] -= 1
                return
            state["suppress_open_port_lines"] = 0

        for obj in objects:
            text = str(obj)
            title = _title_of(obj)
            if "Reconnaissance Summary" in text:
                return
            if "AI — recommended follow-up tools" in text:
                return
            if "Validate against ROE/scope before running any command" in text:
                return
            if "Open Ports:" in text:
                state["suppress_open_port_lines"] = 8
                return
            if "Suggested next moves" in title or "Counts" in title:
                return
        return original_print(*objects, **kwargs)

    console.print = filtered_print
    console._blackbox_legacy_suppressor = True


def _install_default_phase_suppressor() -> None:
    """Suppress detailed phase chatter in normal mode.

    The phase trace remains in JSON/Markdown artifacts. The default terminal
    should behave like an operator console, not a verbose debug log.
    """
    cli_mod = sys.modules.get("blackbox_recon.cli") or sys.modules.get("src.blackbox_recon.cli")
    if cli_mod is None or not hasattr(cli_mod, "console"):
        return
    console = cli_mod.console
    if getattr(console, "_blackbox_phase_suppressor", False):
        return

    original_print = console.print

    def filtered_print(*objects: Any, **kwargs: Any) -> None:
        text = " ".join(str(o) for o in objects)
        stripped = text.strip()

        keep_tokens = (
            "Blackbox Recon",
            "Notice",
            "[*] Running reconnaissance",
            "[+] Starting reconnaissance",
            "Operator Assessment",
            "Scope & Limitations",
            "Executive Recon Snapshot",
            "Attack Surface",
            "Service Assessments",
            "Service Findings",
            "Negative / Inconclusive Summary",
            "Technical Verification Targets",
            "Evidence Artifacts",
            "Tester Takeaway",
            "AI analysis",
            "[AI] Applied",
            "Attack surface analysis",
            "Results saved to",
            "Done. Stay safe",
            "Interrupted by user",
            "Error:",
        )
        if any(tok in text for tok in keep_tokens):
            return original_print(*objects, **kwargs)

        noisy_tokens = (
            "PTES M",
            "Intelligence Gathering",
            "Threat Modeling",
            "Vulnerability Analysis",
            "Objective:",
            "Stack:",
            "Wordlist:",
            "Wordlist path:",
            "Tool preference:",
            "Configured port_scan_mode:",
            "Targets:",
            "Service enrichment:",
            "method:",
            "nmap_binary:",
            "nmap_profile:",
            "nmap_aggressive:",
            "nmap_ssh_algorithms:",
            "nmap_http_safe_scripts:",
            "nikto_http:",
            "ssh_audit:",
            "whatweb:",
            "wafw00f:",
            "dns_PTR:",
            "tls_probe:",
            "requests_headers:",
            "requests_fingerprint:",
            "python_http_probe:",
            "nslookup:",
            "screenshot:",
            "Execution recap",
            "Phase complete",
            "Reconnaissance complete",
            "Service and web posture enrichment complete",
            "Subdomains:",
            "Open TCP ports:",
            "HTTP header URLs:",
            "Running nslookup",
            "Enumerating subdomains",
            "Found 0 valid subdomains",
            "Default port scan:",
            "nmap aggressive scan",
            "Web content discovery on",
            "feroxbuster:",
        )
        if any(tok in text for tok in noisy_tokens):
            return
        if stripped.startswith("─") or stripped.startswith("·") or stripped.startswith("→") or stripped.startswith("===="):
            return

        return original_print(*objects, **kwargs)

    console.print = filtered_print
    console._blackbox_phase_suppressor = True


class DashboardAwareResults(dict):
    """Suppress old duplicate CLI tables while preserving saved JSON data."""

    def __init__(self, source: Dict[str, Any]):
        super().__init__(source)
        self["operator_dashboard_rendered"] = True
        self._suppress_once = {"recon_phase_trace": 1, "deterministic_findings": 1}

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        if key in self._suppress_once and self._suppress_once[key] > 0:
            self._suppress_once[key] -= 1
            return []
        return super().get(key, default)


def patch_operator_dashboard(ReconEngine: Any) -> None:
    """Patch ReconEngine.run once so compact triage renders after the full result exists."""
    if getattr(ReconEngine, "_blackbox_operator_dashboard_patched", False):
        return

    original_run = ReconEngine.run

    async def run_with_operator_dashboard(self: Any, target: str, modules: List[str]) -> Dict[str, Any]:
        # Install immediately before scanning, when cli.py/console definitely exists.
        _install_default_phase_suppressor()
        results = await original_run(self, target, modules)
        try:
            render_triage_dashboard(results)
            _install_legacy_terminal_suppressor()
            return DashboardAwareResults(results)
        except Exception as exc:  # dashboard must never fail the scan
            try:
                from rich import print as rprint
                rprint(f"[yellow][!][/yellow] Triage dashboard failed to render: {exc}")
            except Exception:
                pass
        return results

    ReconEngine.run = run_with_operator_dashboard
    ReconEngine._blackbox_operator_dashboard_patched = True
