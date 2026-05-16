"""Runtime patch to print compact pentester triage after recon enrichment."""

from __future__ import annotations

import sys
import time
from functools import wraps
from typing import Any, Dict, List

from .operator_progress import console as progress_console
from .operator_progress import progress_enabled
from .triage_dashboard import render_triage_dashboard


_NOISY_RECON_TOKENS = (
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

_PROGRESS_PHASES = (
    ("_run_http_header_enrichment", "HTTP header posture"),
    ("_run_tls_enrichment", "TLS posture"),
    ("_run_service_enrichment", "Service-specific enumeration"),
    ("_run_web_fingerprint_enrichment", "Web fingerprinting"),
    ("_run_cms_enrichment", "CMS/app-aware enumeration"),
    ("_run_vuln_intel_enrichment", "Vulnerability intelligence"),
    ("_run_dns_enrichment", "DNS enrichment"),
    ("_run_screenshot_triage", "Screenshot triage"),
)


def _is_noisy_recon_text(text: str) -> bool:
    stripped = (text or "").strip()
    return any(tok in text for tok in _NOISY_RECON_TOKENS) or stripped.startswith("─") or stripped.startswith("·") or stripped.startswith("→") or stripped.startswith("====")


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
    """Suppress detailed phase chatter in normal mode."""
    cli_mod = sys.modules.get("blackbox_recon.cli") or sys.modules.get("src.blackbox_recon.cli")
    if cli_mod is None or not hasattr(cli_mod, "console"):
        return
    console = cli_mod.console
    if getattr(console, "_blackbox_phase_suppressor", False):
        return

    original_print = console.print

    def filtered_print(*objects: Any, **kwargs: Any) -> None:
        text = " ".join(str(o) for o in objects)
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
        if _is_noisy_recon_text(text):
            return
        return original_print(*objects, **kwargs)

    console.print = filtered_print
    console._blackbox_phase_suppressor = True


def _install_recon_rprint_suppressor() -> None:
    """Patch recon.py's rich.print alias and trace echo for default quiet mode."""
    recon_mod = sys.modules.get("blackbox_recon.recon") or sys.modules.get("src.blackbox_recon.recon")
    if recon_mod is None or getattr(recon_mod, "_blackbox_rprint_suppressor", False):
        return

    original_rprint = getattr(recon_mod, "rprint", None)
    if callable(original_rprint):
        def filtered_rprint(*objects: Any, **kwargs: Any) -> None:
            text = " ".join(str(o) for o in objects)
            if _is_noisy_recon_text(text):
                return
            return original_rprint(*objects, **kwargs)

        recon_mod.rprint = filtered_rprint

    try:
        original_phase_tracer = recon_mod.PhaseTracer
        if not getattr(original_phase_tracer, "_blackbox_quiet_init", False):
            original_init = original_phase_tracer.__init__

            def quiet_init(self: Any, results: Dict[str, Any], *, echo: bool = True) -> None:
                return original_init(self, results, echo=False)

            original_phase_tracer.__init__ = quiet_init
            original_phase_tracer._blackbox_quiet_init = True
    except Exception:
        pass

    def quiet_execution_recap(results: Dict[str, Any], *, echo: bool = True) -> None:
        return None

    recon_mod.print_execution_recap = quiet_execution_recap
    recon_mod._blackbox_rprint_suppressor = True


def _install_enrichment_progress_wrappers() -> None:
    """Wrap long enrichment phases with compact operator progress messages."""
    if not progress_enabled():
        return
    mod = sys.modules.get("blackbox_recon.posture_enrichment") or sys.modules.get("src.blackbox_recon.posture_enrichment")
    if mod is None or getattr(mod, "_blackbox_progress_wrapped", False):
        return

    total = len(_PROGRESS_PHASES)
    state = {"idx": 0}

    def _make_wrapper(fn: Any, label: str):
        @wraps(fn)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            state["idx"] += 1
            idx = state["idx"]
            start = time.monotonic()
            progress_console.print(f"[cyan][{idx}/{total}][/cyan] [bold]Recon progress:[/bold] {label} [dim](running)[/dim]")
            if label == "CMS/app-aware enumeration":
                progress_console.print("[dim]    CMS probes and WPScan can take a few minutes on lab targets.[/dim]")
            elif label == "Vulnerability intelligence":
                progress_console.print("[dim]    Checking local SearchSploit and NVD/NIST candidate CVE leads.[/dim]")
            try:
                result = await fn(*args, **kwargs)
                elapsed = time.monotonic() - start
                progress_console.print(f"[green][{idx}/{total}][/green] {label} complete [dim]({elapsed:.1f}s)[/dim]")
                return result
            except Exception as exc:
                elapsed = time.monotonic() - start
                progress_console.print(f"[red][{idx}/{total}][/red] {label} failed after {elapsed:.1f}s: {exc}")
                raise
        return wrapped

    for func_name, label in _PROGRESS_PHASES:
        fn = getattr(mod, func_name, None)
        if callable(fn) and not getattr(fn, "_blackbox_progress_wrapped", False):
            wrapped = _make_wrapper(fn, label)
            wrapped._blackbox_progress_wrapped = True
            setattr(mod, func_name, wrapped)

    mod._blackbox_progress_wrapped = True


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
        _install_default_phase_suppressor()
        _install_recon_rprint_suppressor()
        _install_enrichment_progress_wrappers()
        results = await original_run(self, target, modules)
        try:
            render_triage_dashboard(results)
            _install_legacy_terminal_suppressor()
            return DashboardAwareResults(results)
        except Exception as exc:
            try:
                from rich import print as rprint
                rprint(f"[yellow][!][/yellow] Triage dashboard failed to render: {exc}")
            except Exception:
                pass
        return results

    ReconEngine.run = run_with_operator_dashboard
    ReconEngine._blackbox_operator_dashboard_patched = True
