"""Runtime patch to print compact pentester triage after recon enrichment."""

from __future__ import annotations

import sys
from typing import Any, Dict, List

from .triage_dashboard import render_triage_dashboard


def _install_legacy_terminal_suppressor() -> None:
    """Suppress legacy CLI sections after the new triage dashboard renders.

    cli.py still contains older post-run tables. The new dashboard is now the
    authoritative terminal output, so this suppressor drops only those duplicate
    legacy prints while preserving report writing and the final saved-path line.
    """
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


class DashboardAwareResults(dict):
    """Suppress old duplicate CLI tables while preserving saved JSON data."""

    def __init__(self, source: Dict[str, Any]):
        super().__init__(source)
        self["operator_dashboard_rendered"] = True
        # Suppress the old legacy phase table and old truncated findings table
        # printed by cli.py immediately after engine.run(). JSON/report data is
        # still present for saved output and downstream processing.
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
