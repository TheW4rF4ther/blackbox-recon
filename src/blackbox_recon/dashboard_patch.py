"""Runtime patch to print the operator dashboard after recon enrichment."""

from __future__ import annotations

from typing import Any, Dict, List

from .operator_dashboard import render_operator_dashboard


class DashboardAwareResults(dict):
    """Suppress the old duplicate CLI tables while preserving saved JSON data."""

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
    """Patch ReconEngine.run once so dashboard renders after the full result exists."""
    if getattr(ReconEngine, "_blackbox_operator_dashboard_patched", False):
        return

    original_run = ReconEngine.run

    async def run_with_operator_dashboard(self: Any, target: str, modules: List[str]) -> Dict[str, Any]:
        results = await original_run(self, target, modules)
        try:
            render_operator_dashboard(results)
            return DashboardAwareResults(results)
        except Exception as exc:  # dashboard must never fail the scan
            try:
                from rich import print as rprint
                rprint(f"[yellow][!][/yellow] Operator dashboard failed to render: {exc}")
            except Exception:
                pass
        return results

    ReconEngine.run = run_with_operator_dashboard
    ReconEngine._blackbox_operator_dashboard_patched = True
