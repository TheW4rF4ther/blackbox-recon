"""Runtime patch to print the operator dashboard after recon enrichment."""

from __future__ import annotations

from typing import Any, Dict, List

from .operator_dashboard import render_operator_dashboard


def patch_operator_dashboard(ReconEngine: Any) -> None:
    """Patch ReconEngine.run once so dashboard renders after the full result exists."""
    if getattr(ReconEngine, "_blackbox_operator_dashboard_patched", False):
        return

    original_run = ReconEngine.run

    async def run_with_operator_dashboard(self: Any, target: str, modules: List[str]) -> Dict[str, Any]:
        results = await original_run(self, target, modules)
        try:
            render_operator_dashboard(results)
        except Exception as exc:  # dashboard must never fail the scan
            try:
                from rich import print as rprint
                rprint(f"[yellow][!][/yellow] Operator dashboard failed to render: {exc}")
            except Exception:
                pass
        return results

    ReconEngine.run = run_with_operator_dashboard
    ReconEngine._blackbox_operator_dashboard_patched = True
