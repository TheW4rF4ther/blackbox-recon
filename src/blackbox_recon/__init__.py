"""Blackbox Recon - AI-Augmented Reconnaissance for Penetration Testers."""

__version__ = "1.0.0"
__author__ = "Blackbox Intelligence Group LLC"
__email__ = "info@blackboxintelgroup.com"
__license__ = "MIT"

BLACKBOX_RECON_BANNER_COLOR = "#b45309"

BLACKBOX_RECON_BANNER_ART = r"""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗  ██████╗ ██╗  ██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗╚██╗██╔╝
██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║ ╚███╔╝
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║ ██╔██╗
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██╔╝ ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

                         BLACKBOX RECON
""".strip("\n")

from .recon import ReconEngine
from .posture_enrichment import patch_recon_engine
from .dashboard_patch import patch_operator_dashboard

patch_recon_engine(ReconEngine)
patch_operator_dashboard(ReconEngine)

from .ai_analyzer import AIAnalyzer
from .config import Config


def _patch_cli_banner() -> None:
    """Patch CLI banner art/style without touching CLI scanner logic."""
    try:
        from . import cli as _cli
        from rich.panel import Panel
        from rich.text import Text

        _cli.BANNER_ART = BLACKBOX_RECON_BANNER_ART

        def print_banner() -> None:
            banner = Text()
            banner.append(BLACKBOX_RECON_BANNER_ART, style=f"bold {BLACKBOX_RECON_BANNER_COLOR}")
            banner.append("\n\n")
            banner.append("AI-Augmented Reconnaissance for Pentesters", style="bold bright_white")
            banner.append("\n")
            banner.append("by Blackbox Intelligence Group LLC", style="dim")

            _cli.console.print()
            _cli.console.print(
                Panel(
                    banner,
                    title=f"[bold {BLACKBOX_RECON_BANNER_COLOR}]Blackbox Recon[/bold {BLACKBOX_RECON_BANNER_COLOR}]",
                    subtitle="[dim]Evidence-driven reconnaissance[/dim]",
                    border_style=BLACKBOX_RECON_BANNER_COLOR,
                    padding=(1, 2),
                )
            )
            _cli.console.print()

        _cli.print_banner = print_banner
    except Exception:
        # Banner branding must never prevent package import or recon execution.
        pass


_patch_cli_banner()

__all__ = ["ReconEngine", "AIAnalyzer", "Config"]
