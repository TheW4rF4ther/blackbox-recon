"""Blackbox Recon - AI-Augmented Reconnaissance for Penetration Testers."""

__version__ = "1.0.0"
__author__ = "Blackbox Intelligence Group LLC"
__email__ = "info@blackboxintelgroup.com"
__license__ = "MIT"

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
    """Patch CLI banner art without touching CLI scanner logic."""
    try:
        from . import cli as _cli
        _cli.BANNER_ART = BLACKBOX_RECON_BANNER_ART
    except Exception:
        # Banner branding must never prevent package import or recon execution.
        pass


_patch_cli_banner()

__all__ = ["ReconEngine", "AIAnalyzer", "Config"]
