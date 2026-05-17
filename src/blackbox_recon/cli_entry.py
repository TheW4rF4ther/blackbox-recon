"""Branded CLI entrypoint for Blackbox Recon.

This module keeps the functional CLI in ``blackbox_recon.cli`` untouched,
replaces the startup banner, and handles a tiny pre-parse layer for secrets
that should be available before the main Click command resolves config.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml
from rich.panel import Panel
from rich.text import Text

from . import cli

BANNER_ORANGE = "#d97706"

BLACKBOX_ASCII = r"""
                        ---
                     ---------
                  ---------------
              ----------    ---------
           ----------          ---------
        ---------     -------     ---------
         -----        -------         ----
             ---         -         ----
        --      ----  --    -   ---      --
        -----      -------------      -----
        ---------     +------     ------
        ----  ------           ------
        ----      --           ---      ---
        ------           -           ------
        ----------      --       ----------
           ----------   --    ----------
              ---- ------- ----------
                    --------------
                    -----------
                        ---
""".strip("\n")

RECON_ASCII = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
""".strip("\n")


def print_banner() -> None:
    """Print the Blackbox Recon banner with orange logo art."""
    banner = Text()
    banner.append(BLACKBOX_ASCII, style=f"bold {BANNER_ORANGE}")
    banner.append("\n\n")
    banner.append(RECON_ASCII, style=f"bold {BANNER_ORANGE}")
    banner.append("\n\n")
    banner.append("AI-Augmented Reconnaissance for Pentesters", style="bold bright_white")
    banner.append("\n")
    banner.append("by Blackbox Intelligence Group LLC", style="dim")

    cli.console.print()
    cli.console.print(
        Panel(
            banner,
            title=f"[bold {BANNER_ORANGE}]Blackbox Recon[/bold {BANNER_ORANGE}]",
            subtitle="[dim]Evidence-driven reconnaissance[/dim]",
            border_style=BANNER_ORANGE,
            padding=(1, 2),
        )
    )
    cli.console.print()


def _pop_option_value(argv: list[str], *names: str) -> str | None:
    """Remove a flag/value option from argv and return its value.

    Supports both ``--flag value`` and ``--flag=value`` forms.
    """
    for idx, token in enumerate(list(argv)):
        for name in names:
            if token == name:
                if idx + 1 >= len(argv):
                    raise SystemExit(f"{name} requires a value")
                value = argv[idx + 1]
                del argv[idx : idx + 2]
                return value
            prefix = name + "="
            if token.startswith(prefix):
                value = token[len(prefix) :]
                del argv[idx]
                return value
    return None


def _pop_bool_flag(argv: list[str], *names: str) -> bool:
    for idx, token in enumerate(list(argv)):
        if token in names:
            del argv[idx]
            return True
    return False


def _save_openai_key_to_config(api_key: str) -> Path:
    """Persist OpenAI API key in ~/.blackbox-recon/config.yaml."""
    config_dir = Path.home() / ".blackbox-recon"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"
    data: dict = {}
    if config_path.exists():
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
    data.setdefault("ai", {})
    data["ai"]["provider"] = "openai"
    data["ai"]["api_key"] = api_key
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False, sort_keys=False)
    try:
        os.chmod(config_path, 0o600)
    except Exception:
        pass
    return config_path


def _preparse_api_key_flags() -> None:
    """Handle API key convenience flags before delegating to Click.

    Supported:
      --openai-api-key KEY
      --openai-key KEY
      --save-openai-api-key
    """
    argv = sys.argv
    save_key = _pop_bool_flag(argv, "--save-openai-api-key", "--remember-openai-api-key")
    api_key = _pop_option_value(argv, "--openai-api-key", "--openai-key")
    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key
        os.environ.setdefault("BLACKBOX_RECON_OPENAI_KEY_SOURCE", "cli")
        if save_key:
            path = _save_openai_key_to_config(api_key)
            cli.console.print(f"[green][+][/green] Saved OpenAI API key to [cyan]{path}[/cyan]")
    elif save_key:
        raise SystemExit("--save-openai-api-key requires --openai-api-key KEY")


def main() -> None:
    """Patch the banner and delegate to the original CLI entrypoint."""
    _preparse_api_key_flags()
    cli.BANNER_ART = BLACKBOX_ASCII
    cli.print_banner = print_banner
    cli.main()
