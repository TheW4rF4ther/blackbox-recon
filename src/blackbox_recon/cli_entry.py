"""Branded CLI entrypoint for Blackbox Recon.

This module keeps the functional CLI in ``blackbox_recon.cli`` untouched,
replaces the startup banner, and handles a tiny pre-parse layer for secrets
and operator scan profiles before the main Click command resolves config.
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
  -------------
------     ------
---    ---    ---
  --    -    --
--  -- --- --  --
----   ---   ----
---  --   --  ---
----    -    ----
------  -  ------
  ----- - -----
     -------
       ---
""".strip("\n")

RECON_ASCII = r"""
 ____  _____ ____ ___  _   _
|  _ \| ____/ ___/ _ \| \ | |
| |_) |  _|| |  | | | |  \| |
|  _ <| |__| |__| |_| | |\  |
|_| \_\_____\____\___/|_| \_|
""".strip("\n")


def _side_by_side(left: str, right: str, gap: int = 4) -> str:
    """Render two ASCII blocks side-by-side with top alignment."""
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    height = max(len(left_lines), len(right_lines))
    left_width = max((len(line) for line in left_lines), default=0)
    out = []
    for idx in range(height):
        l = left_lines[idx] if idx < len(left_lines) else ""
        r = right_lines[idx] if idx < len(right_lines) else ""
        out.append(f"{l:<{left_width}}{' ' * gap}{r}")
    return "\n".join(out).rstrip()


def print_banner() -> None:
    """Print the Blackbox Recon banner with compact orange logo art."""
    banner = Text()
    banner.append(_side_by_side(BLACKBOX_ASCII, RECON_ASCII), style=f"bold {BANNER_ORANGE}")
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


def _apply_operator_scan_profile() -> None:
    """Apply CLI-only scan profiles before the underlying Click command runs.

    Default operator mode should not spend 60+ minutes inside full-port aggressive
    Nmap. Use --deep when that behavior is explicitly desired.
    """
    argv = sys.argv
    deep = _pop_bool_flag(argv, "--deep", "--deep-scan", "--nmap-deep")
    fast = _pop_bool_flag(argv, "--fast", "--quick")

    if deep and fast:
        raise SystemExit("Choose either --deep or --fast, not both")

    if deep:
        os.environ["BLACKBOX_RECON_SCAN_PROFILE"] = "deep"
        os.environ["BLACKBOX_RECON_PORT_SCAN_MODE"] = "nmap_aggressive"
        os.environ.setdefault("BLACKBOX_RECON_NMAP_AGGRESSIVE_TIMEOUT_SEC", "7200")
        return

    # Normal/default operator profile: finish the core phase in sane time, then
    # let service-specific modules, CMS probes, SearchSploit/NVD, and AI add depth.
    profile = "fast" if fast else os.environ.get("BLACKBOX_RECON_SCAN_PROFILE", "normal").strip().lower()
    if profile in ("normal", "fast", "quick", "operator", ""):
        os.environ["BLACKBOX_RECON_SCAN_PROFILE"] = "fast" if fast else "normal"
        os.environ.setdefault("BLACKBOX_RECON_PORT_SCAN_MODE", "tcp_connect")
        os.environ.setdefault("BLACKBOX_RECON_PORTS", "top1000")
        os.environ.setdefault("BLACKBOX_RECON_NMAP_SCAN_TIMEOUT_SEC", "180")
        os.environ.setdefault("BLACKBOX_RECON_DIRECTORY_TIMEOUT_SEC", "300")


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
    _apply_operator_scan_profile()
    cli.BANNER_ART = BLACKBOX_ASCII
    cli.print_banner = print_banner
    cli.main()
