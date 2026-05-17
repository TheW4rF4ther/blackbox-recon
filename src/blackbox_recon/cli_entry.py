"""Branded CLI entrypoint for Blackbox Recon.

This module keeps the functional CLI in ``blackbox_recon.cli`` untouched and
only replaces the startup banner before delegating to the original main().
"""

from __future__ import annotations

from rich.panel import Panel
from rich.text import Text

from . import cli

BANNER_ORANGE = "#d97706"

BLACKBOX_ASCII = r"""
                              *++++++**
                          ***++++++*++++**
                       ++++++++++++++++++++++
                    *++++**+++**+++++*+*+++*++***
                 *+++*+++++++++++***+++++++++++++++
             **++++++*****++++*      **++*++++++++++++*
          *++++++++++***+***            ***++*++++++++++++
       *++++++++++++++++*                   *++++++++++++++++*
   **+++++++++++++++*         *++++++*         *++++*+++++++++++*
 *++*+++*+++*++++*         **++*++++++++*          *++++++++++++++*
*++**+++**++++            ++*+*+++++++++++*           *++++++++*+++*
  ***+******              ****+++*++++++++               **++**+**
     ***+++*                  ***+++*+                  *+++***
        ******++                 **                 **++****
            **+++**                              *+++++*
*+*             **++*      +*          *+      *+++**            *++
*++++*#           **+++**  **++**  **++*+  **+++**            +++*++
*++++*+++*           ***++*+* **++++** **+++++*           **+*****+*
*++**+++++****           ***+***   ****++++*           *+++*******
**+*++**++++++***           ***+++++++**           ***+++******
 ***++++  *+++++++**            *++**           **++++++*+*
*+++* *+     **+++++++                        ++++++++**
*+++++*+        **+++++                      *+++++**            #**
*+++++*+           **++                      *++**            +++++*
*+++++++**                                                 *+++++++*
*++++++++++**                   #**                    **+++++++++++
*+++++++++++++**                *+*                  *++++++++++++++
 ++**+++++++++++++*             *+*              *+++++++++++++++++
  +***+++++**++++*++++*         *+*           +++++++++++++++++***
      **+++****++**++++++*      *+*       **+++++**+*****++++**
         ************++**++++*  *+*    *+++++++++++*****+**
             **+**    *++++++++++++  +++**+++++++ **++*#
                *+     ++++++++++++ *+**++*+** **++*
                       ++++++++++++ *+ +++***+++**
                       +*+**+++++++ *+  *++++*
                         **+++++*++*++*+++*
                             ***+++++++
                                **+*
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


def main() -> None:
    """Patch the banner and delegate to the original CLI entrypoint."""
    cli.BANNER_ART = BLACKBOX_ASCII
    cli.print_banner = print_banner
    cli.main()
