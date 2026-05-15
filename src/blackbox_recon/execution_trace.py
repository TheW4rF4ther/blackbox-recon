"""Penetration-test style phased execution trace (what ran, with which tools, in what order)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich import print as rprint
from rich.markup import escape

from .methodology import DEFAULT_PHASES


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _phase_lookup(phase_id: str):
    for ph in DEFAULT_PHASES:
        if ph.phase_id == phase_id:
            return ph
    return None


def _banner_line(ch: str = "─", width: int = 68) -> str:
    return ch * width


# Longest-first so "Wordlist path:" wins over "Wordlist:"
_STACK_PREFIXES = (
    "Wordlist path:",
    "Service enrichment:",
    "Tool preference:",
    "Configured ",
    "Objective:",
    "Stack:",
    "Wordlist:",
    "Note:",
    "Targets:",
)


def _stack_line_markup(line: str) -> str:
    """Apply Rich markup to a phase stack line (keys vs body)."""
    for p in _STACK_PREFIXES:
        if line.startswith(p):
            return f"[bold yellow]{escape(p)}[/bold yellow]{escape(line[len(p) :])}"
    return escape(line)


class PhaseTracer:
    """
    Append structured phase records to ``results['recon_phase_trace']`` and optionally echo banners.

    Each phase documents the *actual* tooling (external CLIs and Python stack) used in that step.
    """

    def __init__(self, results: Dict[str, Any], *, echo: bool = True) -> None:
        self.results = results
        self.echo = echo
        self._entry: Optional[Dict[str, Any]] = None

    def _ensure_list(self) -> List[Dict[str, Any]]:
        return self.results.setdefault("recon_phase_trace", [])

    def start(self, phase_id: str, extra_stack_lines: Optional[List[str]] = None) -> None:
        meta = _phase_lookup(phase_id)
        title = meta.name if meta else phase_id
        ptes = meta.ptes_mapping if meta else ""
        desc = meta.description if meta else ""
        stack_lines = list(extra_stack_lines or [])
        if meta and desc:
            stack_lines.insert(0, f"Objective: {desc}")

        self._entry = {
            "phase_id": phase_id,
            "phase_name": title,
            "ptes_mapping": ptes,
            "stack_lines": stack_lines,
            "commands_executed": [],
            "started_utc": _utc_now_iso(),
            "status": "running",
            "detail": "",
        }
        self._ensure_list().append(self._entry)
        if self.echo:
            rprint()
            rprint(f"[dim]{escape(_banner_line('─', 72))}[/dim]")
            rprint(
                f"  [bold cyan]PTES {escape(phase_id)}[/bold cyan] [dim]·[/dim] "
                f"[bold white]{escape(title)}[/bold white]"
            )
            if ptes:
                rprint(f"  [italic bright_blue]{escape(ptes.replace('>', '›'))}[/italic bright_blue]")
            rprint(f"[dim]{escape(_banner_line('─', 72))}[/dim]")
            for line in stack_lines:
                rprint(f"    [dim]·[/dim] {_stack_line_markup(line)}")

    def note_command(self, label: str, command: str, **extra: Any) -> None:
        if not self._entry:
            return
        row: Dict[str, Any] = {
            "label": label,
            "command": command,
            "logged_utc": _utc_now_iso(),
        }
        row.update({k: v for k, v in extra.items() if v is not None})
        self._entry.setdefault("commands_executed", []).append(row)
        if self.echo:
            rprint(
                f"    [dim][exec][/dim] [yellow]{escape(label)}[/yellow]: "
                f"[bright_white]{escape(command)}[/bright_white]"
            )

    def finish(self, status: str, detail: str = "") -> None:
        if not self._entry:
            return
        self._entry["completed_utc"] = _utc_now_iso()
        self._entry["status"] = status
        self._entry["detail"] = detail
        if self.echo and detail:
            rprint(
                f"  [green]→[/green] Phase complete "
                f"([bold]{escape(status)}[/bold]): [default]{escape(detail)}[/default]"
            )
        self._entry = None

    def skip(self, phase_id: str, reason: str) -> None:
        meta = _phase_lookup(phase_id)
        title = meta.name if meta else phase_id
        ptes = meta.ptes_mapping if meta else ""
        entry = {
            "phase_id": phase_id,
            "phase_name": title,
            "ptes_mapping": ptes,
            "stack_lines": [],
            "commands_executed": [],
            "started_utc": _utc_now_iso(),
            "completed_utc": _utc_now_iso(),
            "status": "skipped",
            "detail": reason,
        }
        self._ensure_list().append(entry)
        if self.echo:
            rprint()
            rprint(f"[dim]{escape(_banner_line('─', 72))}[/dim]")
            rprint(
                f"  [bold cyan]PTES {escape(phase_id)}[/bold cyan] [dim]·[/dim] "
                f"[bold white]{escape(title)}[/bold white] "
                f"[yellow][skipped][/yellow]"
            )
            rprint(f"    [dim]Reason:[/dim] [white]{escape(reason)}[/white]")
            rprint(f"[dim]{escape(_banner_line('─', 72))}[/dim]")


def summarize_execution_trace(trace: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compact summary for executive_snapshot / CLI."""
    phases_out: List[Dict[str, Any]] = []
    labels: List[str] = []
    for row in trace:
        pid = row.get("phase_id")
        cmds = row.get("commands_executed") or []
        for c in cmds:
            lab = c.get("label")
            if isinstance(lab, str) and lab and lab not in labels:
                labels.append(lab)
        phases_out.append(
            {
                "phase_id": pid,
                "status": row.get("status"),
                "command_count": len(cmds),
                "detail": (row.get("detail") or "")[:240],
            }
        )
    return {"phases": phases_out, "command_kinds": labels}


def print_execution_recap(results: Dict[str, Any], *, echo: bool = True) -> None:
    """Plain-text recap after engine.run (in addition to JSON trace)."""
    trace = results.get("recon_phase_trace") or []
    if not echo or not trace:
        return
    rprint()
    rprint(f"[dim]{escape(_banner_line('─', 72))}[/dim]")
    rprint(
        f"[bold green]{escape('[+]')}[/bold green] [bold]Execution recap[/bold] "
        "[dim](full commands in JSON: [cyan]recon_phase_trace[/cyan])[/dim]"
    )
    rprint(f"[dim]{escape(_banner_line('─', 72))}[/dim]")
    for row in trace:
        st = row.get("status", "?")
        pid = row.get("phase_id", "?")
        name = row.get("phase_name", "")
        ncmd = len(row.get("commands_executed") or [])
        detail = (row.get("detail") or "")[:120]
        rprint(
            f"  [bold cyan]{escape(str(pid))}[/bold cyan]  "
            f"[magenta]{escape('[' + str(st) + ']')}[/magenta]  "
            f"[white]{escape(str(name))}[/white]  [dim]·[/dim]  "
            f"[yellow]{ncmd}[/yellow] command(s)"
        )
        if detail and st != "skipped":
            rprint(f"      [dim]{escape(detail)}[/dim]")
    rprint(f"[dim]{escape(_banner_line('─', 72))}[/dim]")
