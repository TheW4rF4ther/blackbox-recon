"""Compact operator progress indicator for longer recon runs."""

from __future__ import annotations

import os
from typing import Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn


console = Console()


def progress_enabled() -> bool:
    val = os.environ.get("BLACKBOX_RECON_PROGRESS", "1").strip().lower()
    return val not in ("0", "false", "no", "off")


class OperatorProgress:
    """Small wrapper around Rich Progress for Blackbox Recon operator mode."""

    def __init__(self, *, total: int, label: str = "Blackbox Recon") -> None:
        self.total = max(1, int(total))
        self.label = label
        self._progress: Optional[Progress] = None
        self._task_id = None
        self._enabled = progress_enabled()
        self._step = 0

    def __enter__(self) -> "OperatorProgress":
        if self._enabled:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                TextColumn("[yellow]{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=False,
            )
            self._progress.__enter__()
            self._task_id = self._progress.add_task(self.label, total=self.total)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        if self._progress:
            self._progress.__exit__(exc_type, exc, tb)

    def start_step(self, name: str) -> None:
        self._step += 1
        desc = f"{self.label}: {name}"
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, description=desc)
        elif self._enabled:
            console.print(f"[cyan][{self._step}/{self.total}][/cyan] {desc}")

    def finish_step(self, detail: str = "") -> None:
        if self._progress and self._task_id is not None:
            self._progress.advance(self._task_id, 1)
        elif self._enabled and detail:
            console.print(f"[green]done[/green] {detail}")

    def note(self, message: str) -> None:
        if self._enabled:
            console.print(f"[dim]{message}[/dim]")
