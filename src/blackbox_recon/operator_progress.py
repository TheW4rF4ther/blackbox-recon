"""Compact operator progress indicator for longer recon runs."""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Awaitable, Optional, TypeVar

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn


console = Console()
T = TypeVar("T")


def progress_enabled() -> bool:
    val = os.environ.get("BLACKBOX_RECON_PROGRESS", "1").strip().lower()
    return val not in ("0", "false", "no", "off")


def heartbeat_interval() -> float:
    raw = os.environ.get("BLACKBOX_RECON_HEARTBEAT_SEC", "8").strip()
    try:
        return max(3.0, float(raw))
    except Exception:
        return 8.0


async def with_heartbeat(label: str, awaitable: Awaitable[T], *, detail: str = "") -> T:
    """Run an awaitable while printing a low-noise heartbeat.

    This intentionally avoids percentages. It only proves the operator that the
    scan is still alive during quiet long-running subprocesses.
    """
    if not progress_enabled():
        return await awaitable

    done = asyncio.Event()
    start = time.monotonic()
    frames = ("◐", "◓", "◑", "◒")
    interval = heartbeat_interval()

    async def _beat() -> None:
        i = 0
        while not done.is_set():
            elapsed = time.monotonic() - start
            msg = f"[cyan]{frames[i % len(frames)]}[/cyan] [bold]Running:[/bold] {label} [dim]({elapsed:.0f}s elapsed)[/dim]"
            if detail:
                msg += f" [dim]— {detail}[/dim]"
            console.print(msg)
            i += 1
            try:
                await asyncio.wait_for(done.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass

    task = asyncio.create_task(_beat())
    try:
        return await awaitable
    finally:
        done.set()
        try:
            await task
        except Exception:
            pass


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
