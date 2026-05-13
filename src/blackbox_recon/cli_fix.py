#!/usr/bin/env python3
"""Command-line interface for Blackbox Recon."""

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from .config import Config, create_default_config
from .recon import ReconEngine
from .ai_analyzer import AIAnalyzer, AnalysisResult


console = Console()


def print_banner():
    """Print the Blackbox Recon banner."""
    console.print()
    console.print(r"[bold #FF6B35]  ____   _____   ____   ____   _   _ [/bold #FF6B35]")
    console.print(r"[bold #FF6B35] |  _ \ / ___| / ___||  _ \ | \ | |[/bold #FF6B35]")
    console.print(r"[bold #FF6B35] | |_) | |    | |    | | | ||  \| |[/bold #FF6B35]")
    console.print(r"[bold #FF6B35] |  _ <| |___ | |___ | |_| || |\  |[/bold #FF6B35]")
    console.print(r"[bold #FF6B35] |_| \_\\____| \____||____/ |_| \_|[/bold #FF6B35]")
    console.print()
    console.print("[bold yellow]  AI-Augmented Reconnaissance for Pentesters[/bold yellow]")
    console.print("[dim]         by Blackbox Intelligence Group LLC[/dim]")
    console.print()
