#!/usr/bin/env python3
"""Command-line interface for Blackbox Recon."""

import asyncio
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .config import Config, create_default_config
from .recon import ReconEngine
from .engagement import (
    EngagementGateError,
    assert_four_questions,
    assert_within_testing_window,
    build_engagement_runtime,
    compute_standing_scope_ips,
    load_engagement,
    plan_techniques,
)
from .ai_analyzer import (
    AIAnalyzer,
    check_local_llm_connection,
    check_ollama_connection,
)
from .kali_platform import ensure_kali_toolchain
from .methodology import build_methodology_block
from .report_renderer import render_technical_assessment_markdown


for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

console = Console()


def build_analysis_panel_text(body: str) -> Text:
    """Syntax-safe Rich ``Text`` with highlights for section headers and key bullets."""
    t = Text()
    for line in body.splitlines():
        st = line.strip()
        if re.match(r"^\d+\)\s+\S", st) and len(st) <= 130:
            t.append(line + "\n", style="bold cyan")
        elif re.match(r"^\s*-\s+", st) and "|" in st and (
            re.search(r"Severity:\s*", st)
            or re.search(r"^\s*-\s*<(?:Confirmed|Candidate|Unclear)", st)
            or re.search(r"Priority:\s*P[123]", st)
        ):
            t.append(line + "\n", style="green")
        elif re.match(
            r"^\s*(?:\*+\s*)?(?:Entry point:|Risk chain:|Potential impact:)\s*",
            line,
            re.I,
        ):
            t.append(line + "\n", style="yellow")
        else:
            t.append(line + "\n")
    return t


def resolve_report_path(
    output: Optional[str],
    target: str,
    output_format: str,
    workspace_reports: Optional[Path] = None,
) -> Path:
    """Pick a writable path for reports (avoids PermissionError in protected cwd)."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"{target}-recon-{timestamp}.{output_format}"
    if not output and workspace_reports is not None:
        workspace_reports.mkdir(parents=True, exist_ok=True)
        return workspace_reports / default_name
    if not output:
        path = Path.home() / ".blackbox-recon" / "reports" / default_name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    path = Path(output).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_report_file(path: Path, results: dict, output_format: str) -> Path:
    """Write report; on PermissionError fall back to ~/.blackbox-recon/reports/."""
    from .reporting import dumps_pretty

    def _write(p: Path) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        if output_format == "markdown":
            generate_markdown_report(results, str(p))
        else:
            with p.open("w", encoding="utf-8") as handle:
                handle.write(dumps_pretty(results))

    try:
        _write(path)
        return path
    except PermissionError:
        alt = Path.home() / ".blackbox-recon" / "reports" / path.name
        _write(alt)
        return alt


BANNER_ART = r"""
  ____  __           __   ____
 / __ )/ /___ ______/ /__/ __ )____  _  __
/ __  / / __ `/ ___/ //_/ __  / __ \| |/_/
/ /_/ / / /_/ / /__/ ,< / /_/ / /_/ />  <
\____/_/\__,_/\___/_/|_/_____/\____/_/|_|

   ____  ______ _________  _   __
  / __ \/ ____// ____/ _ \| | / /
 / /_/ / __/  / /   / // /| |/ /
/ _, _/ /___ / /___/ __  / |   /
/_/ |_/_____/ \____/_/ /_/  |_|_|
""".strip("\n")


def print_banner():
    """Print the Blackbox Recon banner."""
    banner = Text()
    banner.append(BANNER_ART, style="bold #d94a34")
    banner.append("\n\n")
    banner.append("AI-Augmented Reconnaissance for Pentesters", style="bold bright_white")
    banner.append("\n")
    banner.append("by Blackbox Intelligence Group LLC", style="dim")

    console.print()
    console.print(
        Panel(
            banner,
            title="[bold #d94a34]Blackbox Recon[/bold #d94a34]",
            subtitle="[dim]Evidence-driven reconnaissance[/dim]",
            border_style="#d94a34",
            padding=(1, 2),
        )
    )
    console.print()


@click.command()
@click.option('--target', '-t', required=False, help='Target domain to reconnaissance')
@click.option('--config', '-c', type=click.Path(), help='Path to config file')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', 'output_format', default='json', 
              type=click.Choice(['json', 'markdown', 'csv', 'html']), 
              help='Output format')
@click.option('--modules', '-m', default='subdomain,portscan,technology',
              help='Comma-separated list of modules: subdomain,portscan,technology,vulnscan')
@click.option('--ai-mode', type=click.Choice(['openai', 'claude', 'local', 'ollama', 'none']),
              default='none', help='AI provider for analysis')
@click.option('--ai-model', help='Specific AI model to use')
@click.option('--local-url', default='http://localhost:1234/v1', help='URL for local LLM (LM Studio)')
@click.option('--ollama-url', default='http://localhost:11434', help='URL for Ollama')
@click.option('--ollama-model', default='llama3.1', help='Ollama model name')
@click.option(
    '--skip-ai-precheck',
    is_flag=True,
    help='Skip local/Ollama connectivity check before recon (not recommended)',
)
@click.option('--full', is_flag=True, help='Enable all modules')
@click.option('--init-config', is_flag=True, help='Create default configuration file')
@click.option(
    '--install-missing-kali-tools',
    is_flag=True,
    help='On Kali/Debian-like hosts, try non-interactive apt install for missing CLIs (sudo -n)',
)
@click.option(
    '--engagement',
    'engagement_file',
    type=click.Path(exists=True, dir_okay=False),
    help='YAML/JSON engagement record. Required unless --lab / --no-engagement-gates or BLACKBOX_RECON_LAB=1.',
)
@click.option(
    '--no-engagement-gates',
    '--lab',
    is_flag=True,
    help='Skip engagement file, gates, and workspace (same as env BLACKBOX_RECON_LAB=1). Lab/CI only.',
)
@click.option(
    '--action-reason',
    help='Override engagement action_reason for this run (client value statement).',
)
@click.option(
    '--workspace-root',
    type=str,
    default=None,
    help='Base for Aesa-style workspaces (default: ~/.blackbox-recon/workspaces).',
)
@click.option(
    '--show-ai-narrative',
    is_flag=True,
    help='Print the AI enrichment panel for local/Ollama (structured JSON → markdown). Default: off.',
)
@click.option(
    '--save-ai-raw',
    is_flag=True,
    help='Store raw LLM response in saved JSON (ai_analysis.raw_llm_text) for local/Ollama.',
)
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.version_option(version='1.0.0', prog_name='blackbox-recon')
def recon_main(
    target,
    config,
    output,
    output_format,
    modules,
    ai_mode,
    ai_model,
    local_url,
    ollama_url,
    ollama_model,
    skip_ai_precheck,
    full,
    init_config,
    install_missing_kali_tools,
    engagement_file,
    no_engagement_gates,
    action_reason,
    workspace_root,
    verbose,
    show_ai_narrative,
    save_ai_raw,
):
    """Blackbox Recon - AI-Augmented Reconnaissance for Penetration Testers."""
    
    print_banner()
    
    # Initialize config
    if init_config:
        config_path = create_default_config()
        console.print(f"[green][+][/green] Created default config at: {config_path}")
        console.print("[dim]Edit this file to configure your AI providers and preferences[/dim]")
        return
    
    # Load configuration
    try:
        if config:
            cfg = Config.load_from_file(config)
        else:
            default_path = Config.get_default_path()
            if default_path.exists():
                cfg = Config.load_from_file(str(default_path))
            else:
                cfg = Config()
    except Exception as e:
        console.print(f"[red][!] Error loading config: {e}[/red]")
        cfg = Config()
    
    if verbose:
        cfg.verbose = True

    lab_env = os.environ.get("BLACKBOX_RECON_LAB", "").strip().lower() in ("1", "true", "yes", "on")
    if lab_env:
        no_engagement_gates = True

    # Override config with CLI options
    if full:
        modules_list = ["subdomain", "portscan", "technology", "vulnscan"]
    else:
        modules_list = [m.strip() for m in modules.split(',')]
    
    # Validate target (required unless using --init-config)
    if not target:
        console.print("[red][!] Target is required (use -t DOMAIN)[/red]")
        console.print("[dim]Run with --help for usage information[/dim]")
        sys.exit(1)
    
    if not target.replace('.', '').replace('-', '').isalnum():
        console.print("[red][!] Invalid target format[/red]")
        sys.exit(1)

    if ai_mode == 'local' and not skip_ai_precheck:
        console.print("[cyan][*] Checking local LLM API...[/cyan]")
        try:
            status, auto_model_id = check_local_llm_connection(local_url)
            console.print(f"[green][+][/green] Local LLM OK ({status}) at [cyan]{local_url}[/cyan]")
            if not ai_model and auto_model_id:
                ai_model = auto_model_id
                console.print(f"[dim]No --ai-model provided; using first server model: {auto_model_id}[/dim]")
        except Exception as exc:
            console.print(f"[red][!] Local LLM not reachable at {local_url}[/red]")
            console.print(f"[dim]{exc}[/dim]")
            console.print(
                "[dim]Tip: start LM Studio local server, use base URL ending in /v1, "
                "and try GET /v1/models in a browser. Use --skip-ai-precheck to run recon anyway.[/dim]"
            )
            sys.exit(1)
    elif ai_mode == 'ollama' and not skip_ai_precheck:
        console.print("[cyan][*] Checking Ollama API...[/cyan]")
        try:
            status = check_ollama_connection(ollama_url)
            console.print(f"[green][+][/green] Ollama OK ({status}) at [cyan]{ollama_url}[/cyan]")
        except Exception as exc:
            console.print(f"[red][!] Ollama not reachable at {ollama_url}[/red]")
            console.print(f"[dim]{exc}[/dim]")
            console.print("[dim]Use --skip-ai-precheck to run recon anyway.[/dim]")
            sys.exit(1)

    if ai_mode == "local" and not ai_model:
        console.print(
            "[red][!] Local LLM requires a model id. Pass --ai-model, load a model in LM Studio, "
            "or disable --skip-ai-precheck so /v1/models can be used.[/red]"
        )
        sys.exit(1)
    
    # Run reconnaissance
    try:
        recon_config = {
            "threads": cfg.recon.threads,
            "timeout": cfg.recon.timeout,
            "port_scan_timeout": cfg.recon.port_scan_timeout,
            "port_scan_mode": cfg.recon.port_scan_mode,
            "nmap_aggressive_timeout_sec": cfg.recon.nmap_aggressive_timeout_sec,
            "service_detection": cfg.recon.service_detection,
            "nmap_executable": cfg.recon.nmap_executable,
            "nmap_scan_timeout": cfg.recon.nmap_scan_timeout,
            "service_probe_timeout": cfg.recon.service_probe_timeout,
            "wordlist": cfg.recon.wordlist,
            "ports": cfg.recon.ports,
            "run_nslookup": cfg.recon.run_nslookup,
            "nslookup_timeout_sec": cfg.recon.nslookup_timeout_sec,
            "directory_scan_enabled": cfg.recon.directory_scan_enabled,
            "directory_tool": cfg.recon.directory_tool,
            "directory_wordlist": cfg.recon.directory_wordlist,
            "directory_threads": cfg.recon.directory_threads,
            "directory_timeout_sec": cfg.recon.directory_timeout_sec,
            "directory_max_urls": cfg.recon.directory_max_urls,
            "kali_report_missing_tools": cfg.recon.kali_report_missing_tools,
            "kali_auto_install_missing": cfg.recon.kali_auto_install_missing or install_missing_kali_tools,
            "kali_apt_update_before_install": cfg.recon.kali_apt_update_before_install,
            "recon_verbose_phases": cfg.recon.recon_verbose_phases,
        }

        engagement_rt = None
        if not no_engagement_gates:
            if not engagement_file:
                console.print("[red][!] Engagement record required for execution.[/red]")
                console.print(
                    "[dim]Provide --engagement path/to/engagement.yaml (authorization, scope, action_reason) "
                    "or use --lab / --no-engagement-gates / export BLACKBOX_RECON_LAB=1 only for lab/CI.[/dim]"
                )
                sys.exit(1)
            try:
                spec = load_engagement(engagement_file)
                if action_reason:
                    spec = spec.model_copy(update={"action_reason": action_reason})
                assert_within_testing_window(spec)
                techniques = plan_techniques(modules_list, recon_config)
                assert_four_questions(spec, target, techniques)
                expanded = compute_standing_scope_ips(target, spec)
                wb = Path(workspace_root).expanduser() if workspace_root else None
                engagement_rt = build_engagement_runtime(spec, expanded, wb)
                shutil.copy2(engagement_file, engagement_rt.paths["00_scope"] / Path(engagement_file).name)
                engagement_rt.audit(
                    "cli_execution_authorized",
                    target=target,
                    techniques=techniques,
                    engagement_file=str(Path(engagement_file).resolve()),
                )
                console.print(
                    f"[green][+][/green] Engagement gates passed — workspace: [cyan]{engagement_rt.paths['root']}[/cyan]"
                )
            except EngagementGateError as exc:
                console.print(f"[red][!] Engagement gate: {exc}[/red]")
                sys.exit(1)
        else:
            console.print(
                Panel(
                    "[bold]Lab mode[/bold] — engagement gates are off ([cyan]--lab[/cyan] or "
                    "[cyan]BLACKBOX_RECON_LAB=1[/cyan]). "
                    "No authorization, scope, or workspace enforcement.",
                    title="[yellow]Notice[/yellow]",
                    border_style="yellow",
                    padding=(0, 1),
                )
            )

        engine = ReconEngine(recon_config, engagement_rt)
        
        console.print("[cyan][*] Running reconnaissance...[/cyan]")
        results = asyncio.run(engine.run(target, modules_list))

        trace = results.get("recon_phase_trace") or []
        if trace:
            console.print("\n[bold cyan]Recon phases (this run)[/bold cyan]")
            et = Table(
                title="[bold cyan]Commands executed per PTES phase[/bold cyan]",
                box=box.SIMPLE_HEAD,
                show_header=True,
                header_style="bold bright_white",
            )
            et.add_column("Phase", style="bold cyan", no_wrap=True, width=5)
            et.add_column("Status", style="bold magenta", width=11)
            et.add_column("#", justify="right", style="yellow", width=3)
            et.add_column("Representative command", style="bright_white", max_width=76, overflow="ellipsis")
            for row in trace:
                cmds = row.get("commands_executed") or []
                samp = ""
                if cmds:
                    first = cmds[0]
                    samp = f"{first.get('label', '')}: {first.get('command') or ''}"
                    if len(cmds) > 1:
                        samp += " (+{} more)".format(len(cmds) - 1)
                et.add_row(
                    str(row.get("phase_id", "")),
                    str(row.get("status", "")),
                    str(len(cmds)),
                    samp or "—",
                )
            console.print(et)
            console.print(
                "[dim]Timestamps and full command lines: JSON key `recon_phase_trace`.[/dim]"
            )

        det_findings = results.get("deterministic_findings") or []
        if det_findings:
            console.print("\n[bold green]Findings[/bold green] [dim](evidence-backed; see `evidence_package` in JSON)[/dim]")
            ft = Table(box=box.ROUNDED, header_style="bold cyan")
            ft.add_column("ID", style="dim", max_width=12)
            ft.add_column("Code", style="yellow", max_width=14)
            ft.add_column("Severity", style="magenta", max_width=11)
            ft.add_column("Title", style="white", max_width=48, overflow="ellipsis")
            ft.add_column("Evidence", style="dim", justify="right")
            for row in det_findings[:12]:
                eids = row.get("evidence_ids") or []
                ft.add_row(
                    str(row.get("id", ""))[:12],
                    str(row.get("finding_code") or "—")[:14],
                    str(row.get("severity", ""))[:11],
                    (row.get("title") or "")[:200],
                    str(len(eids)),
                )
            console.print(ft)
        if ai_mode != 'none':
            try:
                api_key = cfg.get_api_key()
                
                if ai_mode == 'local':
                    analyzer = AIAnalyzer(
                        provider='local',
                        url=local_url,
                        model=ai_model
                    )
                elif ai_mode == 'ollama':
                    analyzer = AIAnalyzer(
                        provider='ollama',
                        url=ollama_url,
                        model=ollama_model or 'llama3.1'
                    )
                else:
                    if not api_key:
                        console.print(f"[red][!] API key not found for {ai_mode}[/red]")
                        console.print(f"[dim]Set {ai_mode.upper()}_API_KEY environment variable or add to config[/dim]")
                        sys.exit(1)
                    
                    analyzer = AIAnalyzer(
                        provider=ai_mode,
                        api_key=api_key,
                        model=ai_model
                    )
                
                console.print("\n[bold green]AI analysis[/bold green] [dim]· generating enrichment…[/dim]")
                analysis = analyzer.analyze_recon_data(
                    results,
                    show_ai_narrative=show_ai_narrative,
                    save_ai_raw=save_ai_raw,
                )

                is_json_local = ai_mode in ("local", "ollama")
                ta = (analysis.technical_analysis or "").strip()

                if analysis.ai_status == "error_provider":
                    console.print(f"[yellow][!][/yellow] {ta or 'AI provider error.'}")
                elif analysis.ai_status != "applied":
                    console.print(f"[yellow][!][/yellow] {ta}")
                elif is_json_local:
                    if show_ai_narrative and ta:
                        console.print(
                            Panel(
                                build_analysis_panel_text(ta),
                                title="[bold bright_white]AI structured enrichment[/bold bright_white]",
                                title_align="left",
                                subtitle="[dim italic]Validated JSON enrichment · deterministic findings remain authoritative[/dim italic]",
                                border_style="green",
                                padding=(1, 2),
                            )
                        )
                    elif show_ai_narrative and not ta:
                        console.print(
                            Panel(
                                Text(
                                    "The model returned no visible enrichment text after JSON validation.",
                                    style="dim",
                                ),
                                title="[bold bright_white]AI structured enrichment[/bold bright_white]",
                                title_align="left",
                                border_style="yellow",
                                padding=(1, 2),
                            )
                        )
                    else:
                        console.print(
                            "[dim]AI enrichment applied (structured). "
                            "Omitting narrative panel; see report appendix or use --show-ai-narrative.[/dim]"
                        )
                else:
                    if ta:
                        console.print(
                            Panel(
                                build_analysis_panel_text(ta),
                                title="[bold bright_white]Attack surface analysis[/bold bright_white]",
                                title_align="left",
                                subtitle="[dim italic]Advisory triage from this run · not exploitation guidance[/dim italic]",
                                border_style="green",
                                padding=(1, 2),
                            )
                        )
                    else:
                        console.print(
                            Panel(
                                Text(
                                    "The model returned no visible analysis text. "
                                    "Raw JSON is still in the saved report.",
                                    style="dim",
                                ),
                                title="[bold bright_white]Attack surface analysis[/bold bright_white]",
                                title_align="left",
                                border_style="yellow",
                                padding=(1, 2),
                            )
                        )

                results['ai_analysis'] = {
                    'executive_summary': analysis.executive_summary,
                    'technical_analysis': analysis.technical_analysis,
                    'confidence_score': analysis.confidence_score,
                    'recommended_next_steps': analysis.recommended_next_steps,
                    'attack_paths': analysis.attack_paths,
                    'prioritized_findings': analysis.prioritized_findings,
                    'ai_status': analysis.ai_status,
                    'ai_discard_reason': analysis.ai_discard_reason,
                    'ai_enrichment': analysis.ai_enrichment,
                    'raw_llm_text': analysis.raw_llm_text,
                }

                if analysis.recommended_next_steps:
                    console.print("\n[bold cyan]AI — recommended follow-up tools[/bold cyan] [dim](advisory only; Blackbox Recon does not run these)[/dim]")
                    nst = Table(title="[bold cyan]Suggested next moves[/bold cyan]", box=box.ROUNDED, header_style="bold yellow")
                    nst.add_column("Tool", style="bold cyan", max_width=18)
                    nst.add_column("Objective", style="white", max_width=36)
                    nst.add_column("Example CLI (placeholders)", style="dim cyan", max_width=44)
                    for row in analysis.recommended_next_steps[:8]:
                        nst.add_row(row.get("tool", "—") or "—", (row.get("objective") or "—")[:200], (row.get("example_cli") or "—")[:200])
                    console.print(nst)
                    console.print("[dim]Validate against ROE/scope before running any command. Prefer engagement-gated runs and your own wordlists/paths.[/dim]")
            except Exception as e:
                console.print(f"[yellow][!] AI analysis failed: {e}[/yellow]")
        
        console.print("\n[bold green]Reconnaissance Summary[/bold green]")
        table = Table(title="[bold yellow]Counts[/bold yellow]", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Metric", style="yellow")
        table.add_column("Count", style="bold white", justify="right")
        summary = results.get('summary', {})
        table.add_row("Subdomains found", str(summary.get('total_subdomains', 0)))
        table.add_row("Open TCP ports", str(summary.get('open_tcp_ports', summary.get('total_open_ports', 0))))
        table.add_row("HTTP(S) services (from ports)", str(summary.get('http_services_detected', 0)))
        table.add_row("Subdomain HTTP probes w/ status", str(summary.get('subdomain_http_probes_with_status', summary.get('web_services', 0))))
        table.add_row("HTTP URLs targeted (dir / content)", str(summary.get('http_urls_targeted', summary.get('web_urls_targeted', 0))))
        table.add_row("Technology profiles stored", str(summary.get('technology_profiles_stored', summary.get('total_tech_detected', 0))))
        console.print(table)

        results["technical_report_markdown"] = render_technical_assessment_markdown(results)

        ws_reports = engagement_rt.paths["reports"] if engagement_rt else None
        output_path = resolve_report_path(output, target, output_format, workspace_reports=ws_reports)
        written_path = write_report_file(output_path, results, output_format)
        if written_path != output_path:
            console.print(f"[yellow][!][/yellow] Could not write to [cyan]{output_path}[/cyan]; saved to [cyan]{written_path}[/cyan] instead.")
        console.print(f"\n[green][+][/green] Results saved to: [cyan]{written_path}[/cyan]")
        
        if results.get('subdomains'):
            console.print("\n[bold yellow]Top Subdomains:[/bold yellow]")
            for sub in results['subdomains'][:5]:
                console.print(f"  - {sub['subdomain']} ({', '.join(sub['ip_addresses'][:2])})")
        
        if results.get('ports'):
            console.print("\n[bold yellow]Open Ports:[/bold yellow]")
            ports_by_host: dict = {}
            for port in results["ports"][:10]:
                host = port["host"]
                if host not in ports_by_host:
                    ports_by_host[host] = []
                ver = port.get("version") or ""
                if ver:
                    ver = f" ({ver[:60]}{'…' if len(ver) > 60 else ''})"
                line = f"{port['port']}/{port.get('service', '?')}{ver}"
                if line not in ports_by_host[host]:
                    ports_by_host[host].append(line)
            for host, ports in list(ports_by_host.items())[:3]:
                console.print(f"  - {host}: {', '.join(ports[:5])}")
        console.print("\n[dim]Done. Stay safe, hack ethically.[/dim]")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red][!] Error: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@click.command()
@click.option("--config", "-c", type=click.Path(exists=True, dir_okay=False), help="YAML config (uses recon.* to decide which tools are required)")
@click.option("--install", is_flag=True, help="Run apt-get install for missing packages (non-interactive sudo required)")
@click.option("--apt-update", is_flag=True, help="Run apt-get update before install (slower)")
def kali_setup_command(config: Optional[str], install: bool, apt_update: bool):
    """Verify Kali/Debian external CLIs and optionally install missing apt packages."""
    print_banner()
    try:
        if config:
            cfg = Config.load_from_file(config)
        else:
            p = Config.get_default_path()
            cfg = Config.load_from_file(str(p)) if p.exists() else Config()
    except Exception as exc:
        console.print(f"[yellow][!] Config load failed, using defaults: {exc}[/yellow]")
        cfg = Config()

    recon_cfg = {
        "port_scan_mode": cfg.recon.port_scan_mode,
        "run_nslookup": cfg.recon.run_nslookup,
        "directory_scan_enabled": cfg.recon.directory_scan_enabled,
        "directory_tool": cfg.recon.directory_tool,
        "kali_auto_install_missing": install,
        "kali_apt_update_before_install": apt_update,
        "kali_report_missing_tools": cfg.recon.kali_report_missing_tools,
    }
    snap, err = ensure_kali_toolchain(recon_cfg, auto_install=install, apt_update_first=apt_update)
    console.print("\n[bold cyan]Platform[/bold cyan]")
    console.print(f"  Kali: {snap.get('is_kali')} | Debian-like: {snap.get('is_debian_like')}")
    tbl = Table(title="External tools (PATH)", box=box.ROUNDED)
    tbl.add_column("Tool", style="cyan")
    tbl.add_column("Present", style="magenta")
    tbl.add_column("Path", style="dim")
    for name, row in (snap.get("tools") or {}).items():
        tbl.add_row(name, "yes" if row.get("present") else "no", row.get("path") or "")
    console.print(tbl)

    miss = snap.get("missing_apt_packages") or []
    if miss:
        console.print(f"\n[yellow][!][/yellow] Missing packages for current recon config: [cyan]{' '.join(miss)}[/cyan]")
        if not install:
            console.print("[dim]Re-run with --install to apt-get install (requires passwordless sudo), or: sudo apt-get install -y " + " ".join(miss) + "[/dim]")
    else:
        console.print("\n[green][+][/green] All required external tools for this config are on PATH.")

    if err:
        console.print(f"\n[red][!][/red] {err}")
        sys.exit(1)

    mods = [m.strip() for m in "subdomain,portscan,technology".split(",")]
    meth = build_methodology_block(mods, recon_cfg, snap)
    console.print("\n[bold cyan]Recon methodology (default modules)[/bold cyan]")
    for ph in meth.get("phases") or []:
        st = "[green]ready[/green]" if ph.get("ready") else "[yellow]not ready[/yellow]"
        console.print(f"  {ph.get('phase_id')} {ph.get('name')}: {st} — {ph.get('detail')}")
    console.print("\n[dim]Tip: methodology phases depend on --modules on real recon runs.[/dim]")


def main():
    """Entry point: `blackbox-recon …` (recon) or `blackbox-recon kali-setup …`."""
    if len(sys.argv) > 1 and sys.argv[1] == "kali-setup":
        sys.argv.pop(1)
        kali_setup_command.main(standalone_mode=True)
    else:
        recon_main.main(standalone_mode=True)


def generate_markdown_report(results: dict, output_file: str):
    """Generate a Markdown report."""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# Reconnaissance Report: {results.get('target', '')}\n\n")
        f.write(f"**Schema:** {results.get('schema_version', '1.0')}  \n")
        f.write(f"**Generated:** {results.get('timestamp', '')}  \n")
        f.write(f"**Completed (UTC):** {results.get('recon_completed_utc', '')}\n\n")
        f.write(render_technical_assessment_markdown(results))
        f.write("\n---\n\n## Appendices\n\n")

        plat = results.get("platform_toolchain") or {}
        if plat:
            f.write("### Platform toolchain\n\n")
            f.write(f"- **Kali detected:** {plat.get('is_kali')} | **Debian-like:** {plat.get('is_debian_like')}\n")
            miss = plat.get("missing_apt_packages") or []
            if miss:
                f.write(f"- **Missing apt packages (for this config):** {', '.join(miss)}\n")
            f.write("\n")

        meth = results.get("recon_methodology") or {}
        phases = meth.get("phases") or []
        if phases:
            f.write("### Recon methodology (phase readiness)\n\n")
            for ph in phases:
                ok = ph.get("ready")
                f.write(f"- **{ph.get('phase_id')} {ph.get('name')}** — {'ready' if ok else 'not ready'}: {ph.get('detail')}\n")
            f.write("\n")

        trace = results.get("recon_phase_trace") or []
        if trace:
            f.write("### PTES-style execution trace (what ran)\n\n")
            f.write("Per-phase log of tooling: Python stack vs external binaries (`nmap`, `nslookup`, `gobuster`/`dirb`). Each `command` value is the exact line executed where applicable.\n\n")
            for row in trace:
                f.write(f"### {row.get('phase_id')} — {row.get('phase_name')}\n\n")
                f.write(f"- **Status:** {row.get('status')}  \n")
                if row.get("ptes_mapping"):
                    f.write(f"- **PTES mapping:** {row['ptes_mapping']}  \n")
                if row.get("detail"):
                    f.write(f"- **Outcome:** {row['detail']}  \n")
                for line in row.get("stack_lines") or []:
                    f.write(f"- {line}  \n")
                cmds = row.get("commands_executed") or []
                if cmds:
                    f.write("\n| Label | Command / description |\n|-------|------------------------|\n")
                    for c in cmds:
                        lab = str(c.get("label", "")).replace("|", "\\|")
                        cmd = str(c.get("command", "")).replace("|", "\\|")
                        if len(cmd) > 200:
                            cmd = cmd[:197] + "..."
                        f.write(f"| `{lab}` | `{cmd}` |\n")
                f.write("\n")

        snap = results.get("executive_snapshot") or {}
        if snap:
            f.write("### Executive snapshot (supplementary metrics)\n\n")
            f.write(f"- **Open ports (count):** {snap.get('open_port_count', 0)}\n")
            f.write(f"- **HTTP URLs scanned (dir / content targets):** {snap.get('web_url_candidates', 0)}\n")
            if snap.get("http_services_detected") is not None:
                f.write(f"- **HTTP(S) services (from ports):** {snap.get('http_services_detected', 0)}\n")
            if snap.get("subdomain_http_probes_with_status") is not None:
                f.write(f"- **Subdomain HTTP probes w/ status:** {snap.get('subdomain_http_probes_with_status', 0)}\n")
            if snap.get("dns_names_observed"):
                f.write(f"- **DNS names observed:** {', '.join(snap['dns_names_observed'][:15])}\n")
            f.write("\n")

        dns = results.get("dns_intelligence") or {}
        lookups = dns.get("nslookups") or []
        if lookups:
            f.write("### DNS intelligence (nslookup)\n\n")
            for row in lookups:
                f.write(f"### {row.get('target')}\n\n")
                f.write(f"- Status: `{row.get('status')}`  \n")
                if row.get("command"):
                    f.write(f"- Command: `{row['command']}`\n")
                parsed = row.get("parsed") or {}
                if parsed.get("ptr_or_canonical_names"):
                    f.write(f"- Names: {', '.join(parsed['ptr_or_canonical_names'])}\n")
                f.write("\n")

        nmap_meta = results.get("nmap_scan") or {}
        per_host = nmap_meta.get("per_host") or []
        if per_host:
            f.write("### Nmap (per host)\n\n")
            for h in per_host:
                f.write(f"- **{h.get('host')}:** `{h.get('command')}`  \n")
                f.write(f"  - XML parseable: {h.get('xml_parseable')} | Open ports in XML: {h.get('open_ports_in_xml')}\n")
            f.write("\n")

        ai = results.get("ai_analysis") or {}
        if ai:
            st = str(ai.get("ai_status") or "ok")
            ta_body = (ai.get("technical_analysis") or "").strip()
            steps = ai.get("recommended_next_steps") or []
            if st == "applied" and ta_body:
                f.write("### Structured AI enrichment\n\n")
                f.write("*Parsed from model JSON output. Deterministic findings in the technical assessment remain authoritative.*\n\n")
                f.write(ta_body + "\n\n")
            elif st == "ok" and ta_body:
                f.write("### Narrative enrichment (model-generated)\n\n")
                f.write("*Optional model prose for triage context only; it does not supersede deterministic evidence.*\n\n")
                f.write(ta_body + "\n\n")
            elif st not in ("ok", "applied") and ta_body:
                f.write("### AI enrichment status\n\n")
                f.write(ta_body + "\n\n")
                if ai.get("ai_discard_reason"):
                    f.write(f"- **Detail:** `{ai['ai_discard_reason']}`\n\n")
            if steps:
                f.write("### AI — advisory next moves (not executed)\n\n")
                f.write("These are model-suggested follow-ups only. Validate against ROE/scope before running.\n\n")
                f.write("| Tool | Objective | Example CLI | Risk notes |\n")
                f.write("|------|-------------|-------------|------------|\n")
                def _md_cell(s: str, max_len: int = 120) -> str:
                    t = (s or "").replace("|", "\\|").replace("\n", " ")
                    return (t[: max_len - 3] + "...") if len(t) > max_len else t
                for row in steps[:8]:
                    f.write(f"| {_md_cell(str(row.get('tool', '')))} | {_md_cell(str(row.get('objective', '')))} | {_md_cell(str(row.get('example_cli', '')), 160)} | {_md_cell(str(row.get('risk_notes', '')))} |\n")
                f.write("\n")

        if results.get("subdomains"):
            f.write("### Subdomains\n\n")
            f.write("| Subdomain | IP Addresses | Status |\n")
            f.write("|-----------|--------------|--------|\n")
            for sub in results["subdomains"]:
                ips = ", ".join(sub.get("ip_addresses", [])[:2])
                status = sub.get("status_code", "N/A")
                f.write(f"| {sub['subdomain']} | {ips} | {status} |\n")
            f.write("\n")

        if results.get("ports"):
            f.write("### Open ports / services\n\n")
            f.write("| Host | Port | Service | Version / details |\n")
            f.write("|------|------|---------|---------------------|\n")
            for port in results["ports"]:
                ver = (port.get("version") or "").replace("|", "\\|")
                if len(ver) > 120:
                    ver = ver[:117] + "..."
                f.write(f"| {port['host']} | {port['port']} | {port.get('service', 'unknown')} | {ver} |\n")
            f.write("\n")

        web = results.get("web_content_discovery") or {}
        scans = web.get("directory_scans") or []
        if scans:
            f.write("### Web content discovery\n\n")
            for s in scans:
                f.write(f"### {s.get('base_url')}\n\n")
                f.write(f"- Tool: {s.get('tool')} | Status: {s.get('status')}\n")
                hits = s.get("findings_interesting") or []
                if hits:
                    f.write("\n| Path | Status |\n|------|--------|\n")
                    for h in hits[:40]:
                        f.write(f"| `{h.get('path', '')}` | {h.get('status_code')} |\n")
                f.write("\n")


if __name__ == "__main__":
    main()
