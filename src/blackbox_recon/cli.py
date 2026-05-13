#!/usr/bin/env python3
"""Command-line interface for Blackbox Recon."""

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
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
    console.print(r"[bold red]    ____  _            _     ____ _     _            _                         [/bold red]")
    console.print(r"[bold red]   | __ )| | __ _  ___| | __/ ___| |__ | | ___  ___| | _____ _ __           [/bold red]")
    console.print(r"[bold red]   |  _  | |/ _  |/ __| |/ / |   |  _  | |/ _  / __| |/ / _   '__|          [/bold red]")
    console.print(r"[bold red]   | |_) | | (_| | (__|   <| |___| |_) | |  __/ (__|   <  __/ |             [/bold red]")
    console.print(r"[bold red]   |____/|_| __,_| ___|_| _| ____|____/|_| ___| ___|_| _ ___|_|             [/bold red]")
    console.print(r"[bold red]      BLACKBOX                    RECON                                     [/bold red]")
    console.print()
    console.print("[bold yellow]       AI-Augmented Reconnaissance for Penetration Testers[/bold yellow]")
    console.print("[dim]                      by Blackbox Intelligence Group LLC[/dim]")
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
@click.option('--full', is_flag=True, help='Enable all modules')
@click.option('--init-config', is_flag=True, help='Create default configuration file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.version_option(version='1.0.0', prog_name='blackbox-recon')
def main(target, config, output, output_format, modules, ai_mode, ai_model,
         local_url, ollama_url, ollama_model, full, init_config, verbose):
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
    
    # Run reconnaissance
    try:
        recon_config = {
            "threads": cfg.recon.threads,
            "timeout": cfg.recon.timeout,
            "wordlist": cfg.recon.wordlist,
            "ports": cfg.recon.ports
        }
        
        engine = ReconEngine(recon_config)
        
        console.print("[cyan][*] Running reconnaissance...[/cyan]")
        results = asyncio.run(engine.run(target, modules_list))
        
        # AI Analysis
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
                
                console.print("[bold green][*] AI analyzing attack surface...[/bold green]")
                analysis = analyzer.analyze_recon_data(results)
                
                # Display AI analysis
                console.print("\n[bold yellow]AI Analysis Results[/bold yellow]")
                console.print("=" * 60)
                console.print(Panel(analysis.technical_analysis, title="Analysis", border_style="green"))
                
                # Add analysis to results
                results['ai_analysis'] = {
                    'executive_summary': analysis.executive_summary,
                    'technical_analysis': analysis.technical_analysis,
                    'confidence_score': analysis.confidence_score
                }
                
            except Exception as e:
                console.print(f"[yellow][!] AI analysis failed: {e}[/yellow]")
        
        # Display summary table
        console.print("\n[bold green]Reconnaissance Summary[/bold green]")
        table = Table(box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")
        
        summary = results.get('summary', {})
        table.add_row("Subdomains Found", str(summary.get('total_subdomains', 0)))
        table.add_row("Open Ports", str(summary.get('total_open_ports', 0)))
        table.add_row("Web Services", str(summary.get('web_services', 0)))
        table.add_row("Technologies Detected", str(summary.get('total_tech_detected', 0)))
        
        console.print(table)
        
        # Save results
        if output:
            output_file = output
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{target}-recon-{timestamp}.{output_format}"
        
        if output_format == 'json':
            import json
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        elif output_format == 'markdown':
            generate_markdown_report(results, output_file)
        else:
            # Default to JSON for now
            with open(output_file, 'w') as f:
                import json
                json.dump(results, f, indent=2)
        
        console.print(f"\n[green][+][/green] Results saved to: [cyan]{output_file}[/cyan]")
        
        # Print some highlights
        if results.get('subdomains'):
            console.print("\n[bold yellow]Top Subdomains:[/bold yellow]")
            for sub in results['subdomains'][:5]:
                console.print(f"  - {sub['subdomain']} ({', '.join(sub['ip_addresses'][:2])})")
        
        if results.get('ports'):
            console.print("\n[bold yellow]Open Ports:[/bold yellow]")
            ports_by_host = {}
            for port in results['ports'][:10]:
                host = port['host']
                if host not in ports_by_host:
                    ports_by_host[host] = []
                ports_by_host[host].append(f"{port['port']}/{port['service']}")
            
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


def generate_markdown_report(results: dict, output_file: str):
    """Generate a Markdown report."""
    with open(output_file, 'w') as f:
        f.write(f"# Reconnaissance Report: {results['target']}\n\n")
        f.write(f"**Generated:** {results['timestamp']}\n\n")
        
        f.write("## Summary\n\n")
        summary = results.get('summary', {})
        f.write(f"- **Subdomains Found:** {summary.get('total_subdomains', 0)}\n")
        f.write(f"- **Open Ports:** {summary.get('total_open_ports', 0)}\n")
        f.write(f"- **Web Services:** {summary.get('web_services', 0)}\n\n")
        
        if results.get('ai_analysis'):
            f.write("## AI Analysis\n\n")
            f.write(results['ai_analysis'].get('technical_analysis', ''))
            f.write("\n\n")
        
        if results.get('subdomains'):
            f.write("## Subdomains\n\n")
            f.write("| Subdomain | IP Addresses | Status |\n")
            f.write("|-----------|--------------|--------|\n")
            for sub in results['subdomains']:
                ips = ', '.join(sub.get('ip_addresses', [])[:2])
                status = sub.get('status_code', 'N/A')
                f.write(f"| {sub['subdomain']} | {ips} | {status} |\n")
            f.write("\n")
        
        if results.get('ports'):
            f.write("## Open Ports\n\n")
            f.write("| Host | Port | Service |\n")
            f.write("|------|------|----------|\n")
            for port in results['ports']:
                f.write(f"| {port['host']} | {port['port']} | {port.get('service', 'unknown')} |\n")
            f.write("\n")


if __name__ == '__main__':
    main()
