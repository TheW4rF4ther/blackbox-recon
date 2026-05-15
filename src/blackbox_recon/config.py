"""Configuration management for Blackbox Recon."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class AIConfig(BaseModel):
    """AI provider configuration."""
    provider: str = Field(default="openai", description="AI provider: openai, claude, local, ollama")
    api_key: Optional[str] = Field(default=None, description="API key for the provider")
    model: str = Field(default="gpt-4", description="Model to use")
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4000, ge=1)
    url: Optional[str] = Field(default=None, description="Custom URL for local providers")


class ReconConfig(BaseModel):
    """Reconnaissance configuration."""

    threads: int = Field(default=50, ge=1, le=200)
    timeout: int = Field(default=30, ge=1)
    port_scan_timeout: int = Field(default=6, ge=1, le=120, description="Per-port TCP connect timeout (seconds) for tcp_connect port scan")
    port_scan_mode: str = Field(default="nmap_aggressive", description="nmap_aggressive: nmap -v -p- -A --open per IP; tcp_connect: asyncio top-N scan")
    nmap_aggressive_timeout_sec: int = Field(default=7200, ge=120, le=86400, description="Wall-clock budget per host for nmap -p- -A (default 2 hours)")
    service_detection: str = Field(default="auto", description="none | banner | nmap | auto — used only for tcp_connect fallback scans")
    nmap_executable: Optional[str] = Field(default=None, description="Path to nmap; default search PATH and common Windows install locations")
    nmap_scan_timeout: int = Field(default=300, ge=30, le=86400, description="Wall-clock seconds budget for each host nmap -sV subprocess (fallback mode)")
    service_probe_timeout: float = Field(default=4.0, ge=0.5, le=60.0, description="Seconds to wait for banner/HTTP data after connect during service probe")
    run_nslookup: bool = Field(default=True, description="Run nslookup against each resolved IP and the raw target when portscan runs")
    nslookup_timeout_sec: int = Field(default=120, ge=10, le=600)
    directory_scan_enabled: bool = Field(default=True, description="Run gobuster or dirb against discovered http(s) URLs after port scan")
    directory_tool: str = Field(default="auto", description="auto | gobuster | dirb | none")
    directory_wordlist: Optional[str] = Field(default=None, description="Path to directory wordlist; unset uses BLACKBOX_RECON_DIR_WORDLIST or Kali paths under /usr/share/wordlists then bundled small list")
    directory_threads: int = Field(default=10, ge=1, le=50)
    directory_timeout_sec: int = Field(default=900, ge=60, le=7200)
    directory_max_urls: int = Field(default=6, ge=1, le=20)
    http_headers_enabled: bool = Field(default=True, description="Run non-invasive HTTP security header analysis against discovered HTTP(S) URLs")
    http_headers_timeout_sec: int = Field(default=10, ge=3, le=120)
    tls_scan_enabled: bool = Field(default=True, description="Run TLS posture sampling on discovered HTTPS URLs; uses sslscan when present")
    tls_scan_timeout_sec: int = Field(default=60, ge=10, le=600)
    wordlist: Optional[str] = Field(default=None, description="Path to subdomain wordlist")
    ports: str = Field(default="top1000", description="Ports for tcp_connect mode: top100, top1000, all, or custom")
    rate_limit: float = Field(default=0.0, ge=0.0, description="Requests per second limit")
    kali_report_missing_tools: bool = Field(default=True, description="On Kali Linux, print apt hints when external CLIs required by config are missing")
    kali_auto_install_missing: bool = Field(default=False, description="On Kali/Debian-like hosts, run non-interactive apt to install missing packages (needs sudo -n)")
    kali_apt_update_before_install: bool = Field(default=False, description="Run apt-get update before auto-install (slower, fresher indexes)")
    recon_verbose_phases: bool = Field(default=True, description="Print PTES-style phase banners and log each external command line to stdout")


class Config(BaseModel):
    """Main configuration class."""
    ai: AIConfig = Field(default_factory=AIConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    modules: list = Field(default_factory=lambda: ["subdomain", "portscan", "technology"])
    output_format: str = Field(default="json", description="Output format: json, markdown, csv, html")
    verbose: bool = Field(default=False)
    
    @classmethod
    def load_from_file(cls, config_path: str) -> "Config":
        """Load configuration from YAML file."""
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    @classmethod
    def get_default_path(cls) -> Path:
        """Get default configuration file path."""
        home = Path.home()
        config_dir = home / ".blackbox-recon"
        config_dir.mkdir(exist_ok=True)
        return config_dir / "config.yaml"
    
    def save(self, path: Optional[str] = None):
        """Save configuration to YAML file."""
        save_path = Path(path) if path else self.get_default_path()
        with open(save_path, 'w') as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)
    
    def get_api_key(self) -> Optional[str]:
        """Get API key from config or environment."""
        if self.ai.api_key:
            return self.ai.api_key
        env_vars = {"openai": "OPENAI_API_KEY", "claude": "ANTHROPIC_API_KEY", "local": None, "ollama": None}
        env_var = env_vars.get(self.ai.provider)
        if env_var:
            return os.getenv(env_var)
        return None


def create_default_config() -> str:
    """Create a default configuration file."""
    config_content = '''# Blackbox Recon Configuration
# Place this file at ~/.blackbox-recon/config.yaml
#
# Lab quick test (no engagement YAML): export BLACKBOX_RECON_LAB=1
#   Same as CLI flags --lab or --no-engagement-gates. Unset for client runs with --engagement.

# AI Provider Settings
# Supported: openai, claude, local (LM Studio, etc.), ollama
ai:
  provider: openai
  # Get your API key from environment variable or set here
  # For OpenAI: export OPENAI_API_KEY="sk-..."
  # For Claude: export ANTHROPIC_API_KEY="sk-ant-..."
  api_key: null
  model: gpt-4
  temperature: 0.3
  max_tokens: 4000
  # For local providers, set the URL
  # url: http://localhost:1234/v1

# Reconnaissance Settings
recon:
  threads: 50
  timeout: 30
  # Default: full TCP nmap with OS/service/scripts (-A). Very thorough; long runtime per host.
  port_scan_mode: nmap_aggressive  # nmap_aggressive | tcp_connect
  nmap_aggressive_timeout_sec: 7200
  # TCP connect scan tuning (only if port_scan_mode: tcp_connect)
  port_scan_timeout: 6
  service_detection: auto
  # nmap_executable: "C:\\Program Files (x86)\\Nmap\\nmap.exe"
  nmap_scan_timeout: 300
  service_probe_timeout: 4.0
  run_nslookup: true
  nslookup_timeout_sec: 120
  directory_scan_enabled: true
  directory_tool: auto   # auto | gobuster | dirb | none
  # directory_wordlist: /usr/share/wordlists/dirb/common.txt
  # Or: export BLACKBOX_RECON_DIR_WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt
  directory_threads: 10
  directory_timeout_sec: 900
  directory_max_urls: 6
  # Non-invasive web posture enrichment after HTTP(S) services are discovered
  http_headers_enabled: true
  http_headers_timeout_sec: 10
  tls_scan_enabled: true
  tls_scan_timeout_sec: 60
  # Path to subdomain wordlist (optional)
  # wordlist: /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt
  ports: top1000  # top100, top1000, all, or "80,443,8080" (tcp_connect only)
  rate_limit: 0  # Requests per second (0 = no limit)
  # Kali / Debian host integration (external CLIs: nmap, nslookup, gobuster/dirb, sslscan)
  kali_report_missing_tools: true
  kali_auto_install_missing: false   # if true, requires passwordless sudo (sudo -n)
  kali_apt_update_before_install: false
  # Echo PTES-style phase banners and each subprocess command (nmap, nslookup, gobuster, …)
  recon_verbose_phases: true

# Modules to enable
modules:
  - subdomain      # Subdomain enumeration
  - portscan       # Port scanning and web/TLS enrichment
  - technology     # Technology detection
  - vulnscan       # Vulnerability scanning (Nuclei, future)
  # - screenshot     # Screenshot capture, future
  # - dns            # DNS enumeration, future

# Output Settings
output_format: json  # json, markdown, csv, html
verbose: false
'''
    config_path = Config.get_default_path()
    with open(config_path, 'w') as f:
        f.write(config_content)
    return str(config_path)
