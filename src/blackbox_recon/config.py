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
    wordlist: Optional[str] = Field(default=None, description="Path to subdomain wordlist")
    ports: str = Field(default="top1000", description="Ports to scan: top100, top1000, all, or custom")
    rate_limit: float = Field(default=0.0, ge=0.0, description="Requests per second limit")


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
        
        env_vars = {
            "openai": "OPENAI_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "local": None,
            "ollama": None,
        }
        
        env_var = env_vars.get(self.ai.provider)
        if env_var:
            return os.getenv(env_var)
        return None


def create_default_config() -> str:
    """Create a default configuration file."""
    config_content = '''# Blackbox Recon Configuration
# Place this file at ~/.blackbox-recon/config.yaml

# AI Provider Settings
# Supported: openai, claude, local (LM Studio, etc.), ollama
ai:
  provider: openai
  # Get your API key from environment variable or set here
  # For OpenAI: export OPENAI_API_KEY="sk-..."
  # For Claude: export ANTHROPIC_API_KEY="sk-..."
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
  # Path to subdomain wordlist (optional)
  # wordlist: /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt
  ports: top1000  # top100, top1000, all, or "80,443,8080"
  rate_limit: 0  # Requests per second (0 = no limit)

# Modules to enable
modules:
  - subdomain      # Subdomain enumeration
  - portscan       # Port scanning
  - technology     # Technology detection
  - vulnscan       # Vulnerability scanning (Nuclei)
  # - screenshot     # Screenshot capture
  # - dns            # DNS enumeration

# Output Settings
output_format: json  # json, markdown, csv, html
verbose: false
'''
    config_path = Config.get_default_path()
    with open(config_path, 'w') as f:
        f.write(config_content)
    return str(config_path)
