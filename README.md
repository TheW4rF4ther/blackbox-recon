# Blackbox Recon 🔍

> AI-Augmented Reconnaissance for Penetration Testers

**By [Blackbox Intelligence Group LLC](https://blackboxintelgroup.com)**

Blackbox Recon is a smart reconnaissance tool that combines traditional reconnaissance techniques with AI-powered analysis to provide actionable intelligence, not just raw data.

## 🚀 What Makes It Different

Unlike traditional recon tools that spit out raw data, Blackbox Recon:
- **Correlates findings** - Links related vulnerabilities across services
- **AI-powered analysis** - Identifies attack paths and prioritizes findings
- **Actionable output** - Tells you what to do next, not just what exists
- **Pluggable AI** - Works with OpenAI, Claude, or your local LLM (LM Studio, Ollama, etc.)

## 📦 Installation

```bash
pip install blackbox-recon
```

Or install from source:

```bash
git clone https://github.com/blackboxintel/blackbox-recon.git
cd blackbox-recon
pip install -e .
```

## 🎯 Quick Start

### Basic Recon
```bash
# Simple reconnaissance
blackbox-recon --target example.com

# Full recon with all modules
blackbox-recon --target example.com --full

# Save results
blackbox-recon --target example.com -o recon-report.json
```

### With AI Analysis
```bash
# Using OpenAI
export OPENAI_API_KEY="your-key"
blackbox-recon --target example.com --ai-mode openai

# Using Claude
export ANTHROPIC_API_KEY="your-key"
blackbox-recon --target example.com --ai-mode claude

# Using local LM Studio (default: http://localhost:1234)
blackbox-recon --target example.com --ai-mode local --local-url http://localhost:1234/v1

# Using Ollama
blackbox-recon --target example.com --ai-mode ollama --ollama-model llama3.1
```

## 🔧 Features

### Reconnaissance Modules
- **Subdomain Enumeration** - Amass, subfinder, brute-force
- **Port Scanning** - Nmap integration with smart defaults
- **Technology Detection** - whatweb, wappalyzer-style detection
- **Vulnerability Scanning** - Nuclei template integration
- **Screenshotting** - EyeWitness/aquatone-style captures
- **DNS Enumeration** - Comprehensive DNS recon

### AI Analysis Features
- **Attack Surface Analysis** - AI identifies exploitable paths
- **Vulnerability Correlation** - Links findings across services
- **Risk Prioritization** - Ranks findings by exploitation ease
- **Attack Path Generation** - Suggests exploitation chains
- **Report Generation** - Executive and technical summaries

## 📋 Usage Examples

### Example 1: Quick Recon
```bash
$ blackbox-recon --target corp.com

[+] Starting reconnaissance on corp.com
[+] Found 47 subdomains
[+] Discovered 12 live web services
[+] Identified 3 technologies: Apache, PHP, WordPress
[+] Completed in 45 seconds

Results saved to: corp.com-recon-20250113.json
```

### Example 2: AI-Augmented Analysis
```bash
$ export OPENAI_API_KEY="sk-..."
$ blackbox-recon --target corp.com --ai-mode openai

[+] Starting reconnaissance on corp.com
[+] Found 47 subdomains
[+] Discovered 12 live web services
[AI] Analyzing attack surface...
[!] HIGH: Jenkins exposed on dev.corp.com (CVE-2024-23897 possible)
[!] MEDIUM: WordPress 6.2.2 outdated on blog.corp.com
[!] HIGH: SMB signing disabled on 192.168.1.10 (PetitPotam)
[AI] Suggested attack path:
    1. Exploit Jenkins → Internal network access
    2. SMB relay attack → Domain credentials
    3. Lateral movement → Full domain compromise

Analysis saved to: corp.com-analysis-20250113.md
```

### Example 3: Config File
```bash
# Create config
blackbox-recon --init-config

# Edit ~/.blackbox-recon/config.yaml
# Then run with config
blackbox-recon --target corp.com --config ~/.blackbox-recon/config.yaml
```

## ⚙️ Configuration

Create a config file at `~/.blackbox-recon/config.yaml`:

```yaml
# AI Provider Settings
ai:
  provider: openai  # openai, claude, local, ollama
  api_key: ${OPENAI_API_KEY}
  model: gpt-4
  temperature: 0.3

# Local LM Studio
local:
  url: http://localhost:1234/v1
  model: qwen2.5-9b-instruct

# Ollama
ollama:
  url: http://localhost:11434
  model: llama3.1

# Recon Settings
recon:
  threads: 50
  timeout: 30
  wordlist: /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt

# Modules to enable
modules:
  - subdomain
  - portscan
  - technology
  - vulnscan
  - screenshot
```

## 🔌 Supported AI Providers

| Provider | Setup | Best For |
|----------|-------|----------|
| **OpenAI** | `export OPENAI_API_KEY=...` | Best analysis quality |
| **Claude** | `export ANTHROPIC_API_KEY=...` | Large context windows |
| **Local/LM Studio** | Run LM Studio locally | Privacy, no API costs |
| **Ollama** | `ollama serve` | Local models, easy setup |

## 🛠️ Development

```bash
# Clone repo
git clone https://github.com/blackboxintel/blackbox-recon.git
cd blackbox-recon

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
black src/
flake8 src/
```

## 📝 Output Formats

- **JSON** - Machine-readable, full data
- **Markdown** - Human-readable reports
- **CSV** - Spreadsheet-friendly
- **HTML** - Interactive reports

## ⚠️ Legal & Responsible Use

**Blackbox Recon is for authorized security testing only.**

- Only use on systems you own or have explicit written authorization to test
- Respect scope boundaries
- Follow responsible disclosure practices
- Check local laws regarding security testing

**By using this tool, you agree to:**
- Use it ethically and legally
- Not use it for malicious purposes
- Report vulnerabilities responsibly

## 🏢 About Blackbox Intelligence Group

Blackbox Intelligence Group LLC is a veteran-owned cybersecurity firm specializing in:
- 24/7 SOC with BlackboxEDR platform
- Internal/External Penetration Testing
- Red Team Operations
- Cybersecurity Consultation
- Vulnerability Assessments

**Website:** https://blackboxintelgroup.com  
**Email:** info@blackboxintelgroup.com

## 📄 License

MIT License - See [LICENSE](LICENSE) file

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 🙏 Acknowledgments

- Built with inspiration from Amass, Nmap, Nuclei, and the offensive security community
- AI integration powered by your choice of provider
- Created by the operators at Blackbox Intelligence Group

---

**⭐ Star us on GitHub if you find this useful!**
