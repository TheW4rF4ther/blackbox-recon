# Blackbox Recon Usage Examples

## Basic Usage

### Quick Reconnaissance
```bash
# Simple scan of a domain
blackbox-recon --target example.com

# Full reconnaissance with all modules
blackbox-recon --target example.com --full

# Verbose output
blackbox-recon --target example.com --full --verbose
```

## AI-Augmented Analysis

### Using OpenAI
```bash
# Set your API key
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxx"

# Run with OpenAI analysis
blackbox-recon --target example.com --ai-mode openai --full

# Use specific model
blackbox-recon --target example.com --ai-mode openai --ai-model gpt-4-turbo
```

### Using Claude
```bash
# Set your API key
export ANTHROPIC_API_KEY="sk-ant-xxxxxxxxxxxxxxxx"

# Run with Claude analysis
blackbox-recon --target example.com --ai-mode claude --full
```

### Using LM Studio (Local)
```bash
# Start LM Studio with your model loaded on port 1234

# Run with local AI
blackbox-recon --target example.com --ai-mode local --local-url http://localhost:1234/v1
```

### Using Ollama
```bash
# Make sure Ollama is running
ollama serve

# Run with Ollama
blackbox-recon --target example.com --ai-mode ollama --ollama-model llama3.1
```

## Output Options

### Different Output Formats
```bash
# JSON output (default)
blackbox-recon --target example.com -o results.json --format json

# Markdown report
blackbox-recon --target example.com -o report.md --format markdown

# CSV for spreadsheet analysis
blackbox-recon --target example.com -o data.csv --format csv

# HTML report
blackbox-recon --target example.com -o report.html --format html
```

## Module Selection

### Specific Modules
```bash
# Only subdomain enumeration
blackbox-recon --target example.com --modules subdomain

# Subdomain + port scan
blackbox-recon --target example.com --modules subdomain,portscan

# All modules except vulnerability scan
blackbox-recon --target example.com --full
```

## Configuration File

### Initialize Config
```bash
# Create default config
blackbox-recon --init-config

# Edit ~/.blackbox-recon/config.yaml with your settings

# Use config
blackbox-recon --target example.com --config ~/.blackbox-recon/config.yaml
```

## Advanced Usage

### With Custom Settings
```bash
# Full scan with AI analysis and markdown output
blackbox-recon \
  --target corp.example.com \
  --full \
  --ai-mode openai \
  --format markdown \
  -o corp-recon-report.md \
  --verbose
```

### Batch Processing Multiple Targets
```bash
#!/bin/bash
# Script to scan multiple targets

TARGETS=("target1.com" "target2.com" "target3.com")

for target in "${TARGETS[@]}"; do
    echo "Scanning $target..."
    blackbox-recon \
        --target "$target" \
        --full \
        --ai-mode local \
        -o "${target}-recon.json"
done
```

### Integration with Other Tools
```bash
# Use output for further processing
blackbox-recon --target example.com -o - --format json | jq '.subdomains[].subdomain'

# Combine with nuclei
blackbox-recon --target example.com --modules subdomain | \
    jq -r '.subdomains[].subdomain' | \
    nuclei -l -
```

## Docker Usage (Future)

```bash
# Build image
docker build -t blackbox-recon .

# Run
docker run --rm blackbox-recon --target example.com
```

## Tips

1. **Start Small**: Use basic recon first, then add AI analysis
2. **Rate Limiting**: Be mindful of rate limits on target systems
3. **Local AI**: Use LM Studio or Ollama for privacy and cost savings
4. **Output Formats**: Markdown is great for reports, JSON for automation
5. **Verbose Mode**: Use `--verbose` for debugging issues

## Troubleshooting

### API Key Issues
```bash
# Check if key is set
echo $OPENAI_API_KEY

# Set if missing
export OPENAI_API_KEY="your-key-here"
```

### Local AI Not Responding
```bash
# Test LM Studio
curl http://localhost:1234/v1/models

# Test Ollama
curl http://localhost:11434/api/tags
```

### Permission Denied
```bash
# Run with appropriate permissions
sudo blackbox-recon --target example.com  # For certain port scans
```
