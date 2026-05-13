"""AI-powered analysis module with pluggable backends."""

import json
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

import requests


def check_local_llm_connection(base_url: str, timeout: float = 10.0) -> Tuple[str, Optional[str]]:
    """Verify an OpenAI-compatible local server (LM Studio, etc.) is reachable.

    Uses GET ``{base_url}/models`` (same as OpenAI ``/v1/models`` when base ends with ``/v1``).

    Returns ``(status_message, first_model_id_or_none)``.

    Raises:
        requests.RequestError: connection or HTTP errors
        ValueError: unexpected response
    """
    base = base_url.rstrip("/")
    url = f"{base}/models"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict) or "data" not in data:
        raise ValueError(f"Unexpected /models response from {url!r}")
    models = data.get("data") or []
    first_id: Optional[str] = None
    for entry in models:
        if isinstance(entry, dict) and entry.get("id"):
            first_id = str(entry["id"])
            break
    status = f"{len(models)} model(s) reported"
    return status, first_id


def check_ollama_connection(base_url: str, timeout: float = 10.0) -> str:
    """Verify Ollama is reachable (GET ``/api/tags``)."""
    base = base_url.rstrip("/")
    url = f"{base}/api/tags"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict) or "models" not in data:
        raise ValueError(f"Unexpected /api/tags response from {url!r}")
    models = data.get("models") or []
    return f"{len(models)} model(s) available"


@dataclass
class AnalysisResult:
    """Result from AI analysis."""
    attack_paths: List[Dict[str, Any]]
    prioritized_findings: List[Dict[str, Any]]
    correlations: List[Dict[str, Any]]
    executive_summary: str
    technical_analysis: str
    confidence_score: float


class AIProvider(ABC):
    """Abstract base class for AI providers."""
    
    @abstractmethod
    def analyze(self, recon_data: Dict[str, Any], prompt_template: str) -> str:
        """Send data to AI for analysis."""
        pass


class OpenAIProvider(AIProvider):
    """OpenAI GPT provider."""
    
    def __init__(self, api_key: str, model: str = "gpt-4", temperature: float = 0.3, max_tokens: int = 4000):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        try:
            import openai
            self.client = openai.OpenAI(api_key=api_key)
        except ImportError:
            raise ImportError("Install openai package: pip install openai")
    
    def analyze(self, recon_data: Dict[str, Any], prompt_template: str) -> str:
        """Analyze with OpenAI."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in penetration testing and vulnerability analysis."},
                    {"role": "user", "content": prompt_template + "\n\n" + json.dumps(recon_data, indent=2)}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error calling OpenAI API: {str(e)}"


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider."""
    
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229", temperature: float = 0.3, max_tokens: int = 4000):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise ImportError("Install anthropic package: pip install anthropic")
    
    def analyze(self, recon_data: Dict[str, Any], prompt_template: str) -> str:
        """Analyze with Claude."""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system="You are a cybersecurity expert specializing in penetration testing and vulnerability analysis.",
                messages=[{
                    "role": "user",
                    "content": prompt_template + "\n\n" + json.dumps(recon_data, indent=2)
                }]
            )
            return response.content[0].text
        except Exception as e:
            return f"Error calling Claude API: {str(e)}"


class LocalProvider(AIProvider):
    """Local LLM provider (LM Studio, etc.) via OpenAI-compatible API."""
    
    def __init__(self, url: str = "http://localhost:1234/v1", model: Optional[str] = None):
        self.url = url.rstrip('/')
        self.model = model
        self.headers = {"Content-Type": "application/json"}
    
    def analyze(self, recon_data: Dict[str, Any], prompt_template: str) -> str:
        """Analyze with local LLM."""
        try:
            payload = {
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert specializing in penetration testing and vulnerability analysis."},
                    {"role": "user", "content": prompt_template + "\n\n" + json.dumps(recon_data, indent=2)}
                ],
                "temperature": 0.3,
                "max_tokens": 4000,
                "stream": False
            }
            
            if self.model:
                payload["model"] = self.model
            
            response = requests.post(
                f"{self.url}/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Error calling local LLM: {str(e)}"


class OllamaProvider(AIProvider):
    """Ollama local model provider."""
    
    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.url = url.rstrip('/')
        self.model = model
    
    def analyze(self, recon_data: Dict[str, Any], prompt_template: str) -> str:
        """Analyze with Ollama."""
        try:
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert specializing in penetration testing and vulnerability analysis."},
                    {"role": "user", "content": prompt_template + "\n\n" + json.dumps(recon_data, indent=2)}
                ],
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_predict": 4000
                }
            }
            
            response = requests.post(
                f"{self.url}/api/chat",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            return response.json()["message"]["content"]
        except Exception as e:
            return f"Error calling Ollama: {str(e)}"


class AIAnalyzer:
    """Main AI analyzer class."""
    
    ANALYSIS_PROMPT = """Analyze the following reconnaissance data and provide:

1. EXECUTIVE SUMMARY: A brief (2-3 sentence) overview of the attack surface and critical findings

2. PRIORITIZED FINDINGS: List the top 5-10 findings ranked by risk (HIGH/MEDIUM/LOW). For each:
   - Finding name
   - Risk level
   - Location (URL/IP)
   - Brief explanation
   - Quick remediation tip

3. ATTACK PATHS: Identify 2-3 realistic attack chains that could lead to compromise. Format as:
   - Entry point
   - Pivot/Lateral movement
   - Goal/Impact

4. TECHNOLOGY RISKS: Analyze the technology stack for:
   - Outdated software with known CVEs
   - Dangerous configurations
   - Default credentials possibilities

5. CORRELATIONS: Identify relationships between findings (e.g., "Jenkins on dev + weak SMB = internal access")

Be specific, actionable, and focus on what a penetration tester should prioritize. Avoid generic advice."""

    def __init__(self, provider: str, api_key: Optional[str] = None, 
                 model: Optional[str] = None, url: Optional[str] = None,
                 temperature: float = 0.3, max_tokens: int = 4000):
        """Initialize AI analyzer with specified provider."""
        self.provider_name = provider
        
        if provider == "openai":
            if not api_key:
                raise ValueError("OpenAI API key required")
            self.provider = OpenAIProvider(api_key, model or "gpt-4", temperature, max_tokens)
        
        elif provider == "claude":
            if not api_key:
                raise ValueError("Claude API key required")
            self.provider = ClaudeProvider(api_key, model or "claude-3-sonnet-20240229", temperature, max_tokens)
        
        elif provider == "local":
            self.provider = LocalProvider(url or "http://localhost:1234/v1", model)
        
        elif provider == "ollama":
            self.provider = OllamaProvider(url or "http://localhost:11434", model or "llama3.1")
        
        else:
            raise ValueError(f"Unknown provider: {provider}. Choose: openai, claude, local, ollama")
    
    def analyze_recon_data(self, recon_data: Dict[str, Any]) -> AnalysisResult:
        """Analyze reconnaissance data and return structured results."""
        print(f"[AI] Analyzing attack surface with {self.provider_name}...")
        
        raw_analysis = self.provider.analyze(recon_data, self.ANALYSIS_PROMPT)
        
        # Parse the response into structured format
        # For now, return as-is wrapped in the result structure
        # In production, you'd parse the markdown/JSON response
        return AnalysisResult(
            attack_paths=[],
            prioritized_findings=[],
            correlations=[],
            executive_summary=raw_analysis[:500] if len(raw_analysis) > 500 else raw_analysis,
            technical_analysis=raw_analysis,
            confidence_score=0.85
        )
    
    def generate_attack_path(self, entry_point: str, target_type: str) -> Dict[str, Any]:
        """Generate specific attack path from an entry point."""
        prompt = f"""Given this entry point: {entry_point} (Type: {target_type})
        
Generate a specific attack path with:
1. Initial access technique
2. Lateral movement options
3. Privilege escalation path
4. Data access or impact

Format as a step-by-step exploitation chain."""
        
        result = self.provider.analyze({}, prompt)
        return {
            "entry_point": entry_point,
            "target_type": target_type,
            "path": result
        }
