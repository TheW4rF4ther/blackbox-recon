#!/usr/bin/env python3
"""AI analysis module for Blackbox Recon."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests import HTTPError
from rich import print as rprint
from rich.markup import escape

NEXT_STEPS_MARKER = "NEXT_STEPS_JSON:"


@dataclass
class AnalysisResult:
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    prioritized_findings: List[Dict[str, Any]] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    executive_summary: str = ""
    technical_analysis: str = ""
    confidence_score: float = 0.0
    recommended_next_steps: List[Dict[str, Any]] = field(default_factory=list)
    ai_status: str = "ok"
    ai_discard_reason: Optional[str] = None
    ai_enrichment: Optional[Dict[str, Any]] = None
    raw_llm_text: Optional[str] = None


SYSTEM_PROMPT = """You are a senior penetration testing analyst. Provide concise, client-safe reconnaissance analysis. Do not invent facts, hosts, CVEs, or exploitability. Do not provide weaponized exploit steps or payloads."""


def check_local_llm_connection(url: str = "http://localhost:1234/v1") -> Tuple[str, Optional[str]]:
    base = (url or "http://localhost:1234/v1").rstrip("/")
    resp = requests.get(f"{base}/models", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    models = data.get("data") if isinstance(data, dict) else []
    model_ids: List[str] = []
    if isinstance(models, list):
        for row in models:
            if isinstance(row, dict) and row.get("id"):
                model_ids.append(str(row["id"]))
            elif isinstance(row, str):
                model_ids.append(row)
    return f"{len(model_ids)} model(s) reported", model_ids[0] if model_ids else None


def check_ollama_connection(url: str = "http://localhost:11434") -> str:
    base = (url or "http://localhost:11434").rstrip("/")
    resp = requests.get(f"{base}/api/tags", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    models = data.get("models") if isinstance(data, dict) else []
    return f"{len(models) if isinstance(models, list) else 0} model(s) reported"


def _coerce_openai_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: List[str] = []
        for item in content:
            if isinstance(item, dict):
                txt = item.get("text") or item.get("content") or item.get("value")
                if isinstance(txt, str):
                    chunks.append(txt)
            elif isinstance(item, str):
                chunks.append(item)
        return "\n".join(chunks)
    return ""


def assistant_text_from_openai_chat_response(body: Dict[str, Any]) -> str:
    try:
        ch0 = (body.get("choices") or [{}])[0]
        msg = ch0.get("message") if isinstance(ch0.get("message"), dict) else {}
        return _coerce_openai_message_content(msg.get("content")).strip()
    except Exception:
        return ""


def split_next_steps_marker(text: str) -> Tuple[str, Optional[str]]:
    if NEXT_STEPS_MARKER not in (text or ""):
        return text, None
    body, _, tail = text.partition(NEXT_STEPS_MARKER)
    return body.strip(), tail.strip()


def parse_recommended_next_steps(blob: Optional[str]) -> List[Dict[str, Any]]:
    if not blob:
        return []
    try:
        data = json.loads(blob)
        rows = data.get("recommended_next_steps") if isinstance(data, dict) else []
        return [r for r in rows if isinstance(r, dict)][:8]
    except Exception:
        return []


def shrink_recon_payload_for_llm(recon_data: Dict[str, Any], *, max_chars: int = 12000, max_subdomains: int = 20, max_ports: int = 50, max_tech: int = 10) -> str:
    compact = {
        "target": recon_data.get("target"),
        "summary": recon_data.get("summary") or {},
        "ports": list(recon_data.get("ports") or [])[:max_ports],
        "subdomains": list(recon_data.get("subdomains") or [])[:max_subdomains],
        "technologies": list(recon_data.get("technologies") or [])[:max_tech],
        "deterministic_findings": list(recon_data.get("deterministic_findings") or [])[:20],
        "coverage_notes": (recon_data.get("evidence_package") or {}).get("coverage_notes") or [],
    }
    text = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    return text[: max_chars - 20] + "...<truncated>" if len(text) > max_chars else text


def _deterministic_local_fallback(recon_data: Dict[str, Any], *, reason: str) -> Dict[str, Any]:
    findings = list(recon_data.get("deterministic_findings") or [])
    summary = recon_data.get("summary") or {}
    target = recon_data.get("target") or "target"
    top = findings[:3]
    narrative = []
    for f in top:
        narrative.append(
            {
                "finding_id": f.get("id", ""),
                "client_ready_text": f"{f.get('title', 'Finding')} is recorded as {f.get('severity', 'unknown')} severity with {len(f.get('evidence_ids') or [])} evidence reference(s).",
                "confidence_note": f"Status: {f.get('status', 'unknown')}; based only on deterministic Blackbox Recon evidence.",
            }
        )
    steps = [
        {"tool": "manual-review", "objective": "Review deterministic findings and evidence IDs", "prerequisite": "Authorized scope", "example_cli": "blackbox-recon --target TARGET --full --lab", "risk_notes": "Validate against ROE before follow-up."},
        {"tool": "nmap", "objective": "Validate exposed service versions", "prerequisite": "Ports remain in scope", "example_cli": "nmap -sV -sC -p PORTS TARGET", "risk_notes": "Non-invasive validation only."},
        {"tool": "whatweb", "objective": "Confirm web stack fingerprints", "prerequisite": "HTTP services in scope", "example_cli": "whatweb -a 3 http://TARGET/", "risk_notes": "Fingerprinting is advisory, not proof of vulnerability."},
    ]
    enrichment = {
        "executive_summary": f"Blackbox Recon completed evidence-backed reconnaissance for {target}. Local AI enrichment was unavailable, so this section is deterministic fallback text generated from validated findings.",
        "risk_narrative": narrative,
        "cve_assessment": {"summary": "No CVEs were confirmed from the collected evidence alone.", "confirmed_cves": [], "candidate_cves": [], "reasoning_limits": ["Precise product versions or authenticated configuration data may be required for confident CVE mapping."]},
        "recommended_next_steps": steps,
        "quality_flags": [
            {"type": "ai_provider_fallback", "message": reason[:180]},
            {"type": "coverage_note", "message": f"Open ports: {summary.get('total_open_ports', summary.get('open_tcp_ports', 0))}; HTTP services: {summary.get('http_services_detected', 0)}."},
        ],
    }
    return enrichment


class AIProvider:
    def analyze(self, recon_data: Dict[str, Any], prompt_template: str, *, strict_json_evidence: bool = False) -> str:
        raise NotImplementedError


class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "gpt-4", temperature: float = 0.3, max_tokens: int = 4000):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.url = "https://api.openai.com/v1"
        self.headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def analyze(self, recon_data: Dict[str, Any], prompt_template: str, *, strict_json_evidence: bool = False) -> str:
        payload = {"model": self.model, "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt_template + "\n\n" + shrink_recon_payload_for_llm(recon_data)}], "temperature": self.temperature, "max_tokens": self.max_tokens}
        resp = requests.post(f"{self.url}/chat/completions", headers=self.headers, json=payload, timeout=120)
        resp.raise_for_status()
        return assistant_text_from_openai_chat_response(resp.json())


class ClaudeProvider(OpenAIProvider):
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229", temperature: float = 0.3, max_tokens: int = 4000):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.url = "https://api.anthropic.com/v1/messages"
        self.headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}

    def analyze(self, recon_data: Dict[str, Any], prompt_template: str, *, strict_json_evidence: bool = False) -> str:
        payload = {"model": self.model, "max_tokens": self.max_tokens, "temperature": self.temperature, "system": SYSTEM_PROMPT, "messages": [{"role": "user", "content": prompt_template + "\n\n" + shrink_recon_payload_for_llm(recon_data)}]}
        resp = requests.post(self.url, headers=self.headers, json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        return "\n".join(p.get("text", "") for p in (data.get("content") or []) if isinstance(p, dict)).strip()


class LocalProvider(AIProvider):
    def __init__(self, url: str = "http://localhost:1234/v1", model: str = "local-model"):
        self.url = url.rstrip("/")
        self.model = model
        self.headers = {"Content-Type": "application/json"}

    def analyze(self, recon_data: Dict[str, Any], prompt_template: str, *, strict_json_evidence: bool = False) -> str:
        from .ai_json_enrichment import JSON_ENRICHMENT_SYSTEM_PROMPT, evidence_package_json_for_llm, strip_think_spans
        try:
            if strict_json_evidence:
                user_content = f"{prompt_template.strip()}\n\nJSON:\n{evidence_package_json_for_llm(recon_data)}"
                sys_msg = JSON_ENRICHMENT_SYSTEM_PROMPT
                max_out = 768
            else:
                user_content = f"{prompt_template.strip()}\n\nJSON:\n{shrink_recon_payload_for_llm(recon_data)}"
                sys_msg = SYSTEM_PROMPT
                max_out = 1536
            payload = {
                "model": self.model,
                "messages": [{"role": "system", "content": sys_msg}, {"role": "user", "content": user_content}],
                "temperature": 0.0,
                "max_tokens": max_out,
                "stream": False,
                "chat_template_kwargs": {"enable_thinking": False},
                "extra_body": {"chat_template_kwargs": {"enable_thinking": False}, "enable_thinking": False},
            }
            response = requests.post(f"{self.url}/chat/completions", headers=self.headers, json=payload, timeout=120)
            response.raise_for_status()
            body = response.json()
            text = assistant_text_from_openai_chat_response(body)
            if text:
                return strip_think_spans(text) if strict_json_evidence else text.strip()
            fr = ((body.get("choices") or [{}])[0] or {}).get("finish_reason")
            return f"Error: local LLM returned empty content (finish_reason={fr!r}); model used reasoning_content instead of assistant content."
        except HTTPError as exc:
            body = (exc.response.text or "")[:2000] if exc.response is not None else ""
            return f"Error calling local LLM: {exc}\nResponse body (truncated):\n{body}"
        except Exception as e:
            return f"Error calling local LLM: {str(e)}"


class OllamaProvider(LocalProvider):
    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.url = url.rstrip('/')
        self.model = model

    def analyze(self, recon_data: Dict[str, Any], prompt_template: str, *, strict_json_evidence: bool = False) -> str:
        from .ai_json_enrichment import JSON_ENRICHMENT_SYSTEM_PROMPT, evidence_package_json_for_llm, strip_think_spans
        try:
            if strict_json_evidence:
                messages = [{"role": "system", "content": JSON_ENRICHMENT_SYSTEM_PROMPT}, {"role": "user", "content": f"{prompt_template}\n\nJSON:\n{evidence_package_json_for_llm(recon_data)}"}]
                num_predict = 768
            else:
                messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt_template + "\n\n" + shrink_recon_payload_for_llm(recon_data)}]
                num_predict = 1536
            response = requests.post(f"{self.url}/api/chat", json={"model": self.model, "messages": messages, "stream": False, "options": {"temperature": 0.0, "num_predict": num_predict}}, timeout=120)
            response.raise_for_status()
            content = response.json()["message"]["content"]
            return strip_think_spans(content) if strict_json_evidence else content
        except Exception as e:
            return f"Error calling Ollama: {str(e)}"


class AIAnalyzer:
    ANALYSIS_PROMPT = """Analyze this Blackbox Recon output for client-safe attack-surface triage. Be specific, do not invent CVEs, and do not provide exploit steps."""

    def __init__(self, provider: str, api_key: Optional[str] = None, model: Optional[str] = None, url: Optional[str] = None, temperature: float = 0.3, max_tokens: int = 4000):
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
            if not model:
                raise ValueError("Local LLM requires a model id. Pass --ai-model or ensure GET /v1/models returns models.")
            self.provider = LocalProvider(url or "http://localhost:1234/v1", model)
        elif provider == "ollama":
            self.provider = OllamaProvider(url or "http://localhost:11434", model or "llama3.1")
        else:
            raise ValueError(f"Unknown provider: {provider}. Choose: openai, claude, local, ollama")

    def analyze_recon_data(self, recon_data: Dict[str, Any], *, show_ai_narrative: bool = False, save_ai_raw: bool = False) -> AnalysisResult:
        from .ai_json_enrichment import LOCAL_JSON_ENRICHMENT_PROMPT, ai_output_fails_quality_gate, format_enrichment_markdown, next_steps_to_legacy_list, parse_ai_enrichment_json, strip_think_spans
        rprint(f"[bold cyan]{escape('[AI]')}[/bold cyan] Analyzing attack surface with [yellow]{escape(self.provider_name)}[/yellow]…")
        atk = list(recon_data.get("deterministic_attack_paths") or [])
        pri = list(recon_data.get("deterministic_findings") or [])
        if self.provider_name in ("local", "ollama"):
            raw_analysis = self.provider.analyze(recon_data, LOCAL_JSON_ENRICHMENT_PROMPT, strict_json_evidence=True)
            raw_llm_text = (raw_analysis or "") if save_ai_raw else None
            clean = strip_think_spans(raw_analysis or "")
            if (raw_analysis or "").strip().startswith("Error"):
                enrichment = _deterministic_local_fallback(recon_data, reason=str(raw_analysis or "local provider returned no usable content"))
                md = format_enrichment_markdown(enrichment)
                return AnalysisResult(attack_paths=atk, prioritized_findings=pri, executive_summary=enrichment["executive_summary"], technical_analysis=(md if show_ai_narrative else "AI provider produced no usable content; deterministic enrichment fallback applied."), confidence_score=0.75, recommended_next_steps=next_steps_to_legacy_list(enrichment.get("recommended_next_steps") or []), ai_status="fallback_deterministic", ai_discard_reason="provider_empty_or_error", ai_enrichment=enrichment, raw_llm_text=raw_llm_text)
            enrichment, err = parse_ai_enrichment_json(clean)
            if enrichment:
                md = format_enrichment_markdown(enrichment)
                if ai_output_fails_quality_gate(md):
                    enrichment = _deterministic_local_fallback(recon_data, reason="parsed model output failed quality gate")
                    md = format_enrichment_markdown(enrichment)
                    return AnalysisResult(attack_paths=atk, prioritized_findings=pri, executive_summary=enrichment["executive_summary"], technical_analysis=(md if show_ai_narrative else "AI output failed quality checks; deterministic enrichment fallback applied."), confidence_score=0.75, recommended_next_steps=next_steps_to_legacy_list(enrichment.get("recommended_next_steps") or []), ai_status="fallback_deterministic", ai_discard_reason="rendered_quality_gate", ai_enrichment=enrichment, raw_llm_text=raw_llm_text)
                return AnalysisResult(attack_paths=atk, prioritized_findings=pri, executive_summary=(enrichment.get("executive_summary") or "")[:500], technical_analysis=(md if show_ai_narrative else ""), confidence_score=0.85, recommended_next_steps=next_steps_to_legacy_list(enrichment.get("recommended_next_steps") or []), ai_status="applied", ai_enrichment=enrichment, raw_llm_text=raw_llm_text)
            enrichment = _deterministic_local_fallback(recon_data, reason=f"model output parse failed: {err}")
            md = format_enrichment_markdown(enrichment)
            return AnalysisResult(attack_paths=atk, prioritized_findings=pri, executive_summary=enrichment["executive_summary"], technical_analysis=(md if show_ai_narrative else "AI output could not be parsed; deterministic enrichment fallback applied."), confidence_score=0.75, recommended_next_steps=next_steps_to_legacy_list(enrichment.get("recommended_next_steps") or []), ai_status="fallback_deterministic", ai_discard_reason=err, ai_enrichment=enrichment, raw_llm_text=raw_llm_text)

        raw_analysis = self.provider.analyze(recon_data, self.ANALYSIS_PROMPT, strict_json_evidence=False)
        steps: List[Dict[str, Any]] = []
        narrative = raw_analysis
        if NEXT_STEPS_MARKER in (raw_analysis or ""):
            narrative, blob = split_next_steps_marker(raw_analysis)
            steps = parse_recommended_next_steps(blob)
        return AnalysisResult(attack_paths=atk, prioritized_findings=pri, executive_summary=(narrative or "")[:500], technical_analysis=narrative, confidence_score=0.85, recommended_next_steps=steps, ai_status="ok", raw_llm_text=(raw_analysis or "") if save_ai_raw else None)

    def generate_attack_path(self, entry_point: str, target_type: str) -> Dict[str, Any]:
        result = self.provider.analyze({}, f"Entry point context: {entry_point} (Type: {target_type})")
        return {"entry_point": entry_point, "target_type": target_type, "path": result}
