"""Strict JSON enrichment for local/Ollama models using normalized tool results."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

_THINK_SPAN_RE = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)


def strip_think_spans(text: str) -> str:
    return _THINK_SPAN_RE.sub("", (text or "")).strip()


BAD_AI_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bI need to\b",
        r"\bI should\b",
        r"\bLet's\b",
        r"\bWait,\b",
        r"\bActually,\b",
        r"\bDraft\b",
        r"\bRefine\b",
        r"\bThinking\b",
        r"\bchain of thought\b",
        r"\breasoning process\b",
        r"\bthe prompt\b",
    ]
]


JSON_ENRICHMENT_SYSTEM_PROMPT = (
    "/no_think\n"
    "You are Blackbox Recon Analyst. Return one compact valid JSON object only. "
    "Analyze only the normalized tool_results provided by the scanner. "
    "No reasoning. No markdown. No prose outside JSON. No drafts. "
    "Do not invent CVEs, hosts, paths, services, vulnerabilities, or exploitability."
)


LOCAL_JSON_ENRICHMENT_PROMPT = """
/no_think
Return ONLY minified JSON using this schema:
{"executive_summary":"max 2 sentences","risk_narrative":[{"finding_id":"TOOL-001","client_ready_text":"1 short sentence based on tool output","confidence_note":"short note"}],"cve_assessment":{"summary":"short","confirmed_cves":[],"candidate_cves":[],"reasoning_limits":[]},"recommended_next_steps":[{"tool":"tool","objective":"specific validation goal","prerequisite":"short","example_cli":"tool TARGET","risk_notes":"short"}],"quality_flags":[{"type":"coverage_gap","message":"short"}]}
Rules: use only tool_results and vulnerability_signals. Max 3 risk_narrative items, max 4 next steps, every string under 180 chars.
""".strip()


class RiskNarrativeItem(BaseModel):
    model_config = {"extra": "ignore"}
    finding_id: str = ""
    client_ready_text: str = ""
    confidence_note: str = ""


class CveAssessmentOut(BaseModel):
    model_config = {"extra": "ignore"}
    summary: str = ""
    confirmed_cves: List[str] = Field(default_factory=list)
    candidate_cves: List[str] = Field(default_factory=list)
    reasoning_limits: List[str] = Field(default_factory=list)


class NextStepItem(BaseModel):
    model_config = {"extra": "ignore"}
    tool: str = ""
    objective: str = ""
    prerequisite: str = ""
    example_cli: str = ""
    risk_notes: str = ""


class QualityFlag(BaseModel):
    model_config = {"extra": "ignore"}
    type: str = ""
    message: str = ""


class AiEnrichmentResponse(BaseModel):
    model_config = {"extra": "ignore"}
    executive_summary: str = ""
    risk_narrative: List[RiskNarrativeItem] = Field(default_factory=list)
    cve_assessment: CveAssessmentOut = Field(default_factory=CveAssessmentOut)
    recommended_next_steps: List[NextStepItem] = Field(default_factory=list)
    quality_flags: List[QualityFlag] = Field(default_factory=list)


def ai_output_fails_quality_gate(text: str) -> bool:
    if not (text or "").strip():
        return True
    low = text.lower()
    for pat in BAD_AI_PATTERNS:
        if pat.search(text):
            return True
    if "error:" in low[:80] and "local llm" in low[:120]:
        return True
    return False


def extract_json_object(text: str) -> Optional[str]:
    t = strip_think_spans(text or "")
    if not t:
        return None
    t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.IGNORECASE).strip()
    t = re.sub(r"\s*```\s*$", "", t).strip()
    start = t.find("{")
    end = t.rfind("}")
    if start == -1 or end <= start:
        return None
    return t[start : end + 1]


def parse_ai_enrichment_json(raw: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    blob = extract_json_object(raw)
    if not blob:
        return None, "no_json_object"
    try:
        data = json.loads(blob)
    except json.JSONDecodeError as e:
        return None, f"json_decode:{e}"
    try:
        model = AiEnrichmentResponse.model_validate(data)
    except Exception as e:
        return None, f"pydantic:{e}"
    out = model.model_dump()
    out["risk_narrative"] = out.get("risk_narrative", [])[:3]
    out["recommended_next_steps"] = out.get("recommended_next_steps", [])[:4]
    out["quality_flags"] = out.get("quality_flags", [])[:4]
    return out, None


def _shorten(value: Any, max_len: int = 180) -> Any:
    if isinstance(value, str):
        v = " ".join(value.split())
        return v[: max_len - 3] + "..." if len(v) > max_len else v
    if isinstance(value, list):
        return value[:8]
    if isinstance(value, dict):
        return {str(k)[:40]: _shorten(v, 140) for k, v in list(value.items())[:8]}
    return value


def tool_results_dict_for_llm(recon_data: Dict[str, Any], *, max_tools: int = 10) -> Dict[str, Any]:
    """Return an ultra-compact package built from normalized tool_results."""
    from .tool_results import build_tool_results

    raw_tools = build_tool_results(recon_data)
    tools: List[Dict[str, Any]] = []
    for t in raw_tools[:max_tools]:
        if not isinstance(t, dict):
            continue
        tools.append(
            {
                "id": t.get("id"),
                "tool": t.get("tool"),
                "purpose": _shorten(t.get("purpose"), 110),
                "status": t.get("status"),
                "assets": list(t.get("assets") or [])[:4],
                "important_output": [_shorten(x, 170) for x in list(t.get("important_output") or [])[:6]],
                "signals": [_shorten(x, 90) for x in list(t.get("signals") or [])[:6]],
            }
        )

    findings = []
    for f in list(recon_data.get("deterministic_findings") or [])[:8]:
        if not isinstance(f, dict):
            continue
        code = str(f.get("finding_code") or "")
        # Keep signals that are not just obvious exposure restatements.
        if code.startswith("BBR-EXPOSURE"):
            continue
        findings.append(
            {
                "id": f.get("id"),
                "code": code,
                "severity": f.get("severity"),
                "title": _shorten(f.get("title"), 110),
                "assets": list(f.get("affected_assets") or [])[:3],
            }
        )

    summary = recon_data.get("summary") or {}
    return {
        "target": recon_data.get("target"),
        "summary": {
            "open_ports": summary.get("total_open_ports", summary.get("open_tcp_ports", 0)),
            "http_services": summary.get("http_services_detected", 0),
            "content_hits": summary.get("interesting_paths_found", 0),
            "tools": len(raw_tools),
        },
        "tool_results": tools,
        "vulnerability_signals": findings,
        "instruction": "Recommend technical validation paths only from these tool_results. If evidence is insufficient, say so.",
    }


def evidence_package_dict_for_llm(recon_data: Dict[str, Any], *, max_evidence: int = 4, max_findings: int = 8) -> Dict[str, Any]:
    """Compatibility wrapper: AI now receives normalized tool_results, not evidence_package."""
    return tool_results_dict_for_llm(recon_data)


def evidence_package_json_for_llm(recon_data: Dict[str, Any], max_chars: int = 3000) -> str:
    for max_tools in (10, 8, 6, 4):
        pkg = tool_results_dict_for_llm(recon_data, max_tools=max_tools)
        text = json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)
        if len(text) <= max_chars:
            return text
    pkg = tool_results_dict_for_llm(recon_data, max_tools=3)
    return json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)[:max_chars]


def format_enrichment_markdown(enrichment: Dict[str, Any]) -> str:
    parts: List[str] = []
    ex = (enrichment.get("executive_summary") or "").strip()
    if ex:
        parts.append("### Executive summary (enrichment)\n\n" + ex + "\n")
    rn = enrichment.get("risk_narrative") or []
    if rn:
        parts.append("### Risk narrative (by tool result)\n\n")
        for item in rn[:3]:
            if not isinstance(item, dict):
                continue
            fid = item.get("finding_id", "")
            body = (item.get("client_ready_text") or "").strip()
            note = (item.get("confidence_note") or "").strip()
            if body:
                parts.append(f"**{fid}**  \n{body}\n")
            if note:
                parts.append(f"*Evidence note:* {note}\n\n")
    cve = enrichment.get("cve_assessment") or {}
    if isinstance(cve, dict) and cve.get("summary"):
        parts.append("### CVE assessment (enrichment)\n\n" + str(cve.get("summary")) + "\n")
    qf = enrichment.get("quality_flags") or []
    if qf:
        parts.append("### Quality flags\n\n")
        for q in qf[:4]:
            if isinstance(q, dict) and q.get("message"):
                parts.append(f"- **{q.get('type', 'note')}:** {q['message']}\n")
    return "\n".join(parts).strip()


def next_steps_to_legacy_list(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in steps[:4]:
        if not isinstance(s, dict):
            continue
        out.append(
            {
                "tool": str(s.get("tool", "")).strip()[:80],
                "objective": str(s.get("objective", "")).strip()[:220],
                "prerequisite": str(s.get("prerequisite", "")).strip()[:220],
                "example_cli": str(s.get("example_cli", "")).strip()[:220],
                "risk_notes": str(s.get("risk_notes", "")).strip()[:220],
            }
        )
    return [r for r in out if r.get("tool")]
