"""Strict JSON enrichment for AI models using service-centric assessments."""

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
        r"TOOL-\d+",
    ]
]


JSON_ENRICHMENT_SYSTEM_PROMPT = (
    "/no_think\n"
    "You are Blackbox Recon Analyst. Return one compact valid JSON object only. "
    "Analyze only the service_assessments provided by the scanner. "
    "Speak in service terms such as SSH, HTTP, HTTPS, TLS, SMB, FTP, SMTP, and RDP. "
    "Do not mention TOOL IDs. No reasoning. No markdown. No prose outside JSON. "
    "Do not invent CVEs, hosts, paths, services, vulnerabilities, or exploitability."
)


LOCAL_JSON_ENRICHMENT_PROMPT = """
/no_think
Return ONLY minified JSON using this schema:
{"executive_summary":"max 2 sentences","risk_narrative":[{"finding_id":"SSH|HTTP|HTTPS|TLS|SMB|FTP|SMTP|RDP|SCOPE","client_ready_text":"1 short sentence based on service assessment","confidence_note":"short evidence/limitation note"}],"cve_assessment":{"summary":"short","confirmed_cves":[],"candidate_cves":[],"reasoning_limits":[]},"recommended_next_steps":[{"tool":"tool or method","objective":"specific validation goal","prerequisite":"short","example_cli":"tool TARGET","risk_notes":"short"}],"quality_flags":[{"type":"coverage_gap|no_confirmed_findings|evidence_limit","message":"short"}]}
Rules: use only service_assessments, candidate_findings, negative_results, verification_targets, and limitations. Never mention TOOL IDs. Max 4 risk_narrative items, max 4 next steps, every string under 180 chars.
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
    out["risk_narrative"] = out.get("risk_narrative", [])[:4]
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


def service_assessments_dict_for_llm(recon_data: Dict[str, Any], *, max_services: int = 12) -> Dict[str, Any]:
    """Return compact service-centric package for AI enrichment."""
    from .service_assessment import build_service_assessments

    assessment = build_service_assessments(recon_data)
    services: List[Dict[str, Any]] = []
    for svc in (assessment.get("assessments") or [])[:max_services]:
        if not isinstance(svc, dict):
            continue
        services.append(
            {
                "service": svc.get("service"),
                "asset": f"{svc.get('host')}:{svc.get('port')}",
                "observed": [_shorten(x, 150) for x in (svc.get("observed") or [])[:4]],
                "candidate_findings": [_shorten(x, 180) for x in (svc.get("candidate_findings") or [])[:4]],
                "negative_results": [_shorten(x, 150) for x in (svc.get("negative_results") or [])[:4]],
                "operator_notes": [_shorten(x, 160) for x in (svc.get("operator_notes") or [])[:3]],
                "verification_targets": [_shorten(x, 150) for x in (svc.get("verification_targets") or [])[:4]],
            }
        )
    return {
        "target": assessment.get("target"),
        "target_type": assessment.get("target_type"),
        "summary": assessment.get("summary") or {},
        "limitations": [_shorten(x, 170) for x in (assessment.get("limitations") or [])[:5]],
        "service_assessments": services,
        "candidate_findings": [_shorten(x, 180) for x in (assessment.get("candidate_findings") or [])[:8]],
        "negative_results": [_shorten(x, 170) for x in (assessment.get("negative_results") or [])[:8]],
        "verification_targets": [_shorten(x, 170) for x in (assessment.get("verification_targets") or [])[:8]],
        "instruction": "Return service-centric analyst notes. If evidence is insufficient, say no confirmed finding. Never mention TOOL IDs.",
    }


def tool_results_dict_for_llm(recon_data: Dict[str, Any], *, max_tools: int = 10) -> Dict[str, Any]:
    """Compatibility name; returns service assessments now."""
    return service_assessments_dict_for_llm(recon_data, max_services=max_tools)


def evidence_package_dict_for_llm(recon_data: Dict[str, Any], *, max_evidence: int = 4, max_findings: int = 8) -> Dict[str, Any]:
    return service_assessments_dict_for_llm(recon_data)


def evidence_package_json_for_llm(recon_data: Dict[str, Any], max_chars: int = 3000) -> str:
    for max_services in (12, 8, 6, 4):
        pkg = service_assessments_dict_for_llm(recon_data, max_services=max_services)
        text = json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)
        if len(text) <= max_chars:
            return text
    pkg = service_assessments_dict_for_llm(recon_data, max_services=3)
    return json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)[:max_chars]


def format_enrichment_markdown(enrichment: Dict[str, Any]) -> str:
    parts: List[str] = []
    ex = (enrichment.get("executive_summary") or "").strip()
    if ex:
        parts.append("### AI Analyst Summary\n\n" + ex + "\n")
    rn = enrichment.get("risk_narrative") or []
    if rn:
        parts.append("### Service-Centric Analyst Notes\n\n")
        for item in rn[:4]:
            if not isinstance(item, dict):
                continue
            fid = str(item.get("finding_id", "") or "Service").replace("TOOL-", "")
            body = (item.get("client_ready_text") or "").strip()
            note = (item.get("confidence_note") or "").strip()
            if body:
                parts.append(f"**{fid}**  \n{body}\n")
            if note:
                parts.append(f"*Evidence note:* {note}\n\n")
    cve = enrichment.get("cve_assessment") or {}
    if isinstance(cve, dict) and cve.get("summary"):
        parts.append("### CVE Assessment\n\n" + str(cve.get("summary")) + "\n")
    qf = enrichment.get("quality_flags") or []
    if qf:
        parts.append("### Quality Flags\n\n")
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
