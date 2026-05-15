"""Strict JSON enrichment for local/Ollama models (evidence_package only)."""

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
    "No reasoning. No markdown. No prose outside JSON. No drafts. "
    "Use only the provided evidence. Do not invent CVEs, hosts, paths, services, or exploitability."
)


LOCAL_JSON_ENRICHMENT_PROMPT = """
/no_think
Return ONLY minified JSON using this schema:
{"executive_summary":"max 2 sentences","risk_narrative":[{"finding_id":"DET-FIND-001","client_ready_text":"1 short sentence","confidence_note":"short note"}],"cve_assessment":{"summary":"short","confirmed_cves":[],"candidate_cves":[],"reasoning_limits":[]},"recommended_next_steps":[{"tool":"tool","objective":"short","prerequisite":"short","example_cli":"tool TARGET","risk_notes":"short"}],"quality_flags":[{"type":"coverage_gap","message":"short"}]}
Limits: risk_narrative max 3 items, recommended_next_steps max 4 items, every string under 180 chars. Use deterministic_findings only.
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


def _shorten(value: Any, max_len: int = 160) -> Any:
    if isinstance(value, str):
        v = " ".join(value.split())
        return v[: max_len - 3] + "..." if len(v) > max_len else v
    if isinstance(value, list):
        return value[:6]
    if isinstance(value, dict):
        return {str(k)[:40]: _shorten(v, 120) for k, v in list(value.items())[:6]}
    return value


def evidence_package_dict_for_llm(recon_data: Dict[str, Any], *, max_evidence: int = 4, max_findings: int = 8) -> Dict[str, Any]:
    """Return an ultra-compact package for 4K-context local reasoning models."""
    pkg = recon_data.get("evidence_package")
    if not isinstance(pkg, dict) or not pkg.get("deterministic_findings"):
        from .evidence import build_evidence_package
        eng = recon_data.get("engagement") or {}
        mods = list(eng.get("modules_requested") or ["subdomain", "portscan", "technology"])
        lab_mode = not bool(eng.get("record"))
        pkg = build_evidence_package(recon_data, mods, lab_mode=lab_mode)

    findings = []
    for f in list(pkg.get("deterministic_findings") or [])[:max_findings]:
        if isinstance(f, dict):
            findings.append(
                {
                    "id": f.get("id"),
                    "code": f.get("finding_code"),
                    "sev": f.get("severity"),
                    "title": _shorten(f.get("title"), 90),
                    "assets": list(f.get("affected_assets") or [])[:2],
                    "evidence_ids": list(f.get("evidence_ids") or [])[:3],
                }
            )

    evidence_index = []
    for e in list(pkg.get("evidence") or [])[:max_evidence]:
        if not isinstance(e, dict):
            continue
        observed = e.get("observed_value") or {}
        compact = {}
        if isinstance(observed, dict):
            for k in ("service", "version", "status_code", "missing_security_headers", "supported_protocols", "weak_signals", "target_type"):
                if observed.get(k) not in (None, "", [], {}):
                    compact[k] = _shorten(observed.get(k), 100)
        evidence_index.append({"id": e.get("id"), "phase": e.get("phase_id"), "type": e.get("observation_type"), "asset": _shorten(e.get("asset"), 90), "observed": compact})

    assessment = pkg.get("assessment") or {}
    summary = assessment.get("summary_metrics") or {}
    return {
        "target": assessment.get("target"),
        "mode": assessment.get("mode"),
        "metrics": summary,
        "findings": findings,
        "coverage_notes": list(pkg.get("coverage_notes") or [])[:4],
        "evidence_index": evidence_index,
    }


def evidence_package_json_for_llm(recon_data: Dict[str, Any], max_chars: int = 2600) -> str:
    for max_findings, max_evidence in ((8, 4), (6, 2), (4, 0)):
        pkg = evidence_package_dict_for_llm(recon_data, max_evidence=max_evidence, max_findings=max_findings)
        text = json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)
        if len(text) <= max_chars:
            return text
    pkg = evidence_package_dict_for_llm(recon_data, max_evidence=0, max_findings=3)
    return json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)[:max_chars]


def format_enrichment_markdown(enrichment: Dict[str, Any]) -> str:
    parts: List[str] = []
    ex = (enrichment.get("executive_summary") or "").strip()
    if ex:
        parts.append("### Executive summary (enrichment)\n\n" + ex + "\n")
    rn = enrichment.get("risk_narrative") or []
    if rn:
        parts.append("### Risk narrative (by finding)\n\n")
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
