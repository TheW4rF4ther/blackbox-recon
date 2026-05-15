"""Strict JSON enrichment for local/Ollama models (evidence_package only)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

# Match ai_analyzer: strip Qwen-style think spans before JSON extract / quality gate.
_THINK_OPEN, _THINK_CLOSE = "<think>", "</think>"
_THINK_SPAN_RE = re.compile(
    re.escape(_THINK_OPEN) + r"[\s\S]*?" + re.escape(_THINK_CLOSE),
    re.IGNORECASE,
)


def strip_think_spans(text: str) -> str:
    return _THINK_SPAN_RE.sub("", (text or "")).strip()

# Reject obvious planning / scaffolding before attempting JSON parse.
_BAD_AI_PATTERN_STRS = [
    r"\bI need to\b",
    r"\bI should\b",
    r"\bI will\b",
    r"\bLet's\b",
    r"\bWait,\b",
    r"\bActually,\b",
    r"\bDraft\b",
    r"\bRefine\b",
    r"\bThinking\b",
    r"\bchain of thought\b",
    r"\bthe prompt\b",
    r"\bformat\b",
    r"\bmust be\b",
    r"\bLet's stick\b",
    r"\bLet's refine\b",
    r"\bframe risks\b",
]
BAD_AI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _BAD_AI_PATTERN_STRS]


JSON_ENRICHMENT_SYSTEM_PROMPT = (
    "You are Blackbox Recon Analyst. You return only valid JSON (no markdown fences, no prose before or after). "
    "You interpret an evidence_package produced by Blackbox Recon. "
    "deterministic_findings in that package are authoritative: do not invent new findings, "
    "do not change severity/status/evidence IDs, and do not invent CVEs, hosts, services, or paths. "
    "No chain-of-thought, planning, drafts, or self-correction. "
    "No exploit steps, payloads, credential attacks, persistence, evasion, or unauthorized access guidance."
)


LOCAL_JSON_ENRICHMENT_PROMPT = """
You will receive a JSON object: Blackbox Recon ``evidence_package`` with:
- ``assessment`` (metadata, summary_metrics)
- ``evidence`` (typed observations with IDs)
- ``deterministic_findings`` (authoritative findings)
- ``deterministic_attack_paths``
- ``coverage_notes``

Rules:
1. Treat ``deterministic_findings`` as authoritative.
2. Do not create new findings or alter severity, status, evidence_ids, or affected_assets on existing findings.
3. Do not invent CVEs; only state confirmed CVEs if explicitly present in evidence text (usually none).
4. Return **valid JSON only** matching the schema below (no markdown, no commentary).

Schema (exact keys):
{
  "executive_summary": "Two polished client-ready sentences maximum.",
  "risk_narrative": [
    {
      "finding_id": "DET-FIND-001",
      "client_ready_text": "One concise paragraph referencing only cited evidence.",
      "confidence_note": "Short note on evidence strength or uncertainty."
    }
  ],
  "cve_assessment": {
    "summary": "Whether any CVE is confirmed from evidence.",
    "confirmed_cves": [],
    "candidate_cves": [],
    "reasoning_limits": ["Short factual limitation strings only."]
  },
  "recommended_next_steps": [
    {
      "tool": "sslscan",
      "objective": "Assess TLS for observed HTTPS.",
      "prerequisite": "HTTPS observed; ROE permits TLS review.",
      "example_cli": "sslscan TARGET_IP",
      "risk_notes": "Non-invasive; confirm scope."
    }
  ],
  "quality_flags": [
    { "type": "coverage_gap", "message": "Short factual note." }
  ]
}

Use one ``risk_narrative`` entry per deterministic finding when possible (match ``finding_id``).
Keep ``recommended_next_steps`` to at most 5 items. Use placeholders TARGET_IP, HOST, WORDLIST in example_cli.
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
    """Extract a JSON object from model output (handles occasional fences or prefix junk)."""
    t = strip_think_spans(text or "")
    if not t:
        return None
    if "```" in t:
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
    return model.model_dump(), None


def evidence_package_dict_for_llm(recon_data: Dict[str, Any], *, max_evidence: int = 100) -> Dict[str, Any]:
    pkg = recon_data.get("evidence_package")
    if not isinstance(pkg, dict) or not pkg.get("evidence"):
        from .evidence import build_evidence_package

        eng = recon_data.get("engagement") or {}
        mods = list(eng.get("modules_requested") or ["subdomain", "portscan", "technology"])
        lab_mode = not bool(eng.get("record"))
        pkg = build_evidence_package(recon_data, mods, lab_mode=lab_mode)
    out = dict(pkg)
    ev = list(out.get("evidence") or [])
    if len(ev) > max_evidence:
        out["evidence"] = ev[:max_evidence]
        out["_evidence_omitted_count"] = len(ev) - max_evidence
    return out


def evidence_package_json_for_llm(recon_data: Dict[str, Any], max_chars: int = 16000) -> str:
    pkg = evidence_package_dict_for_llm(recon_data)
    text = json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)
    if len(text) <= max_chars:
        return text
    for n in (60, 40, 25, 15, 10, 5, 0):
        pkg2 = evidence_package_dict_for_llm(recon_data, max_evidence=n)
        text = json.dumps(pkg2, separators=(",", ":"), ensure_ascii=False)
        if len(text) <= max_chars:
            return text
    return json.dumps(
        {
            "schema_version": pkg.get("schema_version", "1.0"),
            "assessment": pkg.get("assessment") or {},
            "deterministic_findings": (pkg.get("deterministic_findings") or [])[:20],
            "deterministic_attack_paths": pkg.get("deterministic_attack_paths") or [],
            "coverage_notes": pkg.get("coverage_notes") or [],
            "_truncated": True,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def format_enrichment_markdown(enrichment: Dict[str, Any]) -> str:
    """Client-safe markdown block from validated JSON enrichment."""
    parts: List[str] = []
    ex = (enrichment.get("executive_summary") or "").strip()
    if ex:
        parts.append("### Executive summary (enrichment)\n\n" + ex + "\n")
    rn = enrichment.get("risk_narrative") or []
    if rn:
        parts.append("### Risk narrative (by finding)\n\n")
        for item in rn:
            if not isinstance(item, dict):
                continue
            fid = item.get("finding_id", "")
            body = (item.get("client_ready_text") or "").strip()
            note = (item.get("confidence_note") or "").strip()
            if not body:
                continue
            parts.append(f"**{fid}**  \n{body}\n")
            if note:
                parts.append(f"*Evidence note:* {note}\n\n")
    cve = enrichment.get("cve_assessment") or {}
    if isinstance(cve, dict) and (cve.get("summary") or cve.get("reasoning_limits")):
        parts.append("### CVE assessment (enrichment)\n\n")
        if cve.get("summary"):
            parts.append(str(cve["summary"]) + "\n\n")
        for lim in cve.get("reasoning_limits") or []:
            parts.append(f"- {lim}\n")
        parts.append("\n")
    qf = enrichment.get("quality_flags") or []
    if qf:
        parts.append("### Quality flags\n\n")
        for q in qf:
            if isinstance(q, dict) and q.get("message"):
                parts.append(f"- **{q.get('type', 'note')}:** {q['message']}\n")
        parts.append("\n")
    return "\n".join(parts).strip()


def next_steps_to_legacy_list(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Map JSON next steps to the existing ``recommended_next_steps`` row shape."""
    out: List[Dict[str, Any]] = []
    for s in steps[:8]:
        if not isinstance(s, dict):
            continue
        out.append(
            {
                "tool": str(s.get("tool", "")).strip()[:120],
                "objective": str(s.get("objective", "")).strip()[:500],
                "prerequisite": str(s.get("prerequisite", "")).strip()[:500],
                "example_cli": str(s.get("example_cli", "")).strip()[:800],
                "risk_notes": str(s.get("risk_notes", "")).strip()[:500],
            }
        )
    return [r for r in out if r.get("tool")]
