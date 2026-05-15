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
    "Return valid JSON only. You are Blackbox Recon Analyst. "
    "Use only the provided compact evidence package. "
    "deterministic_findings are authoritative: do not invent findings, CVEs, hosts, paths, services, or exploitability. "
    "No chain-of-thought, drafts, markdown, prose, exploit steps, payloads, or credential attacks."
)


LOCAL_JSON_ENRICHMENT_PROMPT = """
Return JSON only with exact keys:
{
  "executive_summary":"Two client-ready sentences maximum.",
  "risk_narrative":[{"finding_id":"DET-FIND-001","client_ready_text":"One concise paragraph using only evidence.","confidence_note":"Short uncertainty note."}],
  "cve_assessment":{"summary":"CVE status from evidence only.","confirmed_cves":[],"candidate_cves":[],"reasoning_limits":[]},
  "recommended_next_steps":[{"tool":"name","objective":"why","prerequisite":"scope condition","example_cli":"command with TARGET_IP/HOST placeholders","risk_notes":"ROE note"}],
  "quality_flags":[{"type":"coverage_gap","message":"Short factual note."}]
}
Use deterministic_findings as authoritative. Do not create new findings or change severity/status/evidence IDs. Max 5 next steps.
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


def _shorten(value: Any, max_len: int = 220) -> Any:
    if isinstance(value, str):
        v = " ".join(value.split())
        return v[: max_len - 3] + "..." if len(v) > max_len else v
    return value


def evidence_package_dict_for_llm(recon_data: Dict[str, Any], *, max_evidence: int = 12) -> Dict[str, Any]:
    """Return a compact package suitable for small local models.

    Qwen 9B deployments in LM Studio often run with 4096-token context. Avoid
    raw stdout, banners, TLS excerpts, and full evidence bodies; keep only the
    authoritative findings, metrics, coverage notes, and a small evidence index.
    """
    pkg = recon_data.get("evidence_package")
    if not isinstance(pkg, dict) or not pkg.get("deterministic_findings"):
        from .evidence import build_evidence_package

        eng = recon_data.get("engagement") or {}
        mods = list(eng.get("modules_requested") or ["subdomain", "portscan", "technology"])
        lab_mode = not bool(eng.get("record"))
        pkg = build_evidence_package(recon_data, mods, lab_mode=lab_mode)

    findings = []
    for f in list(pkg.get("deterministic_findings") or [])[:12]:
        if not isinstance(f, dict):
            continue
        findings.append(
            {
                "id": f.get("id"),
                "code": f.get("finding_code"),
                "severity": f.get("severity"),
                "status": f.get("status"),
                "title": _shorten(f.get("title"), 120),
                "assets": list(f.get("affected_assets") or [])[:4],
                "evidence_ids": list(f.get("evidence_ids") or [])[:6],
                "impact": _shorten(f.get("impact"), 220),
                "recommendation": _shorten(f.get("recommendation"), 220),
            }
        )

    evidence_index = []
    for e in list(pkg.get("evidence") or [])[:max_evidence]:
        if not isinstance(e, dict):
            continue
        observed = e.get("observed_value") or {}
        compact_observed = {}
        if isinstance(observed, dict):
            for k in (
                "state",
                "service",
                "version",
                "status_code",
                "final_url",
                "missing_security_headers",
                "disclosure_headers",
                "supported_protocols",
                "weak_signals",
                "target_type",
                "interesting_paths_found",
            ):
                if k in observed and observed.get(k) not in (None, "", [], {}):
                    compact_observed[k] = _shorten(observed.get(k), 180)
        evidence_index.append(
            {
                "id": e.get("id"),
                "phase": e.get("phase_id"),
                "type": e.get("observation_type"),
                "asset": _shorten(e.get("asset"), 160),
                "confidence": e.get("confidence"),
                "observed": compact_observed,
            }
        )

    summary = ((pkg.get("assessment") or {}).get("summary_metrics") or {})
    return {
        "schema_version": pkg.get("schema_version", "1.0"),
        "assessment": {
            "target": ((pkg.get("assessment") or {}).get("target")),
            "mode": ((pkg.get("assessment") or {}).get("mode")),
            "summary_metrics": summary,
        },
        "deterministic_findings": findings,
        "deterministic_attack_paths": list(pkg.get("deterministic_attack_paths") or [])[:3],
        "coverage_notes": list(pkg.get("coverage_notes") or [])[:6],
        "evidence_index": evidence_index,
        "_compact_for_local_llm": True,
    }


def evidence_package_json_for_llm(recon_data: Dict[str, Any], max_chars: int = 5200) -> str:
    pkg = evidence_package_dict_for_llm(recon_data)
    text = json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)
    if len(text) <= max_chars:
        return text
    for n in (8, 5, 3, 0):
        pkg2 = evidence_package_dict_for_llm(recon_data, max_evidence=n)
        text = json.dumps(pkg2, separators=(",", ":"), ensure_ascii=False)
        if len(text) <= max_chars:
            return text
    return json.dumps(
        {
            "schema_version": pkg.get("schema_version", "1.0"),
            "assessment": pkg.get("assessment") or {},
            "deterministic_findings": (pkg.get("deterministic_findings") or [])[:8],
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
