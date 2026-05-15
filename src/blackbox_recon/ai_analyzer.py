"""AI-powered analysis module with pluggable backends."""

import json
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

import requests
from requests import HTTPError
from rich import print as rprint
from rich.markup import escape


# Strip common "thinking" spans (Qwen / similar chat templates).
_THINK_OPEN, _THINK_CLOSE = "<think>", "</think>"
_THINK_SPAN_RE = re.compile(
    re.escape(_THINK_OPEN) + r"[\s\S]*?" + re.escape(_THINK_CLOSE),
    re.IGNORECASE,
)


def _strip_rich_panel_borders(text: str) -> str:
    """Remove Rich ``Panel`` border characters so ``^`` regexes match real content."""
    lines: List[str] = []
    for line in text.splitlines():
        lines.append(re.sub(r"^[│┃┆┇]\s*", "", line))
    return "\n".join(lines)


def _coerce_openai_message_content(value: Any) -> str:
    """Normalize ``message.content`` which may be str, null, or a list of content parts."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: List[str] = []
        for block in value:
            if isinstance(block, dict):
                if block.get("type") == "text" and block.get("text"):
                    parts.append(str(block["text"]))
                elif isinstance(block.get("text"), str):
                    parts.append(str(block["text"]))
            elif isinstance(block, str):
                parts.append(block)
        return "".join(parts)
    return str(value)


def assistant_text_from_openai_chat_response(data: Dict[str, Any]) -> str:
    """Extract visible assistant text from an OpenAI-style ``/v1/chat/completions`` JSON body."""
    choices = data.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return ""
    ch0 = choices[0]
    msg = ch0.get("message") if isinstance(ch0.get("message"), dict) else {}
    blobs: List[str] = []
    for key in ("content", "reasoning_content", "reasoning"):
        if not isinstance(msg, dict):
            break
        chunk = _coerce_openai_message_content(msg.get(key)).strip()
        if chunk:
            blobs.append(chunk)
    combined = "\n\n".join(blobs).strip()
    combined = _THINK_SPAN_RE.sub("", combined).strip()
    if not combined and isinstance(ch0.get("text"), str):
        combined = _THINK_SPAN_RE.sub("", ch0["text"]).strip()
    return combined


def _normalize_local_section_headers(text: str) -> str:
    """Flatten bullet- and bold-wrapped section labels (Qwen drafts) to plain ``1) …`` lines."""
    # Run twice: nested bullets sometimes need a second pass.
    t = text
    # Qwen often ends bold headers as ``Title:**`` (colon then closing ``**``), not ``**:``.
    # Avoid ``(?:bullet\\s*){N}\\*+`` — it can consume inner ``**`` and leave stray stars.
    pairs: List[Tuple[str, str]] = [
        (
            r"(?m)^\s*[\*\-•]\s+\*{1,2}\s*1\)\s*Executive\s+summary\s*:\*+\s*",
            "1) Executive summary\n",
        ),
        (
            r"(?m)^\s*[\*\-•]\s+\*{1,2}\s*2\)\s*Top\s+risks\s*:\*+\s*",
            "2) Top risks\n",
        ),
        (
            r"(?m)^\s*[\*\-•]\s+\*{1,2}\s*3\)\s*Likely\s+vulnerabilities\s*/\s*candidate\s+CVEs\s*:\*+\s*",
            "3) Likely vulnerabilities / candidate CVEs\n",
        ),
        (
            r"(?m)^\s*[\*\-•]\s+\*{1,2}\s*4\)\s*Plausible\s+attack\s+paths\s*:\*+\s*",
            "4) Plausible attack paths\n",
        ),
        (
            r"(?m)^\s*[\*\-•]\s+\*{1,2}\s*5\)\s*Top\s+remediations\s*:\*+\s*",
            "5) Top remediations\n",
        ),
        (
            r"(?m)^\s*[\*\-•]\s+\*{1,2}\s*6\)\s*Analyst\s+caveats\s*:\*+\s*",
            "6) Analyst caveats\n",
        ),
        # Lines that start directly with bold (no outer bullet).
        (
            r"(?m)^\s*\*{1,2}\s*1\)\s*Executive\s+summary\s*:\*+\s*",
            "1) Executive summary\n",
        ),
        (
            r"(?m)^\s*\*{1,2}\s*2\)\s*Top\s+risks\s*:\*+\s*",
            "2) Top risks\n",
        ),
        (
            r"(?m)^\s*\*{1,2}\s*3\)\s*Likely\s+vulnerabilities\s*/\s*candidate\s+CVEs\s*:\*+\s*",
            "3) Likely vulnerabilities / candidate CVEs\n",
        ),
        (
            r"(?m)^\s*\*{1,2}\s*4\)\s*Plausible\s+attack\s+paths\s*:\*+\s*",
            "4) Plausible attack paths\n",
        ),
        (
            r"(?m)^\s*\*{1,2}\s*5\)\s*Top\s+remediations\s*:\*+\s*",
            "5) Top remediations\n",
        ),
        (
            r"(?m)^\s*\*{1,2}\s*6\)\s*Analyst\s+caveats\s*:\*+\s*",
            "6) Analyst caveats\n",
        ),
        (
            r"(?m)^\s*[\*\-•]+\s*\*{1,2}\s*1\)\s*Executive\s+summary\s*:\*+\s*",
            "1) Executive summary\n",
        ),
        (
            r"(?m)^\s*[\*\-•]+\s*\*{1,2}\s*2\)\s*Top\s+risks\s*:\*+\s*",
            "2) Top risks\n",
        ),
        (
            r"(?m)^\s*[\*\-•]+\s*\*{1,2}\s*3\)\s*Likely\s+vulnerabilities\s*/\s*candidate\s+CVEs\s*:\*+\s*",
            "3) Likely vulnerabilities / candidate CVEs\n",
        ),
        (
            r"(?m)^\s*[\*\-•]+\s*\*{1,2}\s*4\)\s*Plausible\s+attack\s+paths\s*:\*+\s*",
            "4) Plausible attack paths\n",
        ),
        (
            r"(?m)^\s*[\*\-•]+\s*\*{1,2}\s*5\)\s*Top\s+remediations\s*:\*+\s*",
            "5) Top remediations\n",
        ),
        (
            r"(?m)^\s*[\*\-•]+\s*\*{1,2}\s*6\)\s*Analyst\s+caveats\s*:\*+\s*",
            "6) Analyst caveats\n",
        ),
    ]
    for _ in range(2):
        for pat, rep in pairs:
            t = re.sub(pat, rep, t, flags=re.IGNORECASE)
    return t


def _try_extract_after_drafting_content(t: str) -> Optional[str]:
    """Extract body after ``Drafting Content`` / ``Section by Section`` style headings (Qwen)."""
    patterns = [
        # Qwen: ``3.  **Drafting Content - Section by Section:**`` (colon then closing ``**``).
        r"(?is)\d+\.\s*\*{1,2}\s*Drafting\s+Content\s*-\s*Section\s+by\s+Section\s*:\*+\s*\n",
        r"(?is)\d+\.\s*\*+\s*Drafting\s+Content\b.*?:\s*\*+\s*\n",
        r"(?is)\d+\.\s*\*+\s*Drafting\s+Content\b[^:\n]*:\s*\n",
        r"(?is)\*+\s*Drafting\s+Content\b[^:\n]*:\s*\*+\s*\n",
    ]
    for pat in patterns:
        m = re.search(pat, t)
        if m:
            tail = t[m.end() :].strip()
            tail = _normalize_local_section_headers(tail)
            tail = tail.strip()
            # Normalization shortens Qwen-style lines; keep threshold low enough for short exec summaries.
            if len(tail) >= 50:
                return tail
    return None


def _try_extract_after_drafting_sections(t: str) -> Optional[str]:
    """Take body after 'Drafting the Sections' (Qwen often puts real content there)."""
    m = re.search(
        r"(?is)\d+\.\s*\*+Draft(?:ing)?\s+the\s+Sections\s*:\s*\**\s*",
        t,
    )
    if not m:
        return None
    tail = t[m.end() :].strip()
    tail = _normalize_local_section_headers(tail)
    tail = tail.strip()
    if len(tail) < 60:
        return None
    return tail


def _try_extract_executive_summary_inline(t: str) -> Optional[str]:
    """Find late '1) Executive summary …' blocks (skip early instruction echoes)."""
    patterns = [
        re.compile(r"(?i)1\)\s*Executive\s+summary\s*\*?:\s+The\s+"),
        re.compile(r"(?i)1\)\s*Executive\s+summary\s*\r?\n\s*\S"),
        re.compile(r"(?i)1\)\s*Executive\s+summary\s*\*?:\s+\S"),
    ]
    min_cut = max(250, int(len(t) * 0.06))

    def _pick_start(pat: re.Pattern) -> Optional[int]:
        hits = [m.start() for m in pat.finditer(t)]
        if not hits:
            return None
        late = [h for h in hits if h >= min_cut]
        return late[0] if late else hits[-1]

    start: Optional[int] = None
    for pat in patterns:
        start = _pick_start(pat)
        if start is not None:
            break
    if start is None:
        return None
    tail = t[start:].strip()
    tail = _normalize_local_section_headers(tail)
    return tail if len(tail) > 120 else None


def _strip_local_visible_thinking_preamble(text: str) -> str:
    """Drop Qwen-style visible planning when deliverable text appears later in the string."""
    t = text.strip()
    if not t:
        return t

    t_norm = _normalize_local_section_headers(t)

    matches = list(re.finditer(r"(?im)^1\)\s*Executive\s+summary\b", t_norm))
    if matches:
        if len(matches) == 1:
            return t_norm[matches[0].start() :].strip()
        low = t_norm.lower()
        min_pos = max(400, int(len(t_norm) * 0.03))
        if "thinking process" in low[:6000] or "drafting content" in low[:9000]:
            min_pos = max(min_pos, 800)
        late = [m for m in matches if m.start() >= min_pos]
        pick = late[0] if late else matches[-1]
        return t_norm[pick.start() :].strip()

    m2 = re.search(r"(?im)^2\)\s*Top\s+risks\b", t_norm)
    if m2 and m2.start() > 40:
        return t_norm[m2.start() :].strip()

    drafted_content = _try_extract_after_drafting_content(t_norm)
    if drafted_content:
        return drafted_content

    drafted = _try_extract_after_drafting_sections(t_norm)
    if drafted:
        return drafted

    extracted = _try_extract_executive_summary_inline(t_norm)
    if extracted:
        return extracted

    low = t_norm.lower()
    if "thinking process" in low[:5000]:
        return (
            "[!] The local model returned visible planning only; could not locate sections 1)-6) "
            "in the text. In LM Studio: raise Completion tokens, disable reasoning, or use a "
            "non-thinking chat model.\n\n"
            + t_norm[:6500]
        )
    return t_norm


def _unwrap_star_draft_lines(text: str) -> str:
    """Turn ``* Draft: <actual prose>`` into just the prose (models often label the real answer as Draft)."""
    pat = re.compile(r"(?mi)^(\s*)\*+\s*Draft:\s*(.+)$")
    out_lines: List[str] = []
    for line in text.splitlines():
        m = pat.match(line)
        if m:
            body = m.group(2).strip()
            if len(body) >= 12:
                out_lines.append(body)
                continue
        out_lines.append(line)
    return "\n".join(out_lines)


def _drop_star_prefixed_rubric_lines(text: str) -> str:
    """Remove Qwen-style rubric echoes that start with a star bullet (not part of the deliverable)."""
    # Note: do not use ``\b`` immediately after ``:`` — word boundaries do not occur between ``:`` and space,
    # so lines like ``*   Constraint: Max 2 sentences`` would incorrectly survive.
    kill = re.compile(
        r"(?mi)^\s*\*+\s*("
        r"Must be\b|"
        r"Format:|"
        r"Constraint:|"
        r"Content:|"
        r"Draft:\s*$|"
        r"Refining\b|"
        r"Bullet\s+\d+:|"
        r"Each bullet\b|"
        r"Each path\b|"
        r"Rules for\b|"
        r"Exactly\s+\d+\s+bullets?\b|"
        r"Up to\s+\d+\s+bullets?\b|"
        r"Provide up to\b|"
        r"I need to\b|"
        r"I must\b|"
        r"I should\b|"
        r"I will\b|"
        r"The JSON doesn'?t\b|"
        r"Since the prompt\b|"
        r"Based on the data\b|"
        r"There aren'?t many\b|"
        r"Drafting\b|"
        r"One line JSON\b|"
        r"Pattern:|"
        r"Mention uncertainty\b|"
        r"Data limitation\b|"
        r"Summarize exposed\b|"
        r"1-\d+\s+paths\.?\s*$|"
        r"Actually,\s+standard practice\b|"
        r"Actually,\s+based\b"
        r").*$"
    )
    out: List[str] = []
    for line in text.splitlines():
        if kill.match(line):
            continue
        out.append(line)
    return "\n".join(out)


def _collapse_blank_lines(text: str, max_blank_run: int = 2) -> str:
    """Collapse runs of empty lines so panels do not look sparse after stripping."""
    lines = text.splitlines()
    out: List[str] = []
    blank_run = 0
    for line in lines:
        if not line.strip():
            blank_run += 1
            if blank_run <= max_blank_run:
                out.append("")
        else:
            blank_run = 0
            out.append(line)
    return "\n".join(out).strip()


def _strip_trailing_meta_followup_section(text: str) -> str:
    """
    Remove model echoes of a fake ``7) Recommended…`` block when the real ``NEXT_STEPS_JSON:`` line is absent.
    """
    if not text.strip():
        return text
    if NEXT_STEPS_MARKER in text:
        return text
    patterns = [
        r"(?mi)^\s*\*+\s*\*+\s*7\)\s*Recommended\b[^\n]*$",
        r"(?mi)^\s*\*+\s*7\)\s*Recommended\b[^\n]*$",
        r"(?mi)^\s*\*+\s*\*{0,2}\s*Recommended follow-up tooling\b[^\n]*$",
    ]
    cut: Optional[int] = None
    for pat in patterns:
        m = re.search(pat, text, flags=re.MULTILINE)
        if m and (cut is None or m.start() < cut):
            cut = m.start()
    if cut is not None:
        return text[:cut].rstrip()
    return text


def _finalize_local_assistant_markdown(text: str) -> str:
    """Normalize local LLM text for display (strip template think spans + visible planning)."""
    t = _strip_rich_panel_borders(text)
    t = _THINK_SPAN_RE.sub("", t).strip()
    t = _normalize_local_section_headers(t)
    t = _unwrap_star_draft_lines(t)
    t = _drop_star_prefixed_rubric_lines(t)
    t = _strip_local_visible_thinking_preamble(t)
    t = _drop_star_prefixed_rubric_lines(t)
    t = _strip_trailing_meta_followup_section(t)
    t = _collapse_blank_lines(t)
    return t


NEXT_STEPS_MARKER = "NEXT_STEPS_JSON:"


def split_next_steps_marker(text: str) -> Tuple[str, Optional[str]]:
    """
    Split narrative analysis from optional ``NEXT_STEPS_JSON:{...}`` suffix.

    If the model wraps JSON across lines, extract from first ``{`` to last ``}``.
    """
    if NEXT_STEPS_MARKER not in text:
        return text, None
    pre, post = text.rsplit(NEXT_STEPS_MARKER, 1)
    post = post.strip()
    if not post:
        return pre.rstrip(), None
    blob = post
    if "```" in post:
        post = re.sub(r"^```(?:json)?\s*", "", post, flags=re.IGNORECASE).strip()
        post = re.sub(r"\s*```\s*$", "", post).strip()
        blob = post
    if "{" in blob and "}" in blob:
        i = blob.find("{")
        j = blob.rfind("}")
        if i != -1 and j > i:
            blob = blob[i : j + 1]
    return pre.rstrip(), blob


def parse_recommended_next_steps(blob: Optional[str]) -> List[Dict[str, Any]]:
    """Parse ``recommended_next_steps`` from JSON (advisory only)."""
    if not blob:
        return []
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return []
    arr = data.get("recommended_next_steps") if isinstance(data, dict) else None
    if not isinstance(arr, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in arr[:8]:
        if not isinstance(item, dict):
            continue
        row = {
            "tool": str(item.get("tool", "")).strip()[:120],
            "objective": str(item.get("objective", "")).strip()[:500],
            "prerequisite": str(item.get("prerequisite", "")).strip()[:500],
            "example_cli": str(item.get("example_cli", "")).strip()[:800],
            "risk_notes": str(item.get("risk_notes", "")).strip()[:500],
        }
        if row["tool"]:
            out.append(row)
    return out


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
    if first_id:
        probe_url = f"{base}/chat/completions"
        probe = requests.post(
            probe_url,
            headers={"Content-Type": "application/json"},
            json={
                "model": first_id,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 8,
                "temperature": 0,
                "stream": False,
            },
            timeout=min(timeout, 30.0),
        )
        if probe.status_code >= 400:
            raise RuntimeError(
                f"Chat probe failed ({probe.status_code}) at {probe_url!r}: "
                f"{(probe.text or '')[:2000]}"
            )
    elif not models:
        raise RuntimeError(
            "Local LLM /models returned no models. Load a model in LM Studio before running analysis."
        )
    return status, first_id


def _slim_subdomain_for_llm(entry: Dict[str, Any]) -> Dict[str, Any]:
    ips = entry.get("ip_addresses") or []
    if isinstance(ips, list):
        ips = ips[:4]
    server = entry.get("server")
    if isinstance(server, str) and len(server) > 120:
        server = server[:117] + "..."
    return {
        "subdomain": entry.get("subdomain"),
        "ip_addresses": ips,
        "status_code": entry.get("status_code"),
        "server": server,
    }


def _slim_tech_for_llm(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Drop bulky HTTP header maps; keep URL, tech tags, and a few notable headers."""
    interesting = entry.get("interesting_headers") or []
    if isinstance(interesting, list):
        interesting = interesting[:10]
    else:
        interesting = []
    return {
        "url": entry.get("url"),
        "technologies": entry.get("technologies") or [],
        "interesting_headers": interesting,
    }


def _slim_dns_for_llm(block: Dict[str, Any]) -> Dict[str, Any]:
    rows = block.get("nslookups") or []
    slim: List[Dict[str, Any]] = []
    for r in rows[:16]:
        if not isinstance(r, dict):
            continue
        slim.append(
            {
                "target": r.get("target"),
                "status": r.get("status"),
                "parsed": r.get("parsed"),
            }
        )
    return {"nslookups": slim}


def _slim_web_discovery_for_llm(block: Dict[str, Any]) -> Dict[str, Any]:
    scans = block.get("directory_scans") or []
    slim: List[Dict[str, Any]] = []
    for s in scans[:8]:
        if not isinstance(s, dict):
            continue
        slim.append(
            {
                "base_url": s.get("base_url"),
                "tool": s.get("tool"),
                "status": s.get("status"),
                "interesting": (s.get("findings_interesting") or [])[:20],
            }
        )
    return {"directory_scans": slim}


def shrink_recon_payload_for_llm(
    recon_data: Dict[str, Any],
    *,
    max_chars: int = 24000,
    max_subdomains: int = 50,
    max_ports: int = 120,
    max_tech: int = 25,
) -> str:
    """Reduce recon JSON size for small local models / LM Studio context limits."""
    raw_subs = recon_data.get("subdomains") or []
    slim_subs = [_slim_subdomain_for_llm(s) for s in raw_subs[:max_subdomains] if isinstance(s, dict)]
    raw_tech = recon_data.get("technologies") or []
    slim_tech = [_slim_tech_for_llm(t) for t in raw_tech[:max_tech] if isinstance(t, dict)]
    raw_ports = recon_data.get("ports") or []
    slim_ports: List[Dict[str, Any]] = []
    for p in raw_ports[:max_ports]:
        if not isinstance(p, dict):
            continue
        ver = p.get("version")
        if isinstance(ver, str) and len(ver) > 240:
            ver = ver[:237] + "..."
        slim_ports.append(
            {
                "host": p.get("host"),
                "port": p.get("port"),
                "service": p.get("service"),
                "version": ver,
            }
        )
    dns_block = recon_data.get("dns_intelligence") or {}
    web_block = recon_data.get("web_content_discovery") or {}
    nmap_meta = recon_data.get("nmap_scan") or {}
    compact: Dict[str, Any] = {
        "target": recon_data.get("target"),
        "timestamp": recon_data.get("timestamp"),
        "executive_snapshot": recon_data.get("executive_snapshot"),
        "summary": recon_data.get("summary", {}),
        "nmap_scan_mode": nmap_meta.get("mode"),
        "subdomains": slim_subs,
        "ports": slim_ports,
        "technologies": slim_tech,
        "dns_intelligence": _slim_dns_for_llm(dns_block) if isinstance(dns_block, dict) else {},
        "web_content_discovery": _slim_web_discovery_for_llm(web_block) if isinstance(web_block, dict) else {},
    }
    text = json.dumps(compact, separators=(",", ":"), ensure_ascii=False)
    if len(text) <= max_chars:
        return text
    note = "...[truncated]..."
    return text[: max_chars - len(note)] + note


# Global system instructions for all analysis providers (reporting guardrails).
SYSTEM_PROMPT = (
    "You are an authorized penetration-test reporting assistant for a cybersecurity firm. "
    "Your job is to analyze provided tool output from Kali Linux security testing tools "
    "such as nmap, nikto, sslscan, enum4linux, smbclient, gobuster, whatweb, wpscan, and similar tools. "
    "You must produce concise, evidence-based vulnerability triage and remediation guidance. "
    "Do not provide exploit instructions, payloads, weaponized commands, persistence steps, evasion guidance, "
    "or instructions for unauthorized access. "
    "Never reveal chain-of-thought, hidden reasoning, planning, drafts, or self-correction. "
    "Never use the label 'Thinking Process' or present numbered internal planning as the answer. "
    "Use only the provided tool output and known security knowledge. "
    "Do not invent CVEs. If a CVE is only plausible, label it as 'candidate' and explain what evidence supports it. "
    "If the evidence is insufficient to assign a CVE, say so clearly. "
    "Prioritize client-facing clarity, business risk, and actionable remediation."
)

# Local LM user prompt: strict client-report layout (paired with SYSTEM_PROMPT).
LOCAL_ANALYSIS_PROMPT = """
You are analyzing authorized pentest tool output.
INPUT:
The user will provide raw or summarized output from nmap and/or other Kali Linux testing tools.
STRICT OUTPUT RULES:
- Your entire reply must begin exactly with:
1) Executive summary
- Do not write anything before that line.
- Do not include chain-of-thought, thinking process, drafts, assumptions, or numbered plans.
- Do not emit star-prefixed meta lines (for example lines starting with "* Constraint:", "* Content:", "* Draft:") that restate the instructions; write the finished report only.
- Do not recommend additional scanning unless required to validate a specific uncertain finding.
- Do not provide exploit steps, payloads, shell commands, brute-force instructions, or weaponized guidance.
- Be concise and specific.
- Prefer confirmed findings over speculation.
- Use "candidate CVE" only when the product/version evidence supports it.
- If no reliable CVE mapping exists, say "No reliable CVE identified from the provided evidence."
- Do not overstate risk when version, exposure, or configuration evidence is missing.
OUTPUT FORMAT:
1) Executive summary
Write 2 sentences maximum.
Summarize the exposed services, the highest-risk issues, and the overall remediation priority.
2) Top risks
Provide up to 5 bullets.
Each bullet must use this format:
- Severity: <Critical|High|Medium|Low|Info> | Asset: <IP/host/service/port> | Finding: <short finding> | Evidence: <tool evidence> | Why it matters: <business/security impact>
3) Likely vulnerabilities / candidate CVEs
Provide up to 7 bullets.
Each bullet must use this format:
- <Confirmed|Candidate|Unclear> | Asset: <IP/host/service/port> | Technology: <product/version if known> | CVE: <CVE-ID or "None identified"> | Confidence: <High|Medium|Low> | Basis: <specific evidence from the tool output> | Remediation: <patch/configuration action>
Rules for this section:
- Mark a CVE as Confirmed only when the provided output identifies the vulnerable product/version or the tool explicitly reports the CVE.
- Mark as Candidate when the service/version is consistent with known vulnerable software but the exact build/configuration is not proven.
- Mark as Unclear when the output suggests risk but does not support a reliable CVE match.
4) Plausible attack paths
Provide 1-2 attack paths.
Each path must have exactly 3 bullets:
- Entry point: <externally reachable service or weakness>
- Risk chain: <high-level non-operational description of how weaknesses could combine>
- Potential impact: <business/security impact>
Do not include exploit commands, payloads, step-by-step compromise instructions, or post-exploitation guidance.
5) Top remediations
Provide up to 7 bullets.
Each bullet must use this format:
- Priority: <P1|P2|P3> | Asset: <IP/host/service/port> | Action: <specific remediation> | Owner: <IT/SecOps/App Team/Network Team> | Validation: <how to confirm fixed safely>
6) Analyst caveats
Provide up to 3 bullets.
Mention uncertainty caused by missing version data, unauthenticated scan limits, filtered ports, or incomplete tool output.
- Do not echo instruction rubric (no "Must be 2 sentences", "Format:", "Constraint:", or "Refining" meta-lines).
- Do not describe your drafting process; output only the finished numbered sections.
7) Recommended follow-up tooling (advisory only — not executed by Blackbox Recon)
After section 6, add ONE line by itself (no markdown fences) in exactly this pattern:
NEXT_STEPS_JSON:{"recommended_next_steps":[{"tool":"ffuf","objective":"short text","prerequisite":"open port / scope note","example_cli":"ffuf -u http://HOST/FUZZ -w WORDLIST -mc 200,301 -json","risk_notes":"ROE / rate-limit reminder"}]}
Rules for that JSON line:
- Single line after the colon; valid JSON object; max 5 objects in recommended_next_steps.
- Use placeholders HOST, TARGET_IP, WORDLIST in example_cli (no real secrets).
- Suggest only tools appropriate for authorized testing (e.g. ffuf, sslscan, enum4linux-ng, nmap scripts).
- Do not suggest password spraying, credential stuffing, exploit chains, or destructive actions unless the engagement explicitly allows them (assume they do not).
""".strip()


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
    """Result from AI analysis layered on recon output.

    ``attack_paths`` and ``prioritized_findings`` are populated from the engine's
    deterministic, evidence-backed structures when present; the LLM supplies narrative
    enrichment only (``executive_summary``, ``technical_analysis``, ``recommended_next_steps``).
    """

    attack_paths: List[Dict[str, Any]]
    prioritized_findings: List[Dict[str, Any]]
    correlations: List[Dict[str, Any]]
    executive_summary: str
    technical_analysis: str
    confidence_score: float
    recommended_next_steps: List[Dict[str, Any]] = field(default_factory=list)


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
                    {"role": "system", "content": SYSTEM_PROMPT},
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
                system=SYSTEM_PROMPT,
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
        self.url = url.rstrip("/")
        self.model = model
        self.headers = {"Content-Type": "application/json"}
        self.last_recommended_next_steps: List[Dict[str, Any]] = []
    
    def analyze(self, recon_data: Dict[str, Any], prompt_template: str) -> str:
        """Analyze with local LLM."""
        if not self.model:
            return (
                "Error calling local LLM: missing model id. "
                "Pass --ai-model with the exact id from LM Studio, or ensure /v1/models returns a model."
            )
        try:
            self.last_recommended_next_steps = []
            payload_json = shrink_recon_payload_for_llm(
                recon_data,
                max_chars=3400,
                max_subdomains=10,
                max_ports=30,
                max_tech=6,
            )
            user_content = (
                f"{prompt_template.strip()}\n\n"
                "DATA: The following JSON is authorized Blackbox Recon output (subdomains, open ports with "
                "service/version when detected, technologies). Treat it as summarized tool output under the INPUT "
                "rules above.\n\n"
                f"JSON:\n{payload_json}"
            )
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT,
                    },
                    {"role": "user", "content": user_content},
                ],
                "temperature": 0.15,
                "max_tokens": 8192,
                "stream": False,
                "chat_template_kwargs": {"enable_thinking": False},
                "extra_body": {"chat_template_kwargs": {"enable_thinking": False}},
            }
            
            response = requests.post(
                f"{self.url}/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            body = response.json()
            ch0 = (body.get("choices") or [{}])[0]
            msg = ch0.get("message") if isinstance(ch0.get("message"), dict) else {}
            primary = _coerce_openai_message_content(msg.get("content")).strip()
            text = primary if primary else assistant_text_from_openai_chat_response(body)
            if not text:
                fr = ch0.get("finish_reason")
                return (
                    "Error: local LLM returned an empty assistant message. "
                    "Thinking models often use the whole token budget for internal reasoning. "
                    f"finish_reason={fr!r}. Try: disable thinking in LM Studio, use a non-thinking "
                    "chat variant, increase Context Length / max tokens, or pick another model. "
                    f"Response (truncated): {json.dumps(body, ensure_ascii=False)[:1800]}"
                )
            self.last_recommended_next_steps = []
            body, blob = split_next_steps_marker(text)
            if blob:
                self.last_recommended_next_steps = parse_recommended_next_steps(blob)
            return _finalize_local_assistant_markdown(body)
        except HTTPError as exc:
            body = ""
            if exc.response is not None:
                body = (exc.response.text or "")[:4000]
            return f"Error calling local LLM: {exc}\nResponse body (truncated):\n{body}"
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
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt_template + "\n\n" + shrink_recon_payload_for_llm(
                        recon_data,
                        max_chars=12000,
                        max_subdomains=30,
                        max_ports=80,
                        max_tech=15,
                    )},
                ],
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_predict": 2048,
                },
            }
            
            response = requests.post(
                f"{self.url}/api/chat",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            return response.json()["message"]["content"]
        except HTTPError as exc:
            body = ""
            if exc.response is not None:
                body = (exc.response.text or "")[:4000]
            return f"Error calling Ollama: {exc}\nResponse body (truncated):\n{body}"
        except Exception as e:
            return f"Error calling Ollama: {str(e)}"


class AIAnalyzer:
    """Main AI analyzer class."""
    
    ANALYSIS_PROMPT = """The following JSON is Blackbox Recon output (subdomains, ports, technologies) and should be treated like consolidated reconnaissance / tool output for triage.

Analyze it and provide:

1. EXECUTIVE SUMMARY: A brief (2-3 sentence) overview of the attack surface and critical findings

2. PRIORITIZED FINDINGS: List the top 5-10 findings ranked by risk (HIGH/MEDIUM/LOW). For each:
   - Finding name
   - Risk level
   - Location (URL/IP)
   - Brief explanation
   - Quick remediation tip

3. ATTACK PATHS: Describe 2-3 realistic risk scenarios (how exposure could combine) at a level suitable for a client report—entry themes, pivot classes, and impact in plain language. Do not provide step-by-step exploitation, payloads, or weaponized commands.

4. TECHNOLOGY RISKS: Analyze the technology stack for:
   - Outdated software with known CVEs (mark plausible CVEs as 'candidate' with evidence; do not invent CVE IDs)
   - Dangerous configurations
   - Default credentials possibilities

5. CORRELATIONS: Identify relationships between findings (e.g., "Jenkins on dev + weak SMB = internal access")

6. ADVISORY NEXT STEPS (optional tooling — not run by this app): After your narrative, add exactly one line:
NEXT_STEPS_JSON:{"recommended_next_steps":[{"tool":"name","objective":"why","prerequisite":"scope/port","example_cli":"command with HOST TARGET_IP WORDLIST placeholders","risk_notes":"ROE note"}]}
Max 5 entries; valid single-line JSON; no credential attacks unless explicitly allowed by engagement.

Be specific, actionable, and focus on what a penetration tester should prioritize for remediation. Avoid generic advice."""

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
            if not model:
                raise ValueError(
                    "Local LLM requires a model id. Pass --ai-model with the id shown in LM Studio, "
                    "or ensure the server returns models from GET /v1/models."
                )
            self.provider = LocalProvider(url or "http://localhost:1234/v1", model)
        
        elif provider == "ollama":
            self.provider = OllamaProvider(url or "http://localhost:11434", model or "llama3.1")
        
        else:
            raise ValueError(f"Unknown provider: {provider}. Choose: openai, claude, local, ollama")
    
    def analyze_recon_data(self, recon_data: Dict[str, Any]) -> AnalysisResult:
        """Analyze reconnaissance data and return structured results."""
        rprint(
            f"[bold cyan]{escape('[AI]')}[/bold cyan] Analyzing attack surface with "
            f"[yellow]{escape(self.provider_name)}[/yellow]…"
        )
        prompt = self.ANALYSIS_PROMPT if self.provider_name != "local" else LOCAL_ANALYSIS_PROMPT
        raw_analysis = self.provider.analyze(recon_data, prompt)

        steps: List[Dict[str, Any]] = []
        narrative = raw_analysis
        if self.provider_name == "local" and isinstance(self.provider, LocalProvider):
            steps = list(self.provider.last_recommended_next_steps)
        elif NEXT_STEPS_MARKER in (raw_analysis or ""):
            narrative, blob = split_next_steps_marker(raw_analysis)
            steps = parse_recommended_next_steps(blob)

        exec_src = narrative or ""
        executive = exec_src[:500] if len(exec_src) > 500 else exec_src
        atk = list(recon_data.get("deterministic_attack_paths") or [])
        pri = list(recon_data.get("deterministic_findings") or [])
        return AnalysisResult(
            attack_paths=atk,
            prioritized_findings=pri,
            correlations=[],
            executive_summary=executive,
            technical_analysis=narrative,
            confidence_score=0.85,
            recommended_next_steps=steps,
        )
    
    def generate_attack_path(self, entry_point: str, target_type: str) -> Dict[str, Any]:
        """Generate defensive risk narrative for an entry point (no exploitation instructions)."""
        prompt = f"""Entry point context: {entry_point} (Type: {target_type})

Produce a concise, client-safe defensive summary with four numbered items:
1) Exposure summary — what this entry point represents in business terms
2) Likely risk classes — categories of abuse (no step-by-step attacks, payloads, or weaponized commands)
3) Impact themes — what could go wrong at a high level if risk materializes
4) Remediation priorities — concrete defensive actions

Use only reasonable inference from the entry point description; do not invent CVEs."""
        
        result = self.provider.analyze({}, prompt)
        return {
            "entry_point": entry_point,
            "target_type": target_type,
            "path": result
        }
