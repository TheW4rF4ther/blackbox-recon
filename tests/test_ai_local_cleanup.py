"""Local LLM output cleanup (rubric stripping, Draft unwrap)."""

from blackbox_recon.ai_analyzer import (
    _drop_star_prefixed_rubric_lines,
    _finalize_local_assistant_markdown,
    _strip_trailing_meta_followup_section,
    _unwrap_star_draft_lines,
)


def test_drop_constraint_line_colon_space():
    raw = (
        "1) Executive summary\n"
        "*   Constraint: Max 2 sentences.\n"
        "The host exposes SSH and HTTP.\n"
    )
    out = _drop_star_prefixed_rubric_lines(raw)
    assert "Constraint" not in out
    assert "SSH" in out


def test_drop_content_line():
    raw = "        *   Content: Summarize things here.\n2) Top risks\n"
    out = _drop_star_prefixed_rubric_lines(raw)
    assert "Content:" not in out
    assert "2) Top risks" in out


def test_unwrap_draft_preserves_prose():
    raw = "*   Draft: The target runs nginx on port 443 with a valid certificate.\n"
    out = _unwrap_star_draft_lines(raw)
    assert "Draft:" not in out
    assert out.strip().startswith("The target runs")


def test_strip_trailing_fake_section7_without_json():
    body = (
        "6) Analyst caveats\n"
        "- Note about scans.\n\n"
        "      *   **7) Recommended follow-up tooling:**\n"
        "          *   One line JSON at the end.\n"
    )
    out = _strip_trailing_meta_followup_section(body)
    assert "7) Recommended" not in out
    assert "Analyst caveats" in out


def test_strip_trailing_preserves_body_when_next_steps_json_present():
    body = '6) Caveats\nOK\nNEXT_STEPS_JSON:{"recommended_next_steps":[]}\n'
    assert _strip_trailing_meta_followup_section(body) == body


def test_finalize_strips_qwen_style_rubric_block():
    messy = (
        "1) Executive summary\n"
        "*   Constraint: Max 2 sentences.\n"
        "        *   Content: Say something useful.\n"
        "*   Draft: Services on 22, 80, and 443 suggest a typical web host footprint.\n"
        "2) Top risks\n"
        "- Medium | 10.0.0.1:22 | SSH exposed | nmap | Brute-force surface.\n"
    )
    out = _finalize_local_assistant_markdown(messy)
    assert "Constraint" not in out
    assert "Content:" not in out
    assert "Draft:" not in out
    assert "Services on 22" in out
    assert "2) Top risks" in out
