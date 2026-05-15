"""JSON-only AI enrichment helpers (evidence package path)."""

import json

from blackbox_recon.ai_json_enrichment import (
    ai_output_fails_quality_gate,
    format_enrichment_markdown,
    next_steps_to_legacy_list,
    parse_ai_enrichment_json,
)


def test_parse_valid_json_enrichment():
    payload = {
        "executive_summary": "Two sentences about exposure.",
        "risk_narrative": [
            {
                "finding_id": "DET-FIND-001",
                "client_ready_text": "SSH is reachable.",
                "confidence_note": "Direct port evidence.",
            }
        ],
        "cve_assessment": {
            "summary": "No CVEs confirmed.",
            "confirmed_cves": [],
            "candidate_cves": [],
            "reasoning_limits": ["Unauthenticated scan only."],
        },
        "recommended_next_steps": [
            {
                "tool": "sslscan",
                "objective": "TLS review",
                "prerequisite": "HTTPS in scope",
                "example_cli": "sslscan HOST",
                "risk_notes": "Non-invasive",
            }
        ],
        "quality_flags": [{"type": "coverage_gap", "message": "No TLS probe run."}],
    }
    raw = "Here is JSON:\n" + json.dumps(payload)
    data, err = parse_ai_enrichment_json(raw)
    assert err is None
    assert data is not None
    assert data["executive_summary"].startswith("Two sentences")


def test_quality_gate_rejects_planning_phrase():
    bad = '{"executive_summary":"Let\'s refine the risks."}'
    assert ai_output_fails_quality_gate(bad) is True


def test_quality_gate_accepts_clean_json_string():
    good = '{"executive_summary":"Exposure includes SSH and HTTPS services."}'
    assert ai_output_fails_quality_gate(good) is False


def test_next_steps_mapping():
    rows = next_steps_to_legacy_list(
        [
            {"tool": " nmap ", "objective": "x", "example_cli": "c", "risk_notes": "r"},
            {"tool": "", "objective": "skip"},
        ]
    )
    assert len(rows) == 1
    assert rows[0]["tool"] == "nmap"


def test_format_enrichment_markdown_includes_sections():
    md = format_enrichment_markdown(
        {
            "executive_summary": "Hello.",
            "risk_narrative": [
                {"finding_id": "DET-FIND-001", "client_ready_text": "Body.", "confidence_note": "High."}
            ],
            "cve_assessment": {"summary": "None.", "reasoning_limits": ["Limit a"]},
            "quality_flags": [{"type": "t", "message": "m"}],
        }
    )
    assert "Executive summary" in md
    assert "DET-FIND-001" in md
    assert "CVE assessment" in md
