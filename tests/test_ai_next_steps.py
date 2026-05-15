"""Tests for AI advisory NEXT_STEPS_JSON parsing."""

from blackbox_recon.ai_analyzer import (
    NEXT_STEPS_MARKER,
    parse_recommended_next_steps,
    split_next_steps_marker,
)


def test_split_next_steps_plain_json_suffix():
    body = "Here is the analysis.\n\nFindings look interesting."
    blob = '{"recommended_next_steps":[{"tool":"ffuf","objective":"fuzz","example_cli":"ffuf -u http://HOST"}]}'
    raw = f"{body}\n{NEXT_STEPS_MARKER}{blob}"
    pre, parsed = split_next_steps_marker(raw)
    assert pre == body
    assert parsed == blob


def test_split_next_steps_fenced_json():
    body = "Summary only."
    inner = '{"recommended_next_steps":[{"tool":"nmap","objective":"scripts","example_cli":"nmap -sC HOST"}]}'
    raw = f"{body}\n{NEXT_STEPS_MARKER}```json\n{inner}\n```"
    pre, parsed = split_next_steps_marker(raw)
    assert pre == body
    assert parsed == inner


def test_parse_recommended_next_steps_filters_and_truncates_keys():
    blob = (
        '{"recommended_next_steps":['
        '{"tool":"  ffuf  ","objective":"x","prerequisite":"","example_cli":"c","risk_notes":"r"},'
        '{"not":"a dict"},'
        '{"tool":"","objective":"skip"}'
        "]}"
    )
    rows = parse_recommended_next_steps(blob)
    assert len(rows) == 1
    assert rows[0]["tool"] == "ffuf"
    assert rows[0]["objective"] == "x"


def test_parse_invalid_json_returns_empty():
    assert parse_recommended_next_steps("not json") == []
    assert parse_recommended_next_steps(None) == []
