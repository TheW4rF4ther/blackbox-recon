"""CLI analysis panel text builder."""

from blackbox_recon.cli import build_analysis_panel_text


def test_build_analysis_panel_text_styles_section_numbers():
    body = "1) Executive summary\nHello.\n2) Top risks\n- Medium | x | y | z | w\n"
    t = build_analysis_panel_text(body)
    plain = t.plain
    assert "1) Executive summary" in plain
    assert "Medium" in plain
    assert plain.count("\n") >= 3
