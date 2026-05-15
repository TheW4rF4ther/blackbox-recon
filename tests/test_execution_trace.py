"""Execution trace structure."""

from blackbox_recon.execution_trace import PhaseTracer, summarize_execution_trace


def test_summarize_execution_trace():
    results: dict = {"recon_phase_trace": []}
    tr = PhaseTracer(results, echo=False)
    tr.start("M1", ["line"])
    tr.note_command("x", "cmd1")
    tr.finish("completed", "done")
    s = summarize_execution_trace(results["recon_phase_trace"])
    assert s["phases"][0]["phase_id"] == "M1"
    assert "x" in s["command_kinds"]
