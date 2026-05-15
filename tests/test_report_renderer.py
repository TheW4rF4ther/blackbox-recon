"""Deterministic technical Markdown renderer."""

from blackbox_recon.report_renderer import render_technical_assessment_markdown


def test_renderer_produces_sections():
    results = {
        "target": "198.51.100.10",
        "timestamp": "t",
        "recon_started_utc": "2026-01-01T00:00:00Z",
        "recon_completed_utc": "2026-01-01T00:05:00Z",
        "schema_version": "2.2",
        "engagement": {"modules_requested": ["portscan"], "record": None},
        "subdomains": [],
        "dns_intelligence": {"nslookups": []},
        "ports": [
            {
                "host": "198.51.100.10",
                "port": 22,
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH",
            },
        ],
        "technologies": [],
        "web_content_discovery": {"directory_scans": [], "urls_targeted": []},
        "summary": {
            "total_open_ports": 1,
            "open_tcp_ports": 1,
            "http_services_detected": 0,
            "http_urls_targeted": 0,
            "subdomain_http_probes_with_status": 0,
            "technology_profiles_stored": 0,
            "directory_interesting_hits": 0,
            "nslookup_runs": 0,
            "directory_scan_runs": 0,
            "total_subdomains": 0,
            "total_tech_detected": 0,
            "web_services": 0,
            "web_urls_targeted": 0,
        },
        "executive_snapshot": {},
    }
    md = render_technical_assessment_markdown(results)
    assert "## Technical assessment" in md
    assert "Scope and methodology" in md
    assert "Confirmed attack surface" in md
    assert "CVE assessment" in md
    assert "198.51.100.10" in md
