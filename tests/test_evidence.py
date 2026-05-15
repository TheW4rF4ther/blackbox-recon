"""Evidence package and deterministic findings."""

from blackbox_recon.evidence import (
    _http_like_port_row,
    build_deterministic_findings,
    build_evidence_package,
    build_evidence_records,
)


def test_http_like_detects_standard_web_ports():
    assert _http_like_port_row({"port": 80, "service": "http"}) is True
    assert _http_like_port_row({"port": 443, "service": "http"}) is True
    assert _http_like_port_row({"port": 22, "service": "ssh"}) is False


def test_evidence_and_summary_http_count():
    results = {
        "target": "203.0.113.5",
        "subdomains": [],
        "dns_intelligence": {"nslookups": []},
        "ports": [
            {
                "host": "203.0.113.5",
                "port": 22,
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH",
            },
            {"host": "203.0.113.5", "port": 80, "state": "open", "service": "http", "version": None},
            {"host": "203.0.113.5", "port": 443, "state": "open", "service": "http", "version": None},
        ],
        "technologies": [],
        "web_content_discovery": {
            "directory_scans": [
                {
                    "base_url": "http://203.0.113.5/",
                    "tool": "gobuster",
                    "command": "gobuster …",
                    "findings_interesting": [],
                    "status": "ok",
                }
            ],
            "urls_targeted": ["http://203.0.113.5/"],
        },
        "summary": {
            "total_open_ports": 3,
            "http_services_detected": 2,
            "http_urls_targeted": 1,
            "subdomain_http_probes_with_status": 0,
            "technology_profiles_stored": 0,
            "total_subdomains": 0,
            "total_tech_detected": 0,
            "web_services": 0,
            "nslookup_runs": 0,
            "web_urls_targeted": 1,
            "directory_scan_runs": 1,
            "directory_interesting_hits": 0,
            "open_tcp_ports": 3,
        },
        "recon_started_utc": "2026-01-01T00:00:00Z",
        "recon_completed_utc": "2026-01-01T00:01:00Z",
        "engagement": {},
    }
    ev = build_evidence_records(results)
    assert any(":22/tcp" in e.asset for e in ev if e.phase_id == "M3")
    findings = build_deterministic_findings(ev, results)
    codes = {f.finding_code for f in findings}
    assert "BBR-EXPOSURE-001" in codes
    assert "BBR-EXPOSURE-002" in codes
    pkg = build_evidence_package(results, ["portscan", "subdomain"], lab_mode=True)
    assert pkg["assessment"]["mode"] == "lab"
    assert len(pkg["evidence"]) >= 3
