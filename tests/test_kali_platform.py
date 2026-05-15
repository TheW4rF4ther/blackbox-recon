"""Tests for Kali / Debian toolchain helpers."""

from unittest.mock import patch

from blackbox_recon.kali_platform import (
    build_toolchain_snapshot,
    missing_packages_for_config,
    read_os_release,
    tool_status,
    TOOLS_NMAP,
)
from blackbox_recon.methodology import build_methodology_block


def test_read_os_release_missing():
    with patch("blackbox_recon.kali_platform.Path.is_file", return_value=False):
        assert read_os_release() == {}


def test_missing_packages_respects_config():
    cfg = {
        "port_scan_mode": "tcp_connect",
        "run_nslookup": False,
        "directory_scan_enabled": False,
        "directory_tool": "auto",
    }
    miss_ids, pkgs = missing_packages_for_config(cfg)
    assert miss_ids == []
    assert pkgs == []


def test_build_methodology_block_shape():
    cfg = {
        "port_scan_mode": "tcp_connect",
        "run_nslookup": True,
        "directory_scan_enabled": True,
        "directory_tool": "auto",
    }
    snap = {
        "tools": {
            "nmap": {"present": False},
            "nslookup": {"present": True, "path": "/usr/bin/nslookup"},
            "gobuster": {"present": True, "path": "/usr/bin/gobuster"},
            "dirb": {"present": False},
        },
        "missing_tool_ids": [],
        "missing_apt_packages": [],
    }
    block = build_methodology_block(["subdomain", "portscan", "technology"], cfg, snap)
    assert block.get("framework")
    phases = block.get("phases") or []
    assert len(phases) >= 5
    ids = {p["phase_id"] for p in phases}
    assert "M1" in ids and "M3" in ids


def test_tool_status_when_absent():
    with patch("blackbox_recon.kali_platform.shutil.which", return_value=None):
        st = tool_status(TOOLS_NMAP)
        assert st["present"] is False
