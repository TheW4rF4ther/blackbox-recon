"""Unit tests for parsers used in recon."""

from blackbox_recon.dir_scan import _parse_gobuster_lines, resolve_directory_wordlist
from blackbox_recon.service_detection import parse_nmap_xml_open_tcp_ports


def test_parse_nmap_xml_open_tcp_ports_minimal():
    xml = """<?xml version="1.0"?>
<nmaprun>
<host>
  <address addr="192.0.2.10" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="nginx" version="1.24.0"/>
    </port>
    <port protocol="tcp" portid="22">
      <state state="closed" reason="reset"/>
      <service name="ssh" product="OpenSSH" version="8.4"/>
    </port>
  </ports>
</host>
</nmaprun>"""
    rows = parse_nmap_xml_open_tcp_ports(xml)
    assert len(rows) == 1
    assert rows[0]["host"] == "192.0.2.10"
    assert rows[0]["port"] == 443
    assert rows[0]["service"] == "https"
    assert "nginx" in (rows[0].get("version") or "")


def test_resolve_directory_wordlist_falls_back_to_bundled():
    p = resolve_directory_wordlist("__nonexistent_path__/no.txt")
    assert p.is_file()
    assert "web_discovery_small" in p.name


def test_resolve_directory_wordlist_explicit(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    assert resolve_directory_wordlist(str(wl)) == wl
    lines = ["/admin (Status: 301)", "noise", "/backup (Status: 403)"]
    hits = _parse_gobuster_lines(lines)
    paths = {h["path"]: h["status_code"] for h in hits}
    assert paths["/admin"] == 301
    assert paths["/backup"] == 403
