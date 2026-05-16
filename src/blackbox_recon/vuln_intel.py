"""Vulnerability intelligence lookup layer.

Collects version/technology/CMS signals from the scan and looks for candidate
CVE / Exploit-DB references. This module does not execute exploit code and does
not claim exploitability; results are leads for manual validation.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote

import requests

from .artifacts import write_tool_artifact


_VERSIONISH = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*(?:\s+[A-Za-z][A-Za-z0-9_.+-]*){0,2})\s+([0-9]+(?:\.[0-9A-Za-z_-]+){1,4})")


def _short(value: Any, n: int = 220) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _target(results: Dict[str, Any]) -> str:
    return str(results.get("target") or "target")


def _dedupe_leads(leads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for lead in leads:
        key = (lead.get("source"), lead.get("id") or lead.get("title"), lead.get("asset"), lead.get("query"))
        if key in seen:
            continue
        seen.add(key)
        out.append(lead)
    return out


def _add_signal(signals: List[Dict[str, Any]], *, asset: str, service: str, product: str, version: Optional[str], evidence: str, confidence: str = "medium") -> None:
    product = _short(product, 80)
    version = _short(version, 40) if version else None
    if not product:
        return
    key = (asset, service, product.lower(), (version or "").lower())
    for s in signals:
        if (s.get("asset"), s.get("service"), str(s.get("product", "")).lower(), str(s.get("version") or "").lower()) == key:
            return
    signals.append({"asset": asset, "service": service, "product": product, "version": version, "evidence": _short(evidence, 220), "confidence": confidence})


def collect_vuln_signals(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract product/version/application signals worth CVE/exploit research."""
    signals: List[Dict[str, Any]] = []
    for row in results.get("ports") or []:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or results.get("target") or "target")
        port = int(row.get("port") or 0)
        svc = str(row.get("service") or "unknown")
        asset = f"{host}:{port}"
        banner = str(row.get("version") or row.get("banner") or "")
        if banner:
            # Prefer full recognizable server strings before generic regex.
            if "openssh" in banner.lower():
                m = re.search(r"OpenSSH\s+([^\s]+)", banner, re.IGNORECASE)
                _add_signal(signals, asset=asset, service="SSH", product="OpenSSH", version=m.group(1) if m else None, evidence=banner, confidence="high")
            if "apache httpd" in banner.lower() or "apache/" in banner.lower():
                m = re.search(r"Apache(?: httpd)?[/\s]+([^\s()]+)", banner, re.IGNORECASE)
                _add_signal(signals, asset=asset, service="HTTP", product="Apache httpd", version=m.group(1) if m else None, evidence=banner, confidence="high")
            if "nginx" in banner.lower():
                m = re.search(r"nginx[/\s]+([^\s()]+)", banner, re.IGNORECASE)
                _add_signal(signals, asset=asset, service="HTTP", product="nginx", version=m.group(1) if m else None, evidence=banner, confidence="medium")
            for m in _VERSIONISH.finditer(banner):
                product = m.group(1).strip()
                version = m.group(2).strip()
                if product.lower() not in ("ubuntu linux", "protocol"):
                    _add_signal(signals, asset=asset, service=svc.upper(), product=product, version=version, evidence=banner, confidence="low")
    for row in (results.get("cms_enumeration") or {}).get("results") or []:
        if not isinstance(row, dict):
            continue
        asset = str(row.get("url") or "web")
        for finding in row.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            ftype = finding.get("type")
            if ftype == "wordpress_version" and finding.get("version"):
                _add_signal(signals, asset=asset, service="HTTP", product="WordPress", version=str(finding.get("version")), evidence="CMS enumeration identified WordPress version", confidence="high")
            if ftype == "wordpress_theme" and finding.get("theme"):
                _add_signal(signals, asset=asset, service="HTTP", product=f"WordPress theme {finding.get('theme')}", version=None, evidence="WPScan identified WordPress theme", confidence="medium")
            if ftype == "cms_detected" and finding.get("cms"):
                _add_signal(signals, asset=asset, service="HTTP", product=str(finding.get("cms")), version=None, evidence="CMS fingerprint signal", confidence="medium")
    return signals[:40]


def _searchsploit_available() -> bool:
    return bool(shutil.which("searchsploit"))


def _run_searchsploit(query: str, *, timeout_sec: int, target: str) -> Dict[str, Any]:
    exe = shutil.which("searchsploit")
    if not exe:
        return {"source": "exploitdb", "query": query, "status": "skipped", "reason": "searchsploit not found"}
    cmd = [exe, "--json", query]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=max(10, int(timeout_sec)))
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        artifact = write_tool_artifact(target=target, host=target, port=0, service="vuln_intel", module="searchsploit", command=" ".join(cmd), stdout=stdout, stderr=stderr)
        rows: List[Dict[str, Any]] = []
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for item in (data.get("RESULTS_EXPLOIT") or [])[:12]:
                if isinstance(item, dict):
                    rows.append({"source": "exploitdb", "title": _short(item.get("Title"), 180), "edb_id": item.get("EDB-ID"), "type": item.get("Type"), "platform": item.get("Platform"), "path": item.get("Path")})
        except Exception:
            rows = []
        return {"source": "exploitdb", "query": query, "status": "ok", "returncode": proc.returncode, "matches": rows, "artifact_path": artifact}
    except subprocess.TimeoutExpired:
        return {"source": "exploitdb", "query": query, "status": "timeout"}
    except Exception as exc:
        return {"source": "exploitdb", "query": query, "status": "tool_error", "error": str(exc)[:300]}


def _query_nvd(keyword: str, *, timeout_sec: int, max_results: int = 6) -> Dict[str, Any]:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(keyword)}&cvssV3Severity=HIGH"
    try:
        resp = requests.get(url, timeout=max(5, int(timeout_sec)), headers={"User-Agent": "Blackbox-Recon/1.0"})
        if resp.status_code == 429:
            return {"source": "nvd", "query": keyword, "status": "rate_limited"}
        resp.raise_for_status()
        data = resp.json()
        matches: List[Dict[str, Any]] = []
        for vuln in (data.get("vulnerabilities") or [])[:max_results]:
            cve = (vuln or {}).get("cve") or {}
            descs = cve.get("descriptions") or []
            desc = ""
            for d in descs:
                if d.get("lang") == "en":
                    desc = d.get("value") or ""
                    break
            metrics = cve.get("metrics") or {}
            cvss = None
            sev = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key) or []
                if arr:
                    cvss = ((arr[0] or {}).get("cvssData") or {}).get("baseScore")
                    sev = (arr[0] or {}).get("baseSeverity")
                    break
            matches.append({"source": "nvd", "cve_id": cve.get("id"), "published": cve.get("published"), "last_modified": cve.get("lastModified"), "severity": sev, "cvss": cvss, "description": _short(desc, 240)})
        return {"source": "nvd", "query": keyword, "status": "ok", "matches": matches}
    except Exception as exc:
        return {"source": "nvd", "query": keyword, "status": "error", "error": str(exc)[:300]}


def run_vulnerability_intel(results: Dict[str, Any], *, searchsploit_timeout_sec: int = 30, nvd_timeout_sec: int = 12, max_signals: int = 12) -> Dict[str, Any]:
    target = _target(results)
    signals = collect_vuln_signals(results)[:max(1, int(max_signals))]
    lookups: List[Dict[str, Any]] = []
    leads: List[Dict[str, Any]] = []
    for sig in signals:
        product = str(sig.get("product") or "").strip()
        version = str(sig.get("version") or "").strip()
        if not product:
            continue
        queries = []
        if version:
            queries.append(f"{product} {version}")
        queries.append(product)
        # Limit broad duplicate product-only lookups when version exists.
        for q in queries[:2 if not version else 1]:
            ss = _run_searchsploit(q, timeout_sec=searchsploit_timeout_sec, target=target)
            lookups.append(ss)
            for m in ss.get("matches") or []:
                leads.append({"source": "exploitdb", "asset": sig.get("asset"), "service": sig.get("service"), "query": q, "title": m.get("title"), "id": m.get("edb_id"), "type": m.get("type"), "platform": m.get("platform"), "path": m.get("path"), "confidence": "candidate", "note": "Exploit-DB/searchsploit match; validate applicability before use."})
            nvd = _query_nvd(q, timeout_sec=nvd_timeout_sec, max_results=6)
            lookups.append(nvd)
            for m in nvd.get("matches") or []:
                leads.append({"source": "nvd", "asset": sig.get("asset"), "service": sig.get("service"), "query": q, "title": m.get("cve_id"), "id": m.get("cve_id"), "severity": m.get("severity"), "cvss": m.get("cvss"), "published": m.get("published"), "description": m.get("description"), "confidence": "candidate", "note": "NVD keyword match; validate affected version/configuration."})
    return {"signals": signals, "lookups": lookups, "candidate_leads": _dedupe_leads(leads)[:60], "searchsploit_available": _searchsploit_available(), "nvd_enabled": True, "policy": "candidate intelligence only; no exploit execution or exploitability claim"}
