"""CMS-aware web enumeration for discovered HTTP services.

Recon-focused: fingerprints common CMS/app signals, checks high-value known paths,
and optionally runs CMS-native tools without password attacks.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests

from .artifacts import write_tool_artifact

_WORDPRESS_PATHS = (
    "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-content/", "/wp-includes/",
    "/readme.html", "/license.txt", "/wp-cron.php", "/wp-links-opml.php",
)
_JOOMLA_PATHS = ("/administrator/", "/configuration.php", "/README.txt", "/joomla.xml")
_DRUPAL_PATHS = ("/user/login", "/CHANGELOG.txt", "/core/", "/sites/default/", "/misc/drupal.js")
_COMMON_PATHS = ("/robots.txt", "/sitemap.xml", "/hidden/", "/server-status", "/icons/README", "/admin/", "/login/")
_WP_VERSION_RE = re.compile(r"wordpress(?:\.org)?/\?v=([0-9][0-9A-Za-z_.-]*)", re.IGNORECASE)


def _target_from_url(url: str) -> str:
    return url.replace("http://", "").replace("https://", "").split("/", 1)[0].split(":", 1)[0]


def _status_interesting(status: Optional[int]) -> bool:
    return status in (200, 301, 302, 307, 308, 401, 403)


def _http_get(url: str, timeout: int) -> Dict[str, Any]:
    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True, headers={"User-Agent": "Blackbox-Recon/1.0"})
        return {"url": url, "status_code": resp.status_code, "final_url": resp.url, "content_type": resp.headers.get("Content-Type"), "server": resp.headers.get("Server"), "body_sample": resp.text[:5000], "error": None}
    except Exception as exc:
        return {"url": url, "status_code": None, "final_url": None, "content_type": None, "server": None, "body_sample": "", "error": str(exc)[:300]}


def _extract_wordpress_version(samples: Iterable[str]) -> Optional[str]:
    for sample in samples:
        m = _WP_VERSION_RE.search(sample or "")
        if m:
            return m.group(1)
    return None


def _detect_cms(samples: Iterable[str], known_paths: List[Dict[str, Any]]) -> List[str]:
    blob = "\n".join(samples).lower()
    cms: List[str] = []
    path_text = " ".join(str(p.get("path", "")).lower() for p in known_paths)
    if "wp-content" in blob or "wordpress" in blob or "wp-login" in path_text or "xmlrpc.php" in path_text:
        cms.append("wordpress")
    if "joomla" in blob or "/administrator/" in path_text:
        cms.append("joomla")
    if "drupal" in blob or "/sites/default" in path_text or "/user/login" in path_text:
        cms.append("drupal")
    return list(dict.fromkeys(cms))


def _run_wpscan(url: str, timeout_sec: int, target: str) -> Optional[Dict[str, Any]]:
    exe = shutil.which("wpscan")
    if not exe:
        return None
    cmd = [exe, "--url", url.rstrip("/"), "--enumerate", "u,t,p", "--plugins-detection", "passive", "--no-update", "--random-user-agent"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=max(60, int(timeout_sec)))
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        low = stdout.lower()
        findings: List[Dict[str, Any]] = []
        m = re.search(r"WordPress version\s+([^\s]+)\s+identified", stdout, re.IGNORECASE)
        if m:
            findings.append({"type": "wordpress_version", "version": m.group(1)})
        if "xml-rpc seems to be enabled" in low:
            findings.append({"type": "wordpress_xmlrpc_enabled"})
        if "wordpress readme found" in low:
            findings.append({"type": "wordpress_readme_found"})
        if "wp-cron seems to be enabled" in low or "external wp-cron seems to be enabled" in low:
            findings.append({"type": "wordpress_wp_cron_enabled"})
        theme_match = re.search(r"WordPress theme in use:\s*([^\n]+)", stdout, re.IGNORECASE)
        if theme_match:
            findings.append({"type": "wordpress_theme", "theme": theme_match.group(1).strip()})
        users: List[str] = []
        in_users = False
        for line in stdout.splitlines():
            s = line.strip()
            if "User(s) Identified" in s:
                in_users = True
                continue
            if in_users:
                if s.startswith("[+]"):
                    user = s.replace("[+]", "", 1).strip()
                    if user and not any(x in user.lower() for x in ("url:", "started:", "finished")):
                        users.append(user)
                elif s.startswith("[i]") or s.startswith("Scan Aborted"):
                    break
        if users:
            findings.append({"type": "wordpress_users_identified", "users": users[:20]})
        artifact = write_tool_artifact(target=target, host=target, port=80 if url.startswith("http://") else 443, service="http", module="wpscan_cms", command=" ".join(cmd), stdout=stdout, stderr=stderr)
        return {"tool": "wpscan", "command": " ".join(cmd), "status": "ok" if proc.returncode in (0, 1, 5) else "completed_nonzero", "findings": findings, "artifact_path": artifact, "stdout_excerpt": stdout[-8000:] if stdout else None, "stderr_excerpt": stderr[-3000:] if stderr else None}
    except subprocess.TimeoutExpired as exc:
        return {"tool": "wpscan", "command": " ".join(cmd), "status": "timeout", "findings": [], "error": f"timeout after {timeout_sec}s", "stdout_excerpt": (exc.stdout or "")[-4000:] if exc.stdout else None}
    except Exception as exc:
        return {"tool": "wpscan", "command": " ".join(cmd), "status": "tool_error", "findings": [], "error": str(exc)[:400]}


def run_cms_enumeration(urls: Iterable[str], *, timeout_sec: int = 12, wpscan_timeout_sec: int = 240, max_urls: int = 6) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    for url in list(urls)[: max(1, int(max_urls))]:
        base = url.rstrip("/") + "/"
        target = _target_from_url(base)
        homepage = _http_get(base, timeout_sec)
        samples = [homepage.get("body_sample") or ""]
        known_paths: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        for path in list(_WORDPRESS_PATHS) + list(_JOOMLA_PATHS) + list(_DRUPAL_PATHS) + list(_COMMON_PATHS):
            full = urljoin(base, path.lstrip("/"))
            row = _http_get(full, timeout_sec)
            status = row.get("status_code")
            if _status_interesting(status):
                entry = {"path": path, "url": full, "status_code": status, "final_url": row.get("final_url"), "content_type": row.get("content_type")}
                known_paths.append(entry)
                samples.append(row.get("body_sample") or "")
                if path.startswith("/wp-") or path in ("/readme.html", "/license.txt"):
                    findings.append({"type": "wordpress_known_path", **entry})
                if path == "/xmlrpc.php" and status == 200:
                    findings.append({"type": "wordpress_xmlrpc_enabled", **entry})
                if path == "/wp-login.php" and status in (200, 301, 302):
                    findings.append({"type": "wordpress_login_found", **entry})
                if path in ("/administrator/", "/user/login", "/admin/", "/login/", "/hidden/") and status in (200, 301, 302, 401, 403):
                    findings.append({"type": "interesting_path", **entry})
                if path == "/server-status" and status == 403:
                    findings.append({"type": "apache_server_status_forbidden", **entry})
        wp_version = _extract_wordpress_version(samples)
        if wp_version:
            findings.append({"type": "wordpress_version", "version": wp_version})
        cms = _detect_cms(samples, known_paths)
        for c in cms:
            findings.append({"type": "cms_detected", "cms": c})
        wpscan_result = _run_wpscan(base, wpscan_timeout_sec, target) if "wordpress" in cms else None
        if wpscan_result:
            findings.extend(wpscan_result.get("findings") or [])
        results.append({"url": base, "status": "ok", "homepage_status": homepage.get("status_code"), "cms": cms, "known_paths": known_paths[:80], "findings": findings[:100], "wpscan": wpscan_result})
    return {"results": results, "urls_considered": len(results), "cms_signals": sum(1 for r in results if r.get("findings"))}
