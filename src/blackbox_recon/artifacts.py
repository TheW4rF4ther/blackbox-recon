"""Artifact helpers for Blackbox Recon tool outputs.

Terminal output should stay concise, but professional recon needs durable raw
artifacts per service. These helpers write command/stdout/stderr bundles under
~/.blackbox-recon/artifacts/<target>/tcp_<port>_<service>/.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Optional


def _safe(value: Any, default: str = "unknown") -> str:
    text = str(value or default).strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "_", text)
    text = text.strip("._-")
    return text or default


def artifact_root(target: str) -> Path:
    return Path.home() / ".blackbox-recon" / "artifacts" / _safe(target, "target")


def service_artifact_dir(target: str, host: str, port: int, service: str) -> Path:
    base = artifact_root(target)
    return base / f"tcp_{int(port)}_{_safe(service)}"


def write_tool_artifact(
    *,
    target: str,
    host: str,
    port: int,
    service: str,
    module: str,
    command: Optional[str],
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
) -> Optional[str]:
    """Write a raw tool artifact and return its path."""
    try:
        out_dir = service_artifact_dir(target, host, int(port), service)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{_safe(module)}.txt"
        parts = []
        if command:
            parts.append("# Command\n" + str(command).strip())
        if stdout:
            parts.append("# STDOUT\n" + str(stdout).rstrip())
        if stderr:
            parts.append("# STDERR\n" + str(stderr).rstrip())
        if not parts:
            return None
        path.write_text("\n\n".join(parts) + "\n", encoding="utf-8", errors="replace")
        return str(path)
    except Exception:
        return None


def artifact_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Collect artifact paths already attached to result rows."""
    paths = []
    for block_name in ("service_enumeration", "tls_analysis", "web_content_discovery", "web_fingerprinting", "dns_record_enrichment", "screenshot_triage"):
        block = results.get(block_name) or {}
        if isinstance(block, dict):
            rows = block.get("results") or block.get("directory_scans") or []
            for row in rows:
                if isinstance(row, dict) and row.get("artifact_path"):
                    paths.append(row.get("artifact_path"))
    return {"count": len(paths), "paths": paths[:200]}
