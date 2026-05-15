"""Per-engagement workspace layout (Aesa-style evidence tree)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

# Standard layout under workspaces/<engagement_id>/
WORKSPACE_SUBDIRS: List[str] = [
    "00_scope",
    "01_recon",
    "02_discovery",
    "03_scans",
    "04_web",
    "05_internal",
    "06_ad",
    "07_validation",
    "08_evidence",
    "09_findings",
    "10_reports",
    "tmp",
]


def create_engagement_workspace(
    engagement_id: str,
    base_root: Path | None = None,
) -> Dict[str, Path]:
    """
    Create workspace directories. Returns map of logical name -> absolute path.

    ``base_root`` defaults to ``~/.blackbox-recon/workspaces``.
    """
    root = (base_root or (Path.home() / ".blackbox-recon" / "workspaces")).expanduser()
    safe_id = engagement_id.replace("/", "_").replace("\\", "_").strip() or "unknown"
    ws = root / safe_id
    paths: Dict[str, Path] = {"root": ws.resolve()}
    for sub in WORKSPACE_SUBDIRS:
        p = (ws / sub).resolve()
        p.mkdir(parents=True, exist_ok=True)
        paths[sub] = p
    paths["recon"] = paths["01_recon"]
    paths["reports"] = paths["10_reports"]
    paths["evidence"] = paths["08_evidence"]
    paths["tmp"] = paths["tmp"]
    meta = paths["00_scope"] / "engagement_workspace.json"
    meta.write_text(
        json.dumps(
            {
                "engagement_id": engagement_id,
                "workspace_root": str(paths["root"]),
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "directories": WORKSPACE_SUBDIRS,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return paths
