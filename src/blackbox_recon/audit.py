"""Append-only audit log for execution traceability."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def append_audit_event(log_path: Path, event: str, **fields: Any) -> None:
    """Append one JSON object per line (JSONL)."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record: Dict[str, Any] = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
