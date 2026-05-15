"""Generate nmap_top1000_tcp.py from nmap-services (TCP, by descending open-frequency)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Download nmap-services first:
# curl -L -o nmap-services https://raw.githubusercontent.com/nmap/nmap/master/nmap-services


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("nmap-services")
    rows: list[tuple[float, int]] = []
    for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        if "/tcp" not in parts[1]:
            continue
        try:
            port = int(parts[1].split("/tcp", 1)[0])
            freq = float(parts[2])
        except ValueError:
            continue
        rows.append((freq, port))
    rows.sort(reverse=True)
    seen: set[int] = set()
    top: list[int] = []
    for _, port in rows:
        if port in seen:
            continue
        seen.add(port)
        top.append(port)
        if len(top) >= 1000:
            break
    out = Path(__file__).resolve().parents[1] / "src" / "blackbox_recon" / "nmap_top1000_tcp.py"
    body = (
        "# Generated from nmap-services (Nmap project). TCP ports, unique, by descending "
        "open-frequency field (same ordering nmap uses for weighted port selection).\n"
        "NMAP_TOP1000_TCP = (\n"
        + ",\n".join(str(p) for p in top)
        + ",\n)\n"
    )
    out.write_text(body, encoding="utf-8")
    print(f"Wrote {len(top)} ports to {out}")


if __name__ == "__main__":
    main()
