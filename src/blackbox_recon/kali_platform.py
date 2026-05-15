"""Kali / Debian host integration: discover external CLI tools and optional apt installs."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class ExternalTool:
    """Maps a logical capability to binaries on PATH and Debian-family packages."""

    tool_id: str
    binaries: Tuple[str, ...]
    debian_packages: Tuple[str, ...]


TOOLS_NMAP = ExternalTool("nmap", ("nmap",), ("nmap",))
TOOLS_NSLOOKUP = ExternalTool("nslookup", ("nslookup",), ("dnsutils",))
TOOLS_GOBUSTER = ExternalTool("gobuster", ("gobuster",), ("gobuster",))
TOOLS_DIRB = ExternalTool("dirb", ("dirb",), ("dirb",))


def read_os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.is_file():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        data[key.strip()] = val.strip().strip('"')
    return data


def is_kali_linux(os_release: Optional[Dict[str, str]] = None) -> bool:
    rel = os_release if os_release is not None else read_os_release()
    ident = (rel.get("ID") or "").lower()
    id_like = (rel.get("ID_LIKE") or "").lower()
    name = (rel.get("NAME") or "").lower()
    return ident == "kali" or "kali" in name or "kali" in id_like


def is_debian_like(os_release: Optional[Dict[str, str]] = None) -> bool:
    rel = os_release if os_release is not None else read_os_release()
    ident = (rel.get("ID") or "").lower()
    id_like = (rel.get("ID_LIKE") or "").lower()
    return ident in ("debian", "ubuntu", "kali", "parrot") or "debian" in id_like


def tool_status(tool: ExternalTool) -> Dict[str, Any]:
    for name in tool.binaries:
        path = shutil.which(name)
        if path:
            return {"present": True, "binary": name, "path": path}
    return {"present": False, "binary": tool.binaries[0] if tool.binaries else None, "path": None}


def _directory_scan_needs(cfg: Dict[str, Any]) -> Tuple[bool, str]:
    enabled = bool(cfg.get("directory_scan_enabled", True))
    pref = str(cfg.get("directory_tool", "auto")).lower()
    return enabled and pref != "none", pref


def missing_packages_for_config(cfg: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Return (missing_tool_ids, apt_package_names) for the current recon config.
    """
    missing_ids: List[str] = []
    pkgs: Set[str] = set()

    mode = str(cfg.get("port_scan_mode", "nmap_aggressive")).lower()
    if mode == "nmap_aggressive":
        st = tool_status(TOOLS_NMAP)
        if not st["present"]:
            missing_ids.append(TOOLS_NMAP.tool_id)
            pkgs.update(TOOLS_NMAP.debian_packages)

    if bool(cfg.get("run_nslookup", True)):
        st = tool_status(TOOLS_NSLOOKUP)
        if not st["present"]:
            missing_ids.append(TOOLS_NSLOOKUP.tool_id)
            pkgs.update(TOOLS_NSLOOKUP.debian_packages)

    need_dir, pref = _directory_scan_needs(cfg)
    if need_dir:
        go = tool_status(TOOLS_GOBUSTER)["present"]
        db = tool_status(TOOLS_DIRB)["present"]
        if pref == "auto":
            if not go and not db:
                missing_ids.append("gobuster_or_dirb")
                pkgs.update(TOOLS_GOBUSTER.debian_packages)
                pkgs.update(TOOLS_DIRB.debian_packages)
        elif pref == "gobuster" and not go:
            missing_ids.append(TOOLS_GOBUSTER.tool_id)
            pkgs.update(TOOLS_GOBUSTER.debian_packages)
        elif pref == "dirb" and not db:
            missing_ids.append(TOOLS_DIRB.tool_id)
            pkgs.update(TOOLS_DIRB.debian_packages)

    return missing_ids, sorted(pkgs)


def build_toolchain_snapshot(cfg: Dict[str, Any]) -> Dict[str, Any]:
    rel = read_os_release()
    miss_ids, miss_pkgs = missing_packages_for_config(cfg)
    return {
        "os_release": rel,
        "is_kali": is_kali_linux(rel),
        "is_debian_like": is_debian_like(rel),
        "tools": {
            "nmap": tool_status(TOOLS_NMAP),
            "nslookup": tool_status(TOOLS_NSLOOKUP),
            "gobuster": tool_status(TOOLS_GOBUSTER),
            "dirb": tool_status(TOOLS_DIRB),
        },
        "missing_tool_ids": miss_ids,
        "missing_apt_packages": miss_pkgs,
    }


def sudo_noninteractive_ok() -> bool:
    if os.name != "posix":
        return False
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True
        proc = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def run_apt_install(packages: Sequence[str], *, update_first: bool = False) -> Tuple[bool, str]:
    """
    Install Debian packages using non-interactive sudo. Returns (ok, combined_output).
    """
    pkgs = [p for p in packages if p]
    if not pkgs:
        return True, ""
    if os.name != "posix":
        return False, "apt install is only supported on POSIX hosts."

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    prefix: List[str] = [] if is_root else ["sudo", "-n"]

    parts: List[str] = []
    if update_first:
        u = subprocess.run(
            prefix + ["apt-get", "update", "-qq"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        parts.append((u.stdout or "") + (u.stderr or ""))
        if u.returncode != 0:
            return False, "\n".join(parts)

    proc = subprocess.run(
        prefix + ["apt-get", "install", "-y", "-qq", *pkgs],
        capture_output=True,
        text=True,
        timeout=3600,
    )
    parts.append((proc.stdout or "") + (proc.stderr or ""))
    return proc.returncode == 0, "\n".join(parts).strip()


def ensure_kali_toolchain(
    cfg: Dict[str, Any],
    *,
    auto_install: bool,
    apt_update_first: bool = False,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Build a toolchain snapshot; optionally install missing apt packages on Kali/Debian-like hosts.

    Returns (snapshot, error_message_or_none).
    """
    snap = build_toolchain_snapshot(cfg)
    miss = snap.get("missing_apt_packages") or []
    if not miss or not auto_install:
        return snap, None

    if not (snap.get("is_kali") or snap.get("is_debian_like")):
        return snap, "auto_install requested but host is not Kali/Debian-like; skipping apt."

    if not sudo_noninteractive_ok():
        return (
            snap,
            "Cannot install packages: need passwordless sudo (sudo -n) or run as root. "
            f"Install manually: sudo apt-get install -y {' '.join(miss)}",
        )

    ok, out = run_apt_install(miss, update_first=apt_update_first)
    if not ok:
        return snap, f"apt-get install failed:\n{out}"

    snap2 = build_toolchain_snapshot(cfg)
    return snap2, None
