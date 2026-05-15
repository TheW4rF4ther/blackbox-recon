"""Engagement intake, scope validation, and execution gates (Aesa / Blackbox methodology)."""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from pydantic import BaseModel, Field, field_validator


class EngagementGateError(Exception):
    """Raised when a mandatory gate blocks execution."""


class EngagementSpec(BaseModel):
    """Minimum engagement record required before active recon."""

    engagement_id: str = Field(..., min_length=1)
    client: str = Field(..., min_length=1)
    authorization_reference: str = Field(
        ...,
        description="Signed SOW / ROE / written authorization reference",
        min_length=1,
    )
    sow_reference: Optional[str] = None
    rules_of_engagement_reference: Optional[str] = None
    testing_window_start: Optional[str] = Field(
        default=None,
        description="ISO date YYYY-MM-DD inclusive start of testing window",
    )
    testing_window_end: Optional[str] = Field(
        default=None,
        description="ISO date YYYY-MM-DD inclusive end of testing window",
    )
    allowed_targets: List[str] = Field(
        default_factory=list,
        description="IPs, CIDRs, or hostnames explicitly in scope",
    )
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_techniques: List[str] = Field(
        default_factory=list,
        description="If non-empty, only these technique ids may run",
    )
    prohibited_techniques: List[str] = Field(
        default_factory=list,
        description="Technique ids that must never run for this engagement",
    )
    action_reason: str = Field(
        default="",
        description="Client value: why this run is justified (validation, evidence, etc.)",
    )
    created_by: Optional[str] = None

    @field_validator("allowed_targets", "excluded_targets", mode="before")
    @classmethod
    def _strip_list(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        return []


def load_engagement(path: Union[str, Path]) -> EngagementSpec:
    """Load engagement from YAML or JSON."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise EngagementGateError(f"Engagement file not found: {p}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise EngagementGateError("Engagement file must contain a mapping at the root")
    return EngagementSpec(**data)


def _parse_host_or_network(entry: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network, str]:
    e = entry.strip()
    if not e:
        raise ValueError("empty")
    if "/" in e:
        return ipaddress.ip_network(e, strict=False)
    try:
        return ipaddress.ip_address(e)
    except ValueError:
        return e.lower()


def _host_matches_rule(host: str, rule: Union[ipaddress.IPv4Network, ipaddress.IPv6Network, str]) -> bool:
    """True if host (IP string or FQDN) matches a single allowed/excluded rule."""
    host = host.strip().lower()
    if isinstance(rule, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return addr == rule
    if isinstance(rule, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            try:
                ips = {ipaddress.ip_address(ai[4][0]) for ai in socket.getaddrinfo(host, None)}
            except OSError:
                return False
            return any(addr in rule for addr in ips)
        return addr in rule
    r = str(rule).lower().strip()
    if r.startswith("*."):
        suffix = r[1:]  # .example.com
        return host == r[2:] or host.endswith(suffix)
    return host == r


def host_in_rule_list(host: str, rules: List[str]) -> bool:
    for raw in rules:
        try:
            parsed = _parse_host_or_network(raw)
        except ValueError:
            continue
        if _host_matches_rule(host, parsed):
            return True
    return False


def scope_allows_target(target: str, spec: EngagementSpec) -> Tuple[bool, str]:
    """
    Return (ok, message). Deny if excluded matches first, or not in allowed_targets when that list is set.
    Empty allowed_targets => configuration error (fail closed).
    """
    if not spec.allowed_targets:
        return False, "allowed_targets is empty — define explicit in-scope assets (fail closed)."

    t = target.strip()
    if host_in_rule_list(t, spec.excluded_targets):
        return False, f"Target {t!r} matches an excluded_targets rule."

    if host_in_rule_list(t, spec.allowed_targets):
        return True, "Target matches allowed_targets."

    # Hostname with no direct rule: allow if any resolved A/AAAA is allowed
    try:
        ipaddress.ip_address(t)
        return False, f"IP {t} is not covered by allowed_targets."
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(t, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"Could not resolve {t!r} for scope check: {exc}"

    resolved = []
    for inf in infos:
        fam, _, _, _, sockaddr = inf
        if fam == socket.AF_INET:
            resolved.append(sockaddr[0])
        elif fam == socket.AF_INET6:
            resolved.append(sockaddr[0])

    if not resolved:
        return False, f"No addresses resolved for {t!r}; cannot validate scope."

    for ip in resolved:
        if host_in_rule_list(ip, spec.excluded_targets):
            return False, f"Resolved address {ip} matches excluded_targets."
    for ip in resolved:
        if host_in_rule_list(ip, spec.allowed_targets):
            return True, f"Hostname allowed via resolved address {ip}."
    return False, f"No resolved address for {t!r} is covered by allowed_targets."


def assert_within_testing_window(spec: EngagementSpec) -> None:
    """Fail if calendar today is outside the declared testing window (when dates are set)."""
    if not spec.testing_window_start and not spec.testing_window_end:
        return
    start_s = spec.testing_window_start
    end_s = spec.testing_window_end
    if not start_s or not end_s:
        raise EngagementGateError(
            "Provide both testing_window_start and testing_window_end, or omit both."
        )
    try:
        start = date.fromisoformat(start_s[:10])
        end = date.fromisoformat(end_s[:10])
    except ValueError as exc:
        raise EngagementGateError(f"Invalid testing window dates: {exc}") from exc
    today = date.today()
    if today < start or today > end:
        raise EngagementGateError(
            f"Current date {today} is outside testing window {start} .. {end}."
        )


def technique_allowed(technique_id: str, spec: EngagementSpec) -> Tuple[bool, str]:
    if technique_id in spec.prohibited_techniques:
        return False, f"Technique {technique_id!r} is prohibited for this engagement."
    if spec.allowed_techniques and technique_id not in spec.allowed_techniques:
        return False, (
            f"Technique {technique_id!r} is not listed in allowed_techniques "
            f"(allowed_techniques is non-empty)."
        )
    return True, "Technique permitted."


def assert_four_questions(spec: EngagementSpec, target: str, technique_ids: List[str]) -> None:
    """
    Core operating rule: authorization, scope, technique allow-list, client value (action_reason).
    """
    if not spec.authorization_reference.strip():
        raise EngagementGateError("authorization_reference is required (signed authorization).")
    ok, msg = scope_allows_target(target, spec)
    if not ok:
        raise EngagementGateError(f"Scope / asset gate: {msg}")
    if not spec.action_reason.strip():
        raise EngagementGateError(
            "action_reason is required: document client value "
            "(finding validation, risk clarification, remediation guidance, or evidence collection)."
        )
    for tid in technique_ids:
        ok_t, msg_t = technique_allowed(tid, spec)
        if not ok_t:
            raise EngagementGateError(f"Technique gate: {msg_t}")


def scope_allows_host(host: str, spec: EngagementSpec) -> Tuple[bool, str]:
    """Check a concrete host or IP against allowed/excluded lists (for scan fan-out)."""
    h = host.strip().lower()
    if not spec.allowed_targets:
        return False, "allowed_targets is empty (fail closed)."
    if host_in_rule_list(h, spec.excluded_targets):
        return False, f"Host {host!r} matches excluded_targets."
    if host_in_rule_list(h, spec.allowed_targets):
        return True, "Host matches allowed_targets."
    return False, f"Host {host!r} is not covered by allowed_targets."


def compute_standing_scope_ips(target: str, spec: EngagementSpec) -> set[str]:
    """
    IPv4 addresses in standing for the engagement primary target
    (explicit IP, or all A records for an approved hostname).
    """
    ips: set[str] = set()
    t = target.strip()
    try:
        addr = ipaddress.ip_address(t)
        ok, _ = scope_allows_host(str(addr), spec)
        if ok:
            ips.add(str(addr))
        return ips
    except ValueError:
        pass
    ok, _ = scope_allows_target(t, spec)
    if not ok:
        return ips
    try:
        for inf in socket.getaddrinfo(t, None, socket.AF_INET, socket.SOCK_STREAM):
            ips.add(inf[4][0])
    except OSError:
        pass
    return ips


def plan_techniques(modules: List[str], recon_config: Dict[str, Any]) -> List[str]:
    """Map CLI modules + recon settings to stable technique ids for gates and audit."""
    out: List[str] = []
    if "subdomain" in modules:
        out.append("subdomain_enumeration")
    if "portscan" in modules:
        mode = str(recon_config.get("port_scan_mode", "nmap_aggressive")).lower()
        if mode == "nmap_aggressive":
            out.append("port_scan_nmap_aggressive")
        else:
            out.append("port_scan_tcp_connect")
        if recon_config.get("run_nslookup", True):
            out.append("dns_nslookup")
        if (
            recon_config.get("directory_scan_enabled", True)
            and str(recon_config.get("directory_tool", "auto")).lower() != "none"
        ):
            out.append("directory_bruteforce")
    if "technology" in modules:
        out.append("http_technology_fingerprint")
    seen = set()
    deduped: List[str] = []
    for tid in out:
        if tid not in seen:
            seen.add(tid)
            deduped.append(tid)
    return deduped


@dataclass(frozen=True)
class EngagementRuntime:
    """Bound engagement: immutable spec, workspace paths, audit file, expanded IPv4 scope."""

    spec: EngagementSpec
    paths: Dict[str, Path]
    audit_log_path: Path
    scope_expanded_ips: frozenset[str]

    def audit(self, event: str, **kwargs: Any) -> None:
        from .audit import append_audit_event

        append_audit_event(
            self.audit_log_path,
            event,
            engagement_id=self.spec.engagement_id,
            **kwargs,
        )


def build_engagement_runtime(
    spec: EngagementSpec,
    expanded_ips: set[str],
    workspace_base: Optional[Path] = None,
) -> EngagementRuntime:
    from .workspace import create_engagement_workspace

    paths = create_engagement_workspace(spec.engagement_id, workspace_base)
    audit_path = paths["tmp"] / "audit.jsonl"
    return EngagementRuntime(
        spec=spec,
        paths=paths,
        audit_log_path=audit_path,
        scope_expanded_ips=frozenset(expanded_ips),
    )
