"""Engagement scope helpers (no network)."""

import ipaddress

from blackbox_recon.engagement import (
    EngagementSpec,
    host_in_rule_list,
    scope_allows_target,
    technique_allowed,
)


def test_scope_allows_ip_in_cidr():
    spec = EngagementSpec(
        engagement_id="e1",
        client="c",
        authorization_reference="auth",
        allowed_targets=["10.0.0.0/24"],
        excluded_targets=[],
        action_reason="test",
    )
    ok, msg = scope_allows_target("10.0.0.5", spec)
    assert ok, msg


def test_scope_denies_excluded():
    spec = EngagementSpec(
        engagement_id="e1",
        client="c",
        authorization_reference="auth",
        allowed_targets=["192.0.2.0/24"],
        excluded_targets=["192.0.2.10"],
        action_reason="test",
    )
    ok, _ = scope_allows_target("192.0.2.10", spec)
    assert not ok


def test_technique_prohibited():
    spec = EngagementSpec(
        engagement_id="e1",
        client="c",
        authorization_reference="auth",
        allowed_targets=["192.0.2.0/24"],
        prohibited_techniques=["directory_bruteforce"],
        action_reason="test",
    )
    ok, _ = technique_allowed("directory_bruteforce", spec)
    assert not ok


def test_host_in_cidr_rule():
    net = ipaddress.ip_network("198.51.100.0/28")
    assert host_in_rule_list("198.51.100.3", [str(net)])
