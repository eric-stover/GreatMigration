import json

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import compliance

from compliance import (
    SiteContext,
    Finding,
    ComplianceCheck,
    RequiredSiteVariablesCheck,
    SwitchTemplateConfigurationCheck,
    ConfigurationOverridesCheck,
    FirmwareManagementCheck,
    CloudManagementCheck,
    SwitchPowerSupplyHealthCheck,
    SpareSwitchPresenceCheck,
    DeviceNamingConventionCheck,
    DeviceDocumentationCheck,
    SiteAuditRunner,
    DEFAULT_REQUIRED_SITE_VARIABLES,
    DNS_OVERRIDE_TEMPLATE_NAME,
    DNS_OVERRIDE_LAB_TEMPLATE_NAME,
    DNS_OVERRIDE_PROD_TEMPLATE_IDS,
    DNS_OVERRIDE_LAB_TEMPLATE_IDS,
    DNS_OVERRIDE_REQUIRED_VAR_GROUPS,
    DNS_OVERRIDE_REQUIRED_VARS,
    load_site_variable_config,
)
from audit_actions import (
    AP_RENAME_ACTION_ID,
    CLEAR_DNS_OVERRIDE_ACTION_ID,
    ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
    SET_SITE_VARIABLES_ACTION_ID,
    SET_SPARE_SWITCH_ROLE_ACTION_ID,
)


def _format_dns_label_group(options):
    values = [opt for opt in options if isinstance(opt, str) and opt]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} or {values[1]}"
    return ", ".join(values[:-1]) + f", or {values[-1]}"


def _expected_dns_labels():
    labels = []
    for group in DNS_OVERRIDE_REQUIRED_VAR_GROUPS:
        label = _format_dns_label_group(group)
        if label:
            labels.append(label)
    return labels


def test_load_site_variable_config_parses_defaults(monkeypatch):
    monkeypatch.setenv("MIST_SITE_VARIABLES", "foo=1, bar :2 , baz")
    required, defaults = load_site_variable_config()
    assert required == ("foo", "bar", "baz")
    assert defaults == {"foo": "1", "bar": "2"}


def test_required_site_variables_check_flags_missing():
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={"variables": {}},
        setting={},
        templates=[],
        devices=[],
    )
    check = RequiredSiteVariablesCheck()
    findings = check.run(ctx)
    expected_messages = {
        f"Site variable '{key}' is not defined." for key in DEFAULT_REQUIRED_SITE_VARIABLES
    }
    assert {f.message for f in findings} == expected_messages


def test_required_site_variables_check_passes_when_present():
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={
            "variables": {
                key: f"value-{idx}" for idx, key in enumerate(DEFAULT_REQUIRED_SITE_VARIABLES)
            }
        },
        setting={},
        templates=[],
        devices=[],
    )
    check = RequiredSiteVariablesCheck()
    findings = check.run(ctx)
    assert findings == []


def test_required_site_variables_check_respects_env(monkeypatch):
    monkeypatch.setenv("MIST_SITE_VARIABLES", "foo , bar,baz , ")
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={"variables": {"foo": "ok"}},
        setting={},
        templates=[],
        devices=[],
    )
    check = RequiredSiteVariablesCheck()
    findings = check.run(ctx)
    assert {f.message for f in findings} == {
        "Site variable 'bar' is not defined.",
        "Site variable 'baz' is not defined.",
    }


def test_required_site_variables_check_builds_action_from_env_defaults(monkeypatch):
    monkeypatch.setenv(
        "MIST_SITE_VARIABLES",
        "hubradiusserver=1.1.1.1,localradiusserver=2.2.2.2,siteDNS,hubDNSserver1=10.10.10.1,hubDNSserver2=10.10.10.2",
    )
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={"variables": {}},
        setting={},
        templates=[],
        devices=[],
    )
    check = RequiredSiteVariablesCheck()
    findings = check.run(ctx)
    assert len(findings) == 5
    actions_by_variable = {}
    for finding in findings:
        if not finding.actions:
            continue
        assert len(finding.actions) == 1
        action = finding.actions[0]
        assert action["id"] == SET_SITE_VARIABLES_ACTION_ID
        metadata = action.get("metadata", {})
        variables = metadata.get("variables", {})
        assert len(variables) == 1
        key = next(iter(variables))
        actions_by_variable[key] = variables[key]
    assert actions_by_variable == {
        "hubradiusserver": "1.1.1.1",
        "localradiusserver": "2.2.2.2",
        "hubDNSserver1": "10.10.10.1",
        "hubDNSserver2": "10.10.10.2",
    }
    assert any(
        finding.message == "Site variable 'siteDNS' is not defined." and finding.actions is None
        for finding in findings
    )


def test_switch_template_check_flags_non_lab_site_without_prod_template():
    ctx = SiteContext(
        site_id="site-2",
        site_name="Corporate Campus",
        site={},
        setting={},
        templates=[{"name": "Test - Standard Template"}],
        devices=[],
    )
    check = SwitchTemplateConfigurationCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "should apply" in findings[0].message


def test_switch_template_check_flags_extra_templates_on_non_lab_site():
    ctx = SiteContext(
        site_id="site-3",
        site_name="HQ",
        site={},
        setting={},
        templates=[
            {"name": "Prod - Standard Template"},
            {"name": "Custom Template"},
        ],
        devices=[],
    )
    check = SwitchTemplateConfigurationCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "should not apply additional templates" in findings[0].message


def test_switch_template_check_allows_lab_site_with_test_template():
    ctx = SiteContext(
        site_id="site-4",
        site_name="Innovation Lab",
        site={},
        setting={},
        templates=[{"name": "Test - Standard Template"}],
        devices=[],
    )
    check = SwitchTemplateConfigurationCheck()
    assert check.run(ctx) == []


def test_switch_template_check_allows_lab_site_with_prod_template():
    ctx = SiteContext(
        site_id="site-5",
        site_name="Lab Campus",
        site={},
        setting={},
        templates=[{"name": "Prod - Standard Template"}],
        devices=[],
    )
    check = SwitchTemplateConfigurationCheck()
    assert check.run(ctx) == []


def test_switch_template_check_flags_lab_site_without_allowed_templates():
    ctx = SiteContext(
        site_id="site-6",
        site_name="LAB Annex",
        site={},
        setting={},
        templates=[{"name": "Custom Template"}],
        devices=[],
    )
    check = SwitchTemplateConfigurationCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "Lab site should apply either" in findings[0].message


def test_configuration_overrides_check_respects_access_exceptions():
    ctx = SiteContext(
        site_id="site-4",
        site_name="Branch",
        site={},
        setting={"switch_override": {"foo": "bar"}},
        templates=[],
        devices=[
            {
                "id": "access1",
                "name": "Access Switch",
                "role": "ACCESS",
                "status": "connected",
                "map_id": "map-access1",
                "port_overrides": [{"port_id": "ge-0/0/10", "profile": "Voice"}],
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.10",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            },
            {
                "id": "dist1",
                "name": "Distribution Switch",
                "role": "DISTRIBUTION",
                "status": "connected",
                "map_id": "map-dist1",
                "port_overrides": [{"port_id": "ge-0/0/48", "profile": "Uplink"}],
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.1.10",
                        "gateway": "10.0.1.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            },
            {
                "id": "cfg1",
                "name": "Custom Switch",
                "status": "connected",
                "type": "switch",
                "map_id": "map-cfg1",
                "config_override": {"foo": "bar"},
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.2.10",
                        "gateway": "10.0.2.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            },
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    # Site override should be reported
    site_findings = [f for f in findings if f.device_id is None]
    assert site_findings

    # Access switch override on port 10 should be allowed
    assert all(f.device_id != "access1" for f in findings)

    # Distribution switch override should be reported
    assert any(f.device_id == "dist1" for f in findings)

    # Direct config override should be reported
    assert any(f.device_id == "cfg1" for f in findings)


def test_configuration_overrides_check_detects_template_differences():
    ctx = SiteContext(
        site_id="site-7",
        site_name="Template Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                },
            }
        ],
        devices=[
            {
                "id": "dist1",
                "name": "Distribution",
                "role": "DISTRIBUTION",
                "status": "connected",
                "map_id": "map-dist1",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.3",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "dhcp_snooping": {"enabled": True},
                },
            },
            {
                "id": "access1",
                "name": "Access",
                "role": "ACCESS",
                "status": "connected",
                "map_id": "map-access1",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "port_config": {
                        "ge-0/0/0": {"usage": "voice"},
                        "ge-0/0/48": {"usage": "uplink_idf"},
                        "xe-0/2/1": {"usage": "uplink_idf"},
                    },
                },
            },
            {
                "id": "access2",
                "name": "Access Edge",
                "role": "ACCESS",
                "status": "connected",
                "map_id": "map-access2",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "192.168.0.2",
                        "gateway": "192.168.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "port_config": {
                        "ge-0/0/0": {"usage": "end_user"},
                        "ge-0/0/48": {"usage": "uplink_idf"},
                        "xe-0/2/1": {"usage": "internet_only"},
                    },
                },
            },
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    dist_findings = [
        f
        for f in findings
        if f.device_id == "dist1"
        and any("dhcp" in (diff.get("path") or "") for diff in (f.details or {}).get("diffs", []))
    ]
    assert dist_findings, "Distribution switch dhcp_snooping override should be reported"

    access1_findings = [f for f in findings if f.device_id == "access1" and "differs" in f.message]
    assert not access1_findings, "Access switch non-uplink differences should be ignored"

    access2_findings = [f for f in findings if f.device_id == "access2" and "differs" in f.message]
    assert access2_findings, "Access switch IP violations should be reported"


def _write_standard_versions(path: Path, *, switch_versions, ap_versions, generated_at="2025-01-01T00:00:00Z"):
    payload = {
        "generated_at": generated_at,
        "sources": {},
        "models": {
            "switch": {
                "EX2300": [{"version": version} for version in switch_versions],
            },
            "ap": {
                "AP32": [{"version": version} for version in ap_versions],
            },
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")




def test_refresh_standards_when_recent_file_is_empty(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    recent = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": recent,
                "sources": {},
                "models": {"switch": {}, "ap": {}},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    def _fake_fetch(device_type):
        if device_type == "switch":
            return [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"], "record_id": "1"}]
        if device_type == "ap":
            return [{"model": "AP32", "version": "0.12.27452", "tags": ["junos_suggested"], "record_id": "2"}]
        return []

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    versions = compliance._load_allowed_versions_from_standard_doc("switch")

    assert "20.4R3-S4" in versions

    written = json.loads(standards_path.read_text(encoding="utf-8"))
    assert written["models"]["switch"]["EX2300"][0]["version"] == "20.4R3-S4"
    assert written["models"]["ap"]["AP32"][0]["version"] == "0.12.27452"




def test_refresh_standards_accepts_paginated_payload(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    def _fake_fetch(_device_type):
        return [
            {"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"], "record_id": "1"},
        ]

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    compliance._refresh_firmware_standards_if_needed(standards_path)

    written = json.loads(standards_path.read_text(encoding="utf-8"))
    assert written["models"]["switch"]["EX2300"][0]["version"] == "20.4R3-S4"


def test_fetch_versions_for_type_accepts_dict_payload(monkeypatch):
    monkeypatch.setenv("MIST_TOKEN", "token")
    monkeypatch.setenv("MIST_ORG_ID", "org-id")

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"]}]}

    monkeypatch.setattr(compliance.requests, "get", lambda *args, **kwargs: _Resp())

    rows = compliance._fetch_versions_for_type("switch")
    assert rows == [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"]}]



def test_fetch_versions_for_type_discovers_org_via_self(monkeypatch):
    monkeypatch.setenv("MIST_TOKEN", "token")
    monkeypatch.delenv("MIST_ORG_ID", raising=False)
    monkeypatch.setattr(compliance, "_MIST_ORG_ID_CACHE", None)

    calls = []

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def _fake_get(url, **kwargs):
        calls.append(url)
        if url.endswith("/self"):
            return _Resp({"org_id": "derived-org"})
        return _Resp({"results": [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"]}]})

    monkeypatch.setattr(compliance.requests, "get", _fake_get)

    rows = compliance._fetch_versions_for_type("switch")

    assert rows == [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"]}]
    assert any(call.endswith("/self") for call in calls)
    assert any("/orgs/derived-org/devices/versions" in call for call in calls)


def test_fetch_versions_for_type_uses_cached_org_id(monkeypatch):
    monkeypatch.setenv("MIST_TOKEN", "token")
    monkeypatch.delenv("MIST_ORG_ID", raising=False)
    monkeypatch.setattr(compliance, "_MIST_ORG_ID_CACHE", "cached-org")

    calls = []

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"]}]}

    def _fake_get(url, **kwargs):
        calls.append(url)
        return _Resp()

    monkeypatch.setattr(compliance.requests, "get", _fake_get)

    rows = compliance._fetch_versions_for_type("switch")

    assert rows == [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"]}]
    assert all(not call.endswith("/self") for call in calls)
    assert any("/orgs/cached-org/devices/versions" in call for call in calls)


def test_fetch_versions_for_type_ap_falls_back_to_site_catalog(monkeypatch):
    monkeypatch.setenv("MIST_TOKEN", "token")
    monkeypatch.setenv("MIST_ORG_ID", "org-id")

    calls = []

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def _fake_get(url, **kwargs):
        calls.append(url)
        if url.endswith('/orgs/org-id/devices/versions'):
            return _Resp([])
        if url.endswith('/orgs/org-id/sites'):
            return _Resp([{"id": "site-1"}, {"id": "site-2"}])
        if url.endswith('/sites/site-1/devices/versions'):
            return _Resp([
                {"model": "AP32", "version": "0.12.27452", "record_id": 11, "tags": ["junos_suggested"]}
            ])
        if url.endswith('/sites/site-2/devices/versions'):
            return _Resp([
                {"model": "AP32", "version": "0.12.27452", "record_id": 11, "tags": ["junos_suggested"]},
                {"model": "AP45", "version": "0.13.30000", "record_id": 22, "tags": ["junos_suggested"]},
            ])
        raise AssertionError(f'unexpected url {url}')

    monkeypatch.setattr(compliance.requests, "get", _fake_get)

    rows = compliance._fetch_versions_for_type("ap")

    assert {row["model"] for row in rows} == {"AP32", "AP45"}
    assert any(call.endswith('/orgs/org-id/sites') for call in calls)
    assert any(call.endswith('/sites/site-1/devices/versions') for call in calls)
    assert any(call.endswith('/sites/site-2/devices/versions') for call in calls)


def test_fetch_versions_for_type_ap_without_fallback_for_non_ap(monkeypatch):
    monkeypatch.setenv("MIST_TOKEN", "token")
    monkeypatch.setenv("MIST_ORG_ID", "org-id")

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return []

    monkeypatch.setattr(compliance.requests, "get", lambda *args, **kwargs: _Resp())

    rows = compliance._fetch_versions_for_type("switch")

    assert rows == []


def test_refresh_standards_accepts_string_tags(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    def _fake_fetch(device_type):
        if device_type == "switch":
            return [{"model": "EX2300", "version": "20.4R3-S4", "tags": "beta,junos_suggested"}]
        if device_type == "ap":
            return [{"model": "AP32", "version": "0.12.27452", "tag": "alpha", "tags": ["alpha"]}]
        return []

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    compliance._refresh_firmware_standards_if_needed(standards_path)

    written = json.loads(standards_path.read_text(encoding="utf-8"))
    assert written["models"]["switch"]["EX2300"][0]["version"] == "20.4R3-S4"
    assert written["models"]["ap"]["AP32"][0]["version"] == "0.12.27452"


def test_refresh_standards_uses_ap_alpha_tag_and_drops_internal_version_field(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    def _fake_fetch(device_type):
        if device_type == "switch":
            return [{"model": "EX2300", "version": "20.4R3-S4", "tags": ["junos_suggested"]}]
        if device_type == "ap":
            return [
                {"model": "AP32E", "version": "0.12.27452", "_version": "apfw-0.12.27452-lollys-5ba8", "tag": "alpha", "tags": ["alpha"]},
                {"model": "AP45", "version": "0.13.30000", "tag": "stable", "tags": ["stable"]},
            ]
        return []

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    compliance._refresh_firmware_standards_if_needed(standards_path)

    written = json.loads(standards_path.read_text(encoding="utf-8"))
    ap_entry = written["models"]["ap"]["AP32E"][0]
    assert ap_entry["version"] == "0.12.27452"
    assert ap_entry["tag"] == "alpha"
    assert ap_entry["tags"] == ["alpha"]
    assert "_version" not in ap_entry
    assert "AP45" not in written["models"]["ap"]

def test_skip_refresh_when_recent_file_has_versions(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    recent = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": recent,
                "sources": {},
                "models": {
                    "switch": {"EX2300": [{"version": "20.4R3-S4"}]},
                    "ap": {},
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    def _fail_fetch(_device_type):
        raise AssertionError("fetch should not be called for recent non-empty standards")

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fail_fetch)

    versions = compliance._load_allowed_versions_from_standard_doc("switch")
    assert versions == ("20.4R3-S4",)


def test_refresh_preserves_existing_device_type_when_fetch_empty(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    stale = "2023-01-01T00:00:00Z"
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": stale,
                "sources": {},
                "models": {
                    "switch": {"EX2300": [{"version": "20.4R3-S4"}]},
                    "ap": {"AP32": [{"version": "0.12.10000"}]},
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    def _fake_fetch(device_type):
        if device_type == "switch":
            return [{"model": "EX2300", "version": "20.4R3-S5", "tags": ["junos_suggested"], "record_id": "1"}]
        if device_type == "ap":
            return []
        return []

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    compliance._refresh_firmware_standards_if_needed(standards_path)

    written = json.loads(standards_path.read_text(encoding="utf-8"))
    assert written["models"]["switch"]["EX2300"][0]["version"] == "20.4R3-S5"
    assert written["models"]["ap"]["AP32"][0]["version"] == "0.12.10000"

def test_refresh_standards_syncs_org_switch_auto_upgrade_custom_versions(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    monkeypatch.setenv("MIST_TOKEN", "token")
    monkeypatch.setenv("MIST_ORG_ID", "org-1")

    def _fake_fetch(device_type):
        if device_type == "switch":
            return [
                {"model": "EX2300", "version": "20.4R3-S5", "tags": ["junos_suggested"], "record_id": "1"},
                {"model": "EX4100", "version": "22.1R1", "tags": ["junos_suggested"], "record_id": "2"},
            ]
        if device_type == "ap":
            return []
        return []

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    put_calls = []

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def _fake_get(url, **kwargs):
        if url.endswith('/orgs/org-1/inventory/count'):
            return _Resp({"results": [{"model": "EX2300"}, {"model": "EX4100"}, {"model": "AP32"}]})
        if url.endswith('/orgs/org-1/setting'):
            return _Resp({"switch": {"auto_upgrade": {"enabled": True, "version": "stable"}}})
        raise AssertionError(f'unexpected url {url}')

    def _fake_put(url, **kwargs):
        put_calls.append({"url": url, "json": kwargs.get("json")})
        return _Resp({})

    monkeypatch.setattr(compliance.requests, "get", _fake_get)
    monkeypatch.setattr(compliance.requests, "put", _fake_put)

    compliance._refresh_firmware_standards_if_needed(standards_path)

    assert len(put_calls) == 1
    assert put_calls[0]["url"].endswith('/orgs/org-1/setting')
    assert put_calls[0]["json"]["switch"]["auto_upgrade"]["enabled"] is True
    assert put_calls[0]["json"]["switch"]["auto_upgrade"]["version"] == "stable"
    assert put_calls[0]["json"]["switch"]["auto_upgrade"]["custom_versions"] == {
        "EX2300": "20.4R3-S5",
        "EX4100": "22.1R1",
    }


def test_refresh_standards_skips_switch_auto_upgrade_sync_when_custom_versions_match(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    monkeypatch.setenv("MIST_TOKEN", "token")
    monkeypatch.setenv("MIST_ORG_ID", "org-1")

    def _fake_fetch(device_type):
        if device_type == "switch":
            return [
                {"model": "EX2300", "version": "20.4R3-S5", "tags": ["junos_suggested"], "record_id": "1"},
                {"model": "EX4100", "version": "22.1R1", "tags": ["junos_suggested"], "record_id": "2"},
            ]
        if device_type == "ap":
            return []
        return []

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    put_calls = []

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def _fake_get(url, **kwargs):
        if url.endswith('/orgs/org-1/inventory/count'):
            return _Resp({"results": [{"model": "EX2300"}, {"model": "EX4100"}, {"model": "AP32"}]})
        if url.endswith('/orgs/org-1/setting'):
            return _Resp(
                {
                    "switch": {
                        "auto_upgrade": {
                            "enabled": True,
                            "version": "stable",
                            "custom_versions": {
                                "EX2300": "20.4R3-S5",
                                "EX4100": "22.1R1",
                            },
                        }
                    }
                }
            )
        raise AssertionError(f'unexpected url {url}')

    def _fake_put(url, **kwargs):
        put_calls.append({"url": url, "json": kwargs.get("json")})
        return _Resp({})

    monkeypatch.setattr(compliance.requests, "get", _fake_get)
    monkeypatch.setattr(compliance.requests, "put", _fake_put)

    compliance._refresh_firmware_standards_if_needed(standards_path)

    assert put_calls == []


def test_refresh_standards_skips_switch_auto_upgrade_sync_when_standard_1_unchanged(monkeypatch, tmp_path):
    standards_path = tmp_path / "standard_fw_versions.json"
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": "2023-01-01T00:00:00Z",
                "sources": {},
                "models": {
                    "switch": {"EX2300": [{"version": "20.4R3-S5"}]},
                    "ap": {},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    def _fake_fetch(device_type):
        if device_type == "switch":
            return [{"model": "EX2300", "version": "20.4R3-S5", "tags": ["junos_suggested"], "record_id": "1"}]
        return []

    monkeypatch.setattr(compliance, "_fetch_versions_for_type", _fake_fetch)

    def _fail_sync(_doc):
        raise AssertionError("sync should not run when Standard 1 has not changed")

    monkeypatch.setattr(compliance, "_sync_switch_auto_upgrade_custom_versions", _fail_sync)

    compliance._refresh_firmware_standards_if_needed(standards_path)



def test_firmware_management_check_flags_unapproved_versions(monkeypatch, tmp_path):
    standards_path = tmp_path / "standards.json"
    _write_standard_versions(standards_path, switch_versions=["20.4R3-S4", "22.1R1"], ap_versions=["16.0.2"])
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    ctx = SiteContext(
        site_id="site-fw",
        site_name="Firmware Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-1", "name": "Switch 1", "type": "switch", "firmware_version": "20.1R1"},
            {"id": "ap-1", "name": "AP-1", "type": "ap", "version": "15.0.0"},
            {"id": "ap-2", "name": "AP-2", "type": "ap", "version": "16.0.2"},
        ],
    )

    check = FirmwareManagementCheck()
    findings = check.run(ctx)

    assert len(findings) == 2
    messages = {finding.message for finding in findings}
    assert any("Switch 'Switch 1'" in message for message in messages)
    assert any("AP-1" in message and "15.0.0" in message for message in messages)
    for finding in findings:
        assert finding.details
        assert finding.details.get("allowed_versions")


def test_firmware_management_check_allows_approved_versions(monkeypatch, tmp_path):
    standards_path = tmp_path / "standards.json"
    _write_standard_versions(standards_path, switch_versions=["20.4R3-S4"], ap_versions=["16.0.2"])
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    ctx = SiteContext(
        site_id="site-fw-pass",
        site_name="Firmware Pass",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-pass", "name": "Switch Pass", "type": "switch", "firmware_version": "20.4R3-S4"},
            {"id": "ap-pass", "name": "AP Pass", "type": "ap", "version": "16.0.2"},
        ],
    )

    check = FirmwareManagementCheck()
    assert check.run(ctx) == []


def test_firmware_management_check_uses_model_specific_versions(monkeypatch, tmp_path):
    standards_path = tmp_path / "standards.json"
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": "2025-01-01T00:00:00Z",
                "sources": {},
                "models": {
                    "switch": {
                        "EX2300": [{"version": "20.4R3-S4"}],
                        "EX4100": [{"version": "22.2R1"}],
                    },
                    "ap": {},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    ctx = SiteContext(
        site_id="site-fw-model",
        site_name="Firmware Model",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-model-1",
                "name": "Switch Model 1",
                "type": "switch",
                "model": "EX4100",
                "firmware_version": "20.4R3-S4",
            }
        ],
    )

    findings = FirmwareManagementCheck().run(ctx)

    assert len(findings) == 1
    assert findings[0].details["allowed_versions"] == ["22.2R1"]


def test_firmware_management_check_uses_ap_model_specific_versions(monkeypatch, tmp_path):
    standards_path = tmp_path / "standards.json"
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": "2025-01-01T00:00:00Z",
                "sources": {},
                "models": {
                    "switch": {},
                    "ap": {
                        "AP32": [{"version": "0.12.27452"}],
                        "AP45": [{"version": "0.13.30000"}],
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    ctx = SiteContext(
        site_id="site-fw-ap-model",
        site_name="Firmware AP Model",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "ap-model-1",
                "name": "AP Model 1",
                "type": "ap",
                "model": "AP45",
                "version": "0.12.27452",
            }
        ],
    )

    findings = FirmwareManagementCheck().run(ctx)

    assert len(findings) == 1
    assert findings[0].details["allowed_versions"] == ["0.13.30000"]


def test_firmware_management_check_normalizes_model_lookup(monkeypatch, tmp_path):
    standards_path = tmp_path / "standards.json"
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": "2025-01-01T00:00:00Z",
                "sources": {},
                "models": {
                    "switch": {
                        "EX4000-24T": [{"version": "24.4R2.25"}],
                    },
                    "ap": {},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    ctx = SiteContext(
        site_id="site-fw-model-normalized",
        site_name="Firmware Model Normalized",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-model-2",
                "name": "Switch Model 2",
                "type": "switch",
                "model": 'EX4000-24T"',
                "firmware_version": "24.4R2.25",
            }
        ],
    )

    assert FirmwareManagementCheck().run(ctx) == []


def test_firmware_management_check_skips_when_unconfigured(monkeypatch, tmp_path):
    standards_path = tmp_path / "empty-standards.json"
    _write_standard_versions(standards_path, switch_versions=[], ap_versions=[])
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards_path)

    ctx = SiteContext(
        site_id="site-fw-empty",
        site_name="Firmware Empty",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-empty", "name": "Switch Empty", "type": "switch", "firmware_version": "18.4R1"},
            {"id": "ap-empty", "name": "AP Empty", "type": "ap", "version": "12.0.0"},
        ],
    )

    check = FirmwareManagementCheck()
    assert check.run(ctx) == []


def test_firmware_management_check_prepare_run_reloads_dynamic_versions(monkeypatch):
    calls = {"switch": 0, "ap": 0}

    def _fake_load(device_type):
        calls[device_type] += 1
        if calls[device_type] == 1:
            return ()
        if device_type == "switch":
            return ("20.4R3-S4",)
        return ("0.12.27452",)

    monkeypatch.setattr(compliance, "_load_allowed_versions_from_standard_doc", _fake_load)

    check = FirmwareManagementCheck()
    assert check.allowed_switch_versions == ()
    assert check.allowed_ap_versions == ()

    check.prepare_run()

    assert check.allowed_switch_versions == ("20.4R3-S4",)
    assert check.allowed_ap_versions == ("0.12.27452",)


def test_cloud_management_check_flags_unmanaged_switch():
    ctx = SiteContext(
        site_id="site-cloud-1",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-1",
                "name": "SW-1",
                "type": "switch",
                "disable_auto_config": True,
            },
        ],
    )

    check = CloudManagementCheck()
    findings = check.run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert "locally managed" in finding.message
    assert finding.device_id == "sw-1"
    assert finding.details == {"disable_auto_config": True}
    assert finding.actions is not None
    assert len(finding.actions) == 1
    action = finding.actions[0]
    assert action["id"] == ENABLE_CLOUD_MANAGEMENT_ACTION_ID
    assert action["site_ids"] == ["site-cloud-1"]
    assert action["devices"] == [{"site_id": "site-cloud-1", "device_id": "sw-1"}]


def test_cloud_management_check_ignores_managed_switch():
    ctx = SiteContext(
        site_id="site-cloud-2",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-2",
                "name": "SW-2",
                "type": "switch",
                "disable_auto_config": False,
            },
        ],
    )

    check = CloudManagementCheck()
    assert check.run(ctx) == []


def test_cloud_management_check_ignores_non_switch_devices():
    ctx = SiteContext(
        site_id="site-cloud-3",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "ap-1",
                "name": "AP-1",
                "type": "ap",
                "disable_auto_config": True,
            },
        ],
    )

    check = CloudManagementCheck()
    assert check.run(ctx) == []


def test_switch_power_supply_health_flags_single_switch_failed_psu():
    ctx = SiteContext(
        site_id="site-psu-1",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-1",
                "name": "SW-1",
                "type": "switch",
                "psus": [
                    {"name": "PSU 0", "status": "ok", "description": "Present and healthy"},
                    {"name": "PSU 1", "status": "missing", "description": "Not inserted"},
                ],
            },
        ],
    )

    check = SwitchPowerSupplyHealthCheck()
    findings = check.run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.device_id == "sw-1"
    assert "PSU 1 status 'missing'" in finding.message
    assert finding.details == {
        "psu_issues": [
            {
                "name": "PSU 1",
                "status": "missing",
                "description": "Not inserted",
                "slot": None,
            }
        ]
    }


def test_switch_power_supply_health_flags_stack_with_slot_details():
    ctx = SiteContext(
        site_id="site-psu-2",
        site_name="HQ",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-stack-1",
                "name": "SW-STACK-1",
                "type": "switch",
                "psus": [
                    {"name": "PSU 0", "status": "ok", "description": "switch 0"},
                    {"name": "PSU 1", "status": "missing", "description": "switch 0"},
                    {"name": "PSU 0", "status": "ok", "description": "switch 1"},
                    {"name": "PSU 1", "status": "ok", "description": "switch 1"},
                ],
            },
        ],
    )

    check = SwitchPowerSupplyHealthCheck()
    findings = check.run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert "switch slot 0 PSU 1 status 'missing'" in finding.message
    assert finding.details == {
        "psu_issues": [
            {
                "name": "PSU 1",
                "status": "missing",
                "description": "switch 0",
                "slot": "0",
            }
        ]
    }


def test_switch_power_supply_health_passes_when_all_psus_ok():
    ctx = SiteContext(
        site_id="site-psu-3",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-2",
                "name": "SW-2",
                "type": "switch",
                "psus": [
                    {"name": "PSU 0", "status": "ok", "description": "Present and healthy"},
                    {"name": "PSU 1", "status": "ok", "description": "Present and healthy"},
                ],
            },
        ],
    )

    check = SwitchPowerSupplyHealthCheck()
    assert check.run(ctx) == []


def test_switch_power_supply_health_reads_psus_from_module_stat():
    ctx = SiteContext(
        site_id="site-psu-4",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-3",
                "name": "SW-3",
                "type": "switch",
                "module_stat": [
                    {
                        "_idx": 0,
                        "psus": [
                            {"name": "Power Supply 0", "status": "ok", "description": "JPSU-65W-AC"},
                            {"name": "Power Supply 1", "status": "absent", "description": ""},
                        ],
                    }
                ],
            },
        ],
    )

    check = SwitchPowerSupplyHealthCheck()
    findings = check.run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert "switch slot 0 Power Supply 1 status 'absent'" in finding.message
    assert finding.details == {
        "psu_issues": [
            {
                "name": "Power Supply 1",
                "status": "absent",
                "description": "",
                "slot": "0",
            }
        ]
    }


def test_switch_power_supply_health_reads_stacked_psus_from_module_stat():
    ctx = SiteContext(
        site_id="site-psu-5",
        site_name="HQ",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "sw-stack-2",
                "name": "SW-STACK-2",
                "type": "switch",
                "module_stat": [
                    {
                        "_idx": 0,
                        "psus": [
                            {"name": "Power Supply 0", "status": "ok", "description": "JPSU-920W-AC-AFO"},
                            {"name": "Power Supply 1", "status": "ok", "description": "JPSU-920W-AC-AFO"},
                        ],
                    },
                    {
                        "_idx": 2,
                        "psus": [
                            {"name": "Power Supply 0", "status": "ok", "description": "JPSU-920W-AC-AFO"},
                            {"name": "Power Supply 1", "status": "absent", "description": ""},
                        ],
                    },
                ],
            },
        ],
    )

    check = SwitchPowerSupplyHealthCheck()
    findings = check.run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert "switch slot 2 Power Supply 1 status 'absent'" in finding.message
    assert finding.details == {
        "psu_issues": [
            {
                "name": "Power Supply 1",
                "status": "absent",
                "description": "",
                "slot": "2",
            }
        ]
    }


def test_spare_switch_presence_flags_missing_spare():
    ctx = SiteContext(
        site_id="site-spare-1",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-1", "name": "SW-1", "type": "switch", "role": "distribution"},
            {"id": "sw-2", "name": "SW-2", "type": "switch", "role": "ACCESS"},
        ],
    )

    check = SpareSwitchPresenceCheck()
    findings = check.run(ctx)

    assert len(findings) == 1
    assert findings[0].device_id is None
    assert "role 'spare'" in findings[0].message
    assert findings[0].details == {"total_switches": 2, "spare_switches": 0}
    assert findings[0].actions is not None
    action = findings[0].actions[0]
    assert action["id"] == SET_SPARE_SWITCH_ROLE_ACTION_ID
    assert action["button_label"] == "1 Click Fix Now"
    assert action["metadata"]["require_switch_selection"] is True
    assert len(action["metadata"]["switch_options"]) == 2


def test_spare_switch_presence_allows_spare_role():
    ctx = SiteContext(
        site_id="site-spare-2",
        site_name="Branch",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-1", "name": "SW-1", "type": "switch", "role": "spare"},
            {"id": "ap-1", "name": "AP-1", "type": "ap", "role": "spare"},
        ],
    )

    check = SpareSwitchPresenceCheck()
    findings = check.run(ctx)

    assert findings == []


def test_configuration_overrides_check_includes_offline_devices():
    ctx = SiteContext(
        site_id="site-8",
        site_name="Offline Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.0.0.1"},
                    "port_config": {"ge-0/0/48": {"usage": "uplink_idf"}},
                },
            }
        ],
        devices=[
            {
                "id": "offline1",
                "name": "Offline Switch",
                "role": "DISTRIBUTION",
                "status": "offline",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.0.0.2"},
                    "port_config": {"ge-0/0/48": {"usage": "internet_only"}},
                },
                "config_override": {"foo": "baz"},
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    assert any(f.device_id == "offline1" and "differs" in f.message for f in findings)
    assert any(f.device_id == "offline1" and "override" in f.message.lower() for f in findings)


def test_configuration_overrides_check_flags_map_and_ip_exceptions():
    ctx = SiteContext(
        site_id="site-standard",
        site_name="Standard Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.2",
                        "gateway": "10.1.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "sw1",
                "name": "Switch One",
                "status": "connected",
                "type": "switch",
                "map_id": None,
                "st_ip_base": "10.1.0.0/24",
                "evpn_scope": "fabric",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.5",
                        "gateway": "10.1.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                        "dns": ["10.1.0.10"],
                    }
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    assert findings, "Expected configuration override findings to be reported"

    paths = {
        diff.get("path")
        for finding in findings
        for diff in (finding.details or {}).get("diffs", [])
    }

    assert "map_id" not in paths
    assert "st_ip_base" in paths
    assert "evpn_scope" in paths
    assert "ip_config.dns" in paths


def test_configuration_overrides_check_includes_dns_fix_action():
    ctx = SiteContext(
        site_id="site-dns",
        site_name="DNS Site",
        site={
            "variables": {
                "siteDNS": "dns.example.com",
                "hubDNSserver1": "10.10.10.1",
                "hubDNSserver2": "10.10.10.2",
            },
            "networktemplate_name": "Prod - Standard Template",
        },
        setting={},
        templates=[
            {
                "name": "Prod - Standard Template",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.2",
                        "gateway": "10.1.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "sw-dns",
                "name": "Switch DNS",
                "type": "switch",
                "template_id": DNS_OVERRIDE_PROD_TEMPLATE_IDS[0],
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.5",
                        "gateway": "10.1.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                        "dns": ["10.45.170.17", "10.48.178.1"],
                    }
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    device_findings = [f for f in findings if f.device_id == "sw-dns" and f.actions]
    assert device_findings, "Expected DNS override finding with remediation action"

    action = device_findings[0].actions[0]
    assert action["id"] == CLEAR_DNS_OVERRIDE_ACTION_ID
    assert action["devices"] == [{"site_id": "site-dns", "device_id": "sw-dns"}]
    assert action["metadata"]["dns_values"] == ["10.45.170.17", "10.48.178.1"]
    prechecks = action["metadata"].get("prechecks")
    expected_prechecks = {
        "can_run": True,
        "site_type": "production",
        "template_applied": True,
        "template_name": DNS_OVERRIDE_TEMPLATE_NAME,
        "allowed_template_names": [DNS_OVERRIDE_TEMPLATE_NAME],
        "allowed_template_ids": list(DNS_OVERRIDE_PROD_TEMPLATE_IDS),
        "device_template_id": DNS_OVERRIDE_PROD_TEMPLATE_IDS[0],
        "dns_variables_defined": True,
        "required_dns_variables": _expected_dns_labels(),
        "missing_dns_variables": [],
        "messages": [],
    }
    assert prechecks == expected_prechecks


def test_configuration_overrides_check_reports_prereq_status_when_missing():
    ctx = SiteContext(
        site_id="site-missing",
        site_name="Missing Prereqs",
        site={"variables": {"siteDNS": "dns.example.com"}},
        setting={},
        templates=[
            {
                "name": "Alternate Template",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.2",
                        "gateway": "10.1.0.1",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "sw-noaction",
                "name": "Switch No Action",
                "type": "switch",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.5",
                        "gateway": "10.1.0.1",
                        "netmask": "255.255.255.0",
                        "dns": ["10.45.170.17"],
                    }
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    device_findings = [f for f in findings if f.device_id == "sw-noaction"]
    assert device_findings, "Finding should still be reported"
    actions = [action for finding in device_findings for action in (finding.actions or [])]
    assert actions, "Expected remediation action even when prerequisites missing"
    prechecks = actions[0]["metadata"].get("prechecks")
    expected_prechecks = {
        "can_run": False,
        "site_type": "production",
        "template_applied": False,
        "template_name": DNS_OVERRIDE_TEMPLATE_NAME,
        "allowed_template_names": [DNS_OVERRIDE_TEMPLATE_NAME],
        "allowed_template_ids": list(DNS_OVERRIDE_PROD_TEMPLATE_IDS),
        "device_template_id": None,
        "dns_variables_defined": False,
        "required_dns_variables": _expected_dns_labels(),
        "missing_dns_variables": ["hubDNSserver1", "hubDNSserver2"],
        "messages": [
            "Apply 'Prod - Standard Template' template to this site.",
            "Define site DNS variables: hubDNSserver1, hubDNSserver2.",
        ],
    }
    assert prechecks == expected_prechecks


def test_configuration_overrides_check_allows_lab_template_precheck():
    ctx = SiteContext(
        site_id="site-lab",
        site_name="Automation Lab",
        site={
            "variables": {
                "siteDNS": "10.10.10.10",
                "hubDNSserver1": "10.10.10.11",
                "hubDNSserver2": "10.10.10.12",
            }
        },
        setting={},
        templates=[
            {
                "id": DNS_OVERRIDE_LAB_TEMPLATE_IDS[0],
                "name": DNS_OVERRIDE_LAB_TEMPLATE_NAME,
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.2.0.2",
                        "gateway": "10.2.0.1",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "lab-sw",
                "name": "Lab Switch",
                "type": "switch",
                "template_id": DNS_OVERRIDE_LAB_TEMPLATE_IDS[0],
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.2.0.5",
                        "gateway": "10.2.0.1",
                        "netmask": "255.255.255.0",
                        "dns": ["9.9.9.9"],
                    }
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    device_findings = [f for f in findings if f.device_id == "lab-sw" and f.actions]
    assert device_findings, "Expected remediation action for lab site"

    action = device_findings[0].actions[0]
    prechecks = action["metadata"].get("prechecks")
    assert prechecks["can_run"] is True
    assert prechecks["site_type"] == "lab"
    assert prechecks["template_applied"] is True
    assert DNS_OVERRIDE_LAB_TEMPLATE_NAME in prechecks["allowed_template_names"]
    assert DNS_OVERRIDE_TEMPLATE_NAME in prechecks["allowed_template_names"]
    expected_allowed_ids = sorted(set(DNS_OVERRIDE_LAB_TEMPLATE_IDS + DNS_OVERRIDE_PROD_TEMPLATE_IDS))
    assert sorted(prechecks["allowed_template_ids"]) == expected_allowed_ids
    assert prechecks["device_template_id"] == DNS_OVERRIDE_LAB_TEMPLATE_IDS[0]
    assert prechecks["dns_variables_defined"] is True
    assert prechecks["required_dns_variables"] == _expected_dns_labels()
    assert prechecks["missing_dns_variables"] == []
    assert prechecks["messages"] == []


def test_configuration_overrides_check_skips_vc_port_differences():
    ctx = SiteContext(
        site_id="site-10",
        site_name="VC Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.1.0.1"},
                    "port_config": {"ge-0/0/48": {"usage": "uplink_idf"}},
                },
            }
        ],
        devices=[
            {
                "id": "vc1",
                "name": "VC Stack",
                "role": "Access-VC-Star",
                "status": "connected",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.1.0.1"},
                    "port_config": {"ge-0/0/48": {"usage": "internet_only"}},
                },
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    assert not any(f.device_id == "vc1" and "differs" in f.message for f in findings)


def test_configuration_overrides_check_allows_wan_mgmt_and_oob_blocks():
    ctx = SiteContext(
        site_id="site-11",
        site_name="WAN Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "wan1",
                "name": "WAN Switch",
                "role": "WAN",
                "status": "connected",
                "map_id": "map-wan1",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "mgmt_ip_config": {
                        "type": "static",
                        "ip": "10.10.10.10",
                        "gateway": "10.10.10.1",
                        "netmask": "255.255.255.0",
                    },
                    "oob_ip_config": {
                        "type": "static",
                        "ip": "10.20.20.20",
                        "gateway": "10.20.20.1",
                        "netmask": "255.255.255.0",
                        "use_mgmt_vrf": True,
                        "use_mgmt_vrf_for_host_out": True,
                    },
                },
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    assert all(f.device_id != "wan1" for f in findings)


def test_configuration_overrides_check_flags_unexpected_wan_fields():
    ctx = SiteContext(
        site_id="site-12",
        site_name="WAN Site With Overrides",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "wan2",
                "name": "WAN Switch Overrides",
                "role": "wan",
                "status": "connected",
                "map_id": "map-wan2",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "mgmt_ip_config": {
                        "type": "static",
                        "ip": "10.10.10.10",
                        "gateway": "10.10.10.1",
                        "netmask": "255.255.255.0",
                    },
                    "dhcp_snooping": {"enabled": True},
                },
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    wan_findings = [f for f in findings if f.device_id == "wan2"]
    assert wan_findings, "WAN device with unexpected fields should be flagged"
    assert any(
        any("dhcp" in (diff.get("path") or "") for diff in (finding.details or {}).get("diffs", []))
        for finding in wan_findings
    )


def test_configuration_overrides_check_flags_invalid_wan_oob_config():
    ctx = SiteContext(
        site_id="site-12b",
        site_name="WAN Site Invalid OOB",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "wan3",
                "name": "WAN Switch Invalid",
                "role": "WAN",
                "status": "connected",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "oob_ip_config": {
                        "type": "dhcp",
                        "ip": "",
                        "gateway": None,
                        "netmask": "",
                        "use_mgmt_vrf": False,
                        "use_mgmt_vrf_for_host_out": False,
                    }
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    wan_findings = [f for f in findings if f.device_id == "wan3"]
    assert wan_findings, "WAN device with invalid OOB config should be flagged"
    diff_paths = {
        diff.get("path")
        for finding in wan_findings
        for diff in (finding.details or {}).get("diffs", [])
    }
    assert "oob_ip_config.type" in diff_paths
    assert "oob_ip_config.use_mgmt_vrf" in diff_paths
    assert "oob_ip_config.use_mgmt_vrf_for_host_out" in diff_paths



def test_configuration_overrides_check_flags_unexpected_wan_up_ports():
    ctx = SiteContext(
        site_id="site-12c",
        site_name="WAN Site Active Ports",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "wan4",
                "name": "WAN Switch Active Ports",
                "role": "wan",
                "status": "connected",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "oob_ip_config": {
                        "type": "static",
                        "ip": "10.20.20.20",
                        "gateway": "10.20.20.1",
                        "netmask": "255.255.255.0",
                        "use_mgmt_vrf": True,
                        "use_mgmt_vrf_for_host_out": True,
                    }
                },
                "if_stat": {
                    "ge-0/0/0.0": {"port_id": "ge-0/0/0", "up": True},
                    "ge-0/0/4.0": {"port_id": "ge-0/0/4", "up": True},
                    "xe-0/2/0.0": {"port_id": "xe-0/2/0", "up": True},
                    "lo0.0": {"port_id": "lo0", "up": True},
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    wan_findings = [f for f in findings if f.device_id == "wan4"]
    assert wan_findings, "WAN device with unexpected active ports should be flagged"

    if_stat_diffs = [
        diff
        for finding in wan_findings
        for diff in (finding.details or {}).get("diffs", [])
        if diff.get("path") == "if_stat"
    ]
    assert if_stat_diffs
    assert if_stat_diffs[0]["actual"] == ["xe-0/2/0"]


def test_configuration_overrides_check_allows_expected_wan_up_ports():
    ctx = SiteContext(
        site_id="site-12d",
        site_name="WAN Site Allowed Ports",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "wan5",
                "name": "WAN Switch Allowed Ports",
                "role": "WAN",
                "status": "connected",
                "switch_config": {
                    "oob_ip_config": {
                        "type": "static",
                        "ip": "10.20.20.20",
                        "gateway": "10.20.20.1",
                        "netmask": "255.255.255.0",
                        "use_mgmt_vrf": True,
                        "use_mgmt_vrf_for_host_out": True,
                    }
                },
                "if_stat": {
                    "ge-0/0/0.0": {"port_id": "ge-0/0/0", "up": True},
                    "mge-0/0/4.0": {"port_id": "mge-0/0/4", "up": True},
                    "ge-0/0/8.0": {"port_id": "ge-0/0/8", "up": True},
                    "ge-0/0/12.0": {"port_id": "ge-0/0/12", "up": True},
                    "ge-0/0/16.0": {"port_id": "ge-0/0/16", "up": True},
                    "lo0.0": {"port_id": "lo0", "up": True},
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    assert all(f.device_id != "wan5" for f in findings)

def test_device_naming_convention_enforces_pattern():
    ctx = SiteContext(
        site_id="site-9",
        site_name="Naming Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "good1", "name": "NAABCMDFAS1", "type": "switch", "status": "connected"},
            {"id": "spare", "name": "NAABCMDFSPARE", "type": "switch", "status": "connected"},
            {"id": "bad1", "name": "NaABCMDFAS2", "type": "switch", "status": "connected"},
            {"id": "bad2", "name": "NAABCIDFAS3", "type": "switch", "status": "connected"},
            {"id": "ignore1", "name": "ap-1", "type": "ap", "status": "connected"},
            {"id": "offline", "name": "NAABCIDF1CS4", "type": "switch", "status": "offline"},
        ],
    )
    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    ids = {f.device_id for f in findings}
    assert ids == {"bad1", "bad2", "ignore1"}
    for finding in findings:
        assert finding.details and "expected_pattern" in finding.details


def test_device_naming_convention_respects_custom_patterns():
    ctx = SiteContext(
        site_id="site-9b",
        site_name="Naming Site Custom",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "switch-ok", "name": "SW-1", "type": "switch", "status": "connected"},
            {"id": "switch-bad", "name": "NAABCMDFAS1", "type": "switch", "status": "connected"},
            {"id": "ap-ok", "name": "AP-1", "type": "ap", "status": "connected"},
            {"id": "ap-bad", "name": "bad-ap", "type": "ap", "status": "connected"},
        ],
    )
    check = DeviceNamingConventionCheck(switch_pattern=r"^SW-\d+$", ap_pattern=r"^AP-\d+$")
    findings = check.run(ctx)
    assert {(f.device_id, f.details.get("expected_pattern")) for f in findings} == {
        ("switch-bad", r"^SW-\d+$"),
        ("ap-bad", r"^AP-\d+$"),
    }


def test_device_naming_convention_provides_ap_fix_action():
    ctx = SiteContext(
        site_id="site-9c",
        site_name="Naming Site Actions",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "ap-1", "name": "BadAP", "type": "ap", "status": "connected"},
            {"id": "switch-1", "name": "NAABCMDFAS1", "type": "switch", "status": "connected"},
        ],
    )
    check = DeviceNamingConventionCheck()
    check.prepare_run()
    findings = check.run(ctx)
    assert {f.device_id for f in findings} == {"ap-1"}
    assert findings[0].actions, "Expected per-device action"
    action = findings[0].actions[0]
    assert action["id"] == AP_RENAME_ACTION_ID
    assert action["site_ids"] == ["site-9c"]
    assert action["devices"] == [{"site_id": "site-9c", "device_id": "ap-1"}]
    actions = check.suggest_actions([ctx], findings)
    assert actions == []


def test_device_naming_convention_detects_ap_switch_location_mismatch():
    ctx = SiteContext(
        site_id="site-9d",
        site_name="Naming Site Location",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-1", "name": "NACHIMDFAS1", "type": "switch", "status": "connected"},
            {
                "id": "ap-1",
                "name": "NACHIIDF1AP1",
                "type": "ap",
                "status": "connected",
                "stats": {"lldp_stats": [{"neighbor": {"system_name": "NACHIMDFAS1"}}]},
            },
        ],
    )
    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.device_id == "ap-1"
    assert "does not match uplink switch" in finding.message
    assert finding.details
    assert finding.details.get("neighbor") == "NACHIMDFAS1"
    mismatch_types = {item.get("type") for item in finding.details.get("mismatches", [])}
    assert mismatch_types == {"location"}
    assert finding.actions and finding.actions[0]["id"] == AP_RENAME_ACTION_ID


def test_device_naming_convention_detects_ap_switch_site_mismatch():
    ctx = SiteContext(
        site_id="site-9e",
        site_name="Naming Site Region",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-2", "name": "APZENIDF3AS4", "type": "switch", "status": "connected"},
            {
                "id": "ap-2",
                "name": "NACHIIDF1AP1",
                "type": "ap",
                "status": "connected",
                "stats": {"lldp_stats": [{"neighbor": {"system_name": "APZENIDF3AS4"}}]},
            },
        ],
    )
    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    finding = findings[0]
    mismatch_types = {item.get("type") for item in finding.details.get("mismatches", [])}
    assert mismatch_types == {"site", "location"}
    assert finding.details.get("neighbor") == "APZENIDF3AS4"


def test_device_naming_convention_allows_matching_ap_switch_alignment():
    ctx = SiteContext(
        site_id="site-9f",
        site_name="Naming Site Match",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-3", "name": "NACHIMDFAS1", "type": "switch", "status": "connected"},
            {
                "id": "ap-3",
                "name": "NACHIMDFAP7",
                "type": "ap",
                "status": "connected",
                "stats": {"lldp_stats": [{"neighbor": {"system_name": "NACHIMDFAS1"}}]},
            },
        ],
    )
    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    assert findings == []


def test_device_naming_convention_uses_nested_device_stats_for_neighbor():
    ctx = SiteContext(
        site_id="site-9g",
        site_name="Naming Device Stats",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-4", "name": "NACHIMDFAS1", "type": "switch", "status": "connected"},
            {
                "id": "ap-4",
                "name": "NACHIIDF1AP1",
                "type": "ap",
                "status": "connected",
                "device_stats": {
                    "lldp": {
                        "ports": [
                            {
                                "port_id": "eth0",
                                "neighbors": [
                                    {
                                        "system_name": "NACHIMDFAS1",
                                        "port_id": "ge-0/0/1",
                                    }
                                ],
                            }
                        ]
                    }
                },
            },
        ],
    )

    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    assert findings[0].device_id == "ap-4"
    assert findings[0].details.get("neighbor") == "NACHIMDFAS1"


def test_device_naming_convention_handles_uplink_neighbor_list():
    ctx = SiteContext(
        site_id="site-9h",
        site_name="Naming Uplink List",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "sw-5", "name": "NACHIIDF2AS1", "type": "switch", "status": "connected"},
            {
                "id": "ap-5",
                "name": "NACHIIDF1AP1",
                "type": "ap",
                "status": "connected",
                "stats": {
                    "uplink": {
                        "neighbors": [
                            {
                                "system_name": "NACHIIDF2AS1",
                                "port_id": "ge-0/0/2",
                            }
                        ]
                    }
                },
            },
        ],
    )

    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    assert findings[0].details.get("neighbor") == "NACHIIDF2AS1"


@pytest.mark.parametrize(
    "env_value",
    [
        'r"^SW-\\d+$"',
        '"^SW-\\d+$"',
        "'^SW-\\d+$'",
    ],
)
def test_env_pattern_loader_strips_wrappers(monkeypatch, env_value):
    monkeypatch.setenv("SWITCH_NAME_REGEX_PATTERN", env_value)
    from compliance import _load_pattern_from_env

    pattern = _load_pattern_from_env("SWITCH_NAME_REGEX_PATTERN", None)
    assert pattern is not None
    assert pattern.pattern == r"^SW-\d+$"
    assert pattern.fullmatch("SW-1")


def test_env_pattern_loader_handles_double_backslashes(monkeypatch):
    monkeypatch.setenv(
        "SWITCH_NAME_REGEX_PATTERN",
        r"^(NA|LA|EU|AP)[A-Z]{3}(?:MDFSPARE|MDF(AS|CS|WS)\\d+|IDF\\d+(AS|CS|WS)\\d+)$",
    )
    from compliance import _load_pattern_from_env

    pattern = _load_pattern_from_env("SWITCH_NAME_REGEX_PATTERN", None)
    assert pattern is not None
    assert pattern.fullmatch("NACHIMDFCS1")
    assert pattern.fullmatch("NACHIIDF1AS3")


def test_device_naming_convention_reports_sanitized_env_pattern(monkeypatch):
    monkeypatch.setenv("SWITCH_NAME_REGEX_PATTERN", 'r"^SW-\\d+$"')
    from compliance import _load_pattern_from_env, DeviceNamingConventionCheck, SiteContext

    pattern = _load_pattern_from_env("SWITCH_NAME_REGEX_PATTERN", None)
    assert pattern is not None

    ctx = SiteContext(
        site_id="site-env",
        site_name="Env Pattern",
        site={},
        setting={},
        templates=[],
        devices=[{"id": "bad", "name": "BAD", "type": "switch"}],
    )
    check = DeviceNamingConventionCheck(switch_pattern=pattern)
    findings = check.run(ctx)
    assert len(findings) == 1
    assert findings[0].details["expected_pattern"] == r"^SW-\d+$"


def test_device_documentation_reports_missing_items():
    ctx = SiteContext(
        site_id="site-10",
        site_name="Image Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "complete",
                "name": "NAABCMDFAS1",
                "type": "switch",
                "status": "connected",
                "map_id": "map-1",
                "images": ["img1", "img2"],
            },
            {
                "id": "no-images",
                "name": "NAABCMDFAS2",
                "type": "switch",
                "status": "connected",
                "map_id": "map-2",
                "pictures": ["img1"],
            },
            {
                "id": "no-map",
                "name": "NAABCIDF1AS3",
                "type": "switch",
                "status": "offline",
                "images": ["img1", "img2"],
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("no-images", "Required images not present (found 1 of 2)."),
        ("no-map", "Device not assigned to any floorplan."),
    }


def test_device_documentation_handles_numbered_urls():
    ctx = SiteContext(
        site_id="site-11",
        site_name="Camera Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "numbered",
                "name": "NAABCMDFAS5",
                "type": "switch",
                "status": "connected",
                "map_id": "map-5",
                "image1_url": "https://example.com/image1.jpg",
                "image2_url": " https://example.com/image2.jpg ",
            },
            {
                "id": "single-numbered",
                "name": "NAABCMDFAS6",
                "type": "switch",
                "status": "connected",
                "map_id": "map-6",
                "image1_url": "https://example.com/only.jpg",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert [f.device_id for f in findings] == ["single-numbered"]


def test_device_documentation_handles_nested_status_dicts():
    ctx = SiteContext(
        site_id="site-12",
        site_name="Nested Status",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "nested",
                "name": "NAABCMDFAS7",
                "type": "switch",
                "status": {"status": "connected", "uptime": 12345},
                "map_id": "map-7",
            },
            {
                "id": "offline-nested",
                "name": "NAABCMDFAS8",
                "type": "switch",
                "status": {"status": "offline"},
                "map_id": "map-8",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("nested", "Required images not present (found 0 of 2)."),
        ("offline-nested", "Required images not present (found 0 of 2)."),
    }




def test_device_documentation_handles_status_strings_with_suffix():
    ctx = SiteContext(
        site_id="site-13",
        site_name="Status Strings",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "suffix",
                "name": "NAABCMDFAS9",
                "type": "switch",
                "status": "Connected (wired)",
                "map_id": "map-9",
            },
            {
                "id": "offline-suffix",
                "name": "NAABCMDFAS10",
                "type": "switch",
                "status": "Disconnected",
                "map_id": "map-10",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("suffix", "Required images not present (found 0 of 2)."),
        ("offline-suffix", "Required images not present (found 0 of 2)."),
    }


def test_device_documentation_handles_deeply_nested_status_structures():
    ctx = SiteContext(
        site_id="site-14",
        site_name="Nested Structures",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "deep-nested",
                "name": "NAABCMDFAS11",
                "type": "switch",
                "status": {
                    "wired": {
                        "details": {"state": "Connected"},
                        "history": [
                            {"state": "offline"},
                            {"state": "connected"},
                        ],
                    }
                },
                "map_id": "map-11",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("deep-nested", "Required images not present (found 0 of 2)."),
    }


def test_device_documentation_respects_per_type_requirements():
    ctx = SiteContext(
        site_id="site-15",
        site_name="Mixed Types",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "switch-images",
                "name": "NAABCMDFAS12",
                "type": "switch",
                "map_id": "map-12",
                "images": ["img1", "img2"],
            },
            {
                "id": "ap-images",
                "name": "NAABCIDF1AP1",
                "type": "ap",
                "map_id": "map-13",
                "images": ["img1"],
            },
        ],
    )
    check = DeviceDocumentationCheck(switch_min_images=3, ap_min_images=1)
    findings = {(f.device_id, f.message) for f in check.run(ctx)}
    assert findings == {
        ("switch-images", "Required images not present (found 2 of 3)."),
    }


def test_site_audit_runner_summarizes_results():
    contexts = [
        SiteContext(
            site_id="site-5",
            site_name="Site 5",
            site={
                "variables": {
                    "hubradiusserver": "1.1.1.1",
                    "localradiusserver": "2.2.2.2",
                    "siteDNS": "dns.example.com",
                    "hubDNSserver1": "10.0.0.53",
                    "hubDNSserver2": "10.0.0.54",
                }
            },
            setting={},
            templates=[],
            devices=[{"id": "dev-1"}, {"id": "dev-2"}],
        ),
        SiteContext(
            site_id="site-6",
            site_name="Site 6",
            site={"variables": {"hubradiusserver": "1.1.1.1"}},
            setting={},
            templates=[],
            devices=[{"id": "dev-3"}],
        ),
    ]
    runner = SiteAuditRunner([RequiredSiteVariablesCheck()])
    result = runner.run(contexts)
    assert result["total_sites"] == 2
    assert result["total_devices"] == 3
    assert result["total_findings"] == 4
    assert result["total_quick_fix_issues"] == 0
    assert result["site_findings"] == {"site-5": 0, "site-6": 4}
    assert result["site_devices"] == {"site-5": 2, "site-6": 1}
    checks = result["checks"]
    assert len(checks) == 1
    check = checks[0]
    assert check["failing_sites"] == ["site-6"]
    assert check["passing_sites"] == 1
    assert check.get("actions") == []


def test_site_audit_runner_counts_quick_fix_findings():
    contexts = [
        SiteContext(
            site_id="site-quick-1",
            site_name="Quick 1",
            site={},
            setting={},
            templates=[],
            devices=[],
        ),
        SiteContext(
            site_id="site-quick-2",
            site_name="Quick 2",
            site={},
            setting={},
            templates=[],
            devices=[],
        ),
    ]

    class QuickFixCheck(ComplianceCheck):
        id = "quick-fix"
        name = "Quick fix"

        def run(self, context: SiteContext):
            return [
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    message="Auto-remediation available.",
                    actions=[
                        {
                            "id": "quick-fix-action",
                            "button_label": "1 Click Fix Now",
                        }
                    ],
                )
            ]

    runner = SiteAuditRunner([QuickFixCheck()])
    result = runner.run(contexts)

    assert result["total_findings"] == 2
    assert result["total_quick_fix_issues"] == 2


def test_site_audit_runner_categorizes_findings():
    contexts = [
        SiteContext(
            site_id="site-7",
            site_name="HQ",
            site={},
            setting={},
            templates=[],
            devices=[],
        )
    ]

    class CategorizedCheck(ComplianceCheck):
        id = "categorized"
        name = "Categorized check"

        def run(self, context: SiteContext):
            return [
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    message="Site-level issue",
                ),
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    device_id="dev-1",
                    device_name="Switch 1",
                    message="Device-level issue",
                ),
            ]

    runner = SiteAuditRunner([CategorizedCheck()])
    result = runner.run(contexts)
    checks = result["checks"]
    assert len(checks) == 1
    check = checks[0]
    assert len(check["findings"]) == 2
    assert [f["message"] for f in check["site_level_findings"]] == ["Site-level issue"]
    assert [f["device_id"] for f in check["device_level_findings"]] == ["dev-1"]
