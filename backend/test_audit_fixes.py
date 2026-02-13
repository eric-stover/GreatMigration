import pytest
import requests

from audit_actions import (
    AP_RENAME_ACTION_ID,
    CLEAR_DNS_OVERRIDE_ACTION_ID,
    ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
    SET_SITE_VARIABLES_ACTION_ID,
    SET_SPARE_SWITCH_ROLE_ACTION_ID,
)
from audit_fixes import execute_audit_action


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


def test_execute_action_rejects_unknown_action():
    with pytest.raises(ValueError):
        execute_audit_action("unknown", "https://example", "token", [])


def test_execute_action_skips_when_no_site_variable_defaults(monkeypatch):
    monkeypatch.setenv("MIST_SITE_VARIABLES", "localDNSserver")
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append(url)
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        SET_SITE_VARIABLES_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
    )

    summary = result["results"][0]
    assert summary["skipped"] == 1
    assert summary["updated"] == 0
    assert summary["failed"] == 0
    assert summary["errors"]
    assert calls["put"] == []


def test_execute_action_sets_site_variables(monkeypatch):
    monkeypatch.setenv("MIST_SITE_VARIABLES", "hubDNSserver1=10.1.1.1,hubDNSserver2=10.2.2.2,hubradiusserver=1.1.1.1")
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append(url)
        if url.endswith("/sites/site-1"):
            return DummyResponse(
                {
                    "name": "Site One",
                    "variables": {
                        "hubradiusserver": "",
                        "siteDNS": "existing",
                    },
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        SET_SITE_VARIABLES_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
    )

    summary = result["results"][0]
    assert summary["site_name"] == "Site One"
    assert summary["updated"] == 3
    assert summary["failed"] == 0
    assert summary["skipped"] == 0
    assert len(summary["changes"]) == 3
    put_url, payload = calls["put"][0]
    assert put_url.endswith("/sites/site-1")
    assert payload["variables"] == {
        "hubradiusserver": "1.1.1.1",
        "siteDNS": "existing",
        "hubDNSserver1": "10.1.1.1",
        "hubDNSserver2": "10.2.2.2",
    }


def test_execute_action_sets_requested_site_variable_only(monkeypatch):
    monkeypatch.setenv("MIST_SITE_VARIABLES", "hubDNSserver1=10.1.1.1,hubDNSserver2=10.2.2.2,hubradiusserver=1.1.1.1")
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append(url)
        if url.endswith("/sites/site-1"):
            return DummyResponse(
                {
                    "name": "Site One",
                    "variables": {
                        "hubradiusserver": "",
                        "siteDNS": "existing",
                    },
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        SET_SITE_VARIABLES_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        metadata={"variables": {"hubDNSserver1": "10.1.1.1"}},
    )

    summary = result["results"][0]
    assert summary["site_name"] == "Site One"
    assert summary["updated"] == 1
    assert summary["failed"] == 0
    assert summary["skipped"] == 0
    assert len(summary["changes"]) == 1
    put_url, payload = calls["put"][0]
    assert put_url.endswith("/sites/site-1")
    assert payload["variables"] == {
        "hubradiusserver": "",
        "siteDNS": "existing",
        "hubDNSserver1": "10.1.1.1",
    }


def test_execute_action_enables_cloud_management(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append(url)
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices/dev-1"):
            return DummyResponse(
                {
                    "id": "dev-1",
                    "name": "Switch 1",
                    "type": "switch",
                    "disable_auto_config": True,
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        device_map={"site-1": ["dev-1"]},
    )

    assert result["ok"] is True
    summary = result["results"][0]
    assert summary["site_name"] == "Site One"
    assert summary["updated"] == 1
    assert summary["failed"] == 0
    assert summary["skipped"] == 0
    change = summary["changes"][0]
    assert change["device_id"] == "dev-1"
    assert change["device_name"] == "Switch 1"
    assert change["status"] == "success"
    assert change["message"] == "Cloud management enabled."
    assert len(calls["put"]) == 1
    assert calls["put"][0][0].endswith("/devices/dev-1")
    assert calls["put"][0][1] == {"disable_auto_config": False}


def test_execute_action_renames_aps_in_dry_run(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append((url, params))
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices"):
            assert params == {"type": "ap"}
            return DummyResponse([
                {"id": "dev1", "mac": "AA:BB:CC", "name": "BadAP"},
                {"id": "dev2", "mac": "DD:EE:FF", "name": "NAABCIDF1AP1"},
            ])
        if url.endswith("/sites/site-1/stats/devices/dev1"):
            assert params == {"type": "ap"}
            return DummyResponse(
                {
                    "stats": {
                        "lldp_stats": [
                            {"neighbor": {"system_name": "NACHIIDF1AS1"}},
                        ]
                    }
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        raise AssertionError("rename should not be executed during dry run")

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        AP_RENAME_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=True,
    )

    assert result["ok"] is True
    totals = result["totals"]
    assert totals["renamed"] == 1
    assert totals["failed"] == 0
    assert totals["sites"] == 1
    summary = result["results"][0]
    assert summary["site_name"] == "Site One"
    assert summary["renamed"] == 1
    assert summary["changes"]
    preview_change = summary["changes"][0]
    assert preview_change["status"] == "preview"
    assert preview_change["message"].startswith("Would rename to ")
    # No live PUT requests should be attempted during dry run
    assert calls["put"] == []


def test_execute_action_targets_specific_device(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append((url, params))
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices"):
            return DummyResponse(
                [
                    {"id": "dev1", "mac": "AA:BB:CC", "name": "BadAP"},
                    {"id": "dev2", "mac": "DD:EE:FF", "name": "NALABIDF5AP2"},
                ]
            )
        if url.endswith("/sites/site-1/stats/devices/dev2"):
            assert params == {"type": "ap"}
            return DummyResponse(
                {
                    "stats": {
                        "lldp_stats": [
                            {"neighbor": {"system_name": "NACHIIDF1AS2"}},
                        ]
                    }
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        AP_RENAME_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        pause=0,
        device_map={"site-1": ["dev2"]},
    )

    assert result["ok"] is True
    summary = result["results"][0]
    assert summary["renamed"] == 1
    assert len(summary["changes"]) == 1
    change = summary["changes"][0]
    assert change["device_id"] == "dev2"
    assert change["old_name"] == "NALABIDF5AP2"
    assert change["new_name"] == "NACHIIDF1AP1"
    assert change["status"] == "success"
    assert change["message"] == "Success!"
    assert len(calls["put"]) == 1
    assert calls["put"][0][0].endswith("/devices/dev2")
    assert calls["put"][0][1] == {"name": "NACHIIDF1AP1"}


def test_execute_action_assigns_unique_suffixes(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append((url, params))
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices"):
            return DummyResponse(
                [
                    {"id": "dev1", "mac": "AA:BB:CC", "name": "BadAP"},
                    {"id": "dev2", "mac": "DD:EE:FF", "name": "AlsoBad"},
                    {"id": "dev3", "mac": "11:22:33", "name": "NACHIIDF9AP1"},
                ]
            )
        if url.endswith("/sites/site-1/stats/devices/dev1"):
            assert params == {"type": "ap"}
            return DummyResponse(
                {
                    "stats": {
                        "lldp_stats": [
                            {"neighbor": {"system_name": "NACHIIDF1AS1"}},
                        ]
                    }
                }
            )
        if url.endswith("/sites/site-1/stats/devices/dev2"):
            assert params == {"type": "ap"}
            return DummyResponse(
                {
                    "stats": {
                        "lldp_stats": [
                            {"neighbor": {"system_name": "NACHIIDF2AS3"}},
                        ]
                    }
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        AP_RENAME_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        pause=0,
    )

    assert result["ok"] is True
    summary = result["results"][0]
    assert summary["renamed"] == 2
    assert len(calls["put"]) == 2
    payloads = [payload for _, payload in calls["put"]]
    new_names = {payload.get("name") for payload in payloads}
    assert "NACHIIDF1AP2" in new_names
    assert "NACHIIDF2AP3" in new_names


def test_execute_action_reports_rename_failure(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append((url, params))
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices"):
            return DummyResponse(
                [
                    {"id": "dev1", "mac": "AA:BB:CC", "name": "NALABIDF5AP2"},
                ]
            )
        if url.endswith("/sites/site-1/stats/devices/dev1"):
            assert params == {"type": "ap"}
            return DummyResponse(
                {
                    "stats": {
                        "lldp_stats": [
                            {"neighbor": {"system_name": "NACHIIDF1AS2"}},
                        ]
                    }
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        raise requests.HTTPError("boom")

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        AP_RENAME_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        pause=0,
        device_map={"site-1": ["dev1"]},
    )

    assert result["ok"] is True
    summary = result["results"][0]
    assert summary["failed"] == 1
    assert summary["renamed"] == 0
    assert summary["changes"] == []
    assert len(summary["errors"]) == 1
    error = summary["errors"][0]
    assert error["reason"] == "Change Failed! Please see device logs"
    details = error.get("details") or {}
    assert details.get("attempted_name") == "NACHIIDF1AP1"
    assert "Rename failed" in (details.get("error") or "")

def test_execute_dns_override_action_updates_payload(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append(url)
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One", "networktemplate_name": "Prod - Standard Template"})
        if url.endswith("/sites/site-1/setting"):
            return DummyResponse(
                {
                    "variables": {
                        "siteDNS": "dns.example.com",
                        "hubDNSserver1": "10.1.1.1",
                        "hubDNSserver2": "10.1.1.2",
                    }
                }
            )
        if url.endswith("/sites/site-1/networktemplates"):
            return DummyResponse([
                {"name": "Prod - Standard Template"},
            ])
        if url.endswith("/sites/site-1/devices/device-1"):
            return DummyResponse(
                {
                    "id": "device-1",
                    "name": "Switch 1",
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.5",
                        "gateway": "10.0.0.1",
                        "dns": ["9.9.9.9"],
                        "static_config": {
                            "dns_servers": ["10.45.170.17", "10.48.178.1"],
                            "ntp": ["1.1.1.1"],
                        },
                    },
                    "switch_config": {
                        "ip_config": {
                            "dns_servers": ["10.45.170.17", "10.48.178.1"],
                            "other": "value",
                        }
                    },
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        CLEAR_DNS_OVERRIDE_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        device_map={"site-1": ["device-1"]},
    )

    assert result["ok"] is True
    totals = result["totals"]
    assert totals["updated"] == 1
    assert "summary" in totals
    assert len(calls["put"]) == 1
    put_url, put_payload = calls["put"][0]
    assert put_url.endswith("/devices/device-1")
    assert "dns" not in put_payload.get("ip_config", {})
    assert "dns_servers" not in put_payload.get("ip_config", {})
    static_config = put_payload.get("ip_config", {}).get("static_config")
    assert static_config == {
        "dns_servers": ["10.45.170.17", "10.48.178.1"],
        "ntp": ["1.1.1.1"],
    }
    assert "switch_config" not in put_payload
    assert result["results"][0]["changes"][0]["removed_dns"] == ["9.9.9.9"]


def test_execute_dns_override_action_handles_static_config_only(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append(url)
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One", "networktemplate_name": "Prod - Standard Template"})
        if url.endswith("/sites/site-1/setting"):
            return DummyResponse(
                {
                    "variables": {
                        "siteDNS": "dns.example.com",
                        "hubDNSserver1": "10.1.1.1",
                        "hubDNSserver2": "10.1.1.2",
                    }
                }
            )
        if url.endswith("/sites/site-1/networktemplates"):
            return DummyResponse([
                {"name": "Prod - Standard Template"},
            ])
        if url.endswith("/sites/site-1/devices/device-2"):
            return DummyResponse(
                {
                    "id": "device-2",
                    "name": "Switch 2",
                    "ip_config": {
                        "type": "static",
                        "static_config": {
                            "dns": ["4.4.4.4"],
                        },
                    },
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        CLEAR_DNS_OVERRIDE_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        device_map={"site-1": ["device-2"]},
    )

    assert result["ok"] is True
    assert calls["put"] == []
    site_summary = result["results"][0]
    assert site_summary["skipped"] == 1
    change = site_summary["changes"][0]
    assert change["device_id"] == "device-2"
    assert change["removed_dns"] == []


def test_execute_dns_override_action_checks_preconditions(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append(url)
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/setting"):
            return DummyResponse({"variables": {"siteDNS": "dns.example.com"}})
        if url.endswith("/sites/site-1/networktemplates"):
            return DummyResponse([])
        if url.endswith("/sites/site-1/devices/device-1"):
            return DummyResponse({"id": "device-1", "name": "Switch 1"})
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        CLEAR_DNS_OVERRIDE_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        device_map={"site-1": ["device-1"]},
    )

    assert result["ok"] is True
    totals = result["totals"]
    assert totals["updated"] == 0
    assert totals["failed"] >= 1
    assert calls["put"] == []
    site_summary = result["results"][0]
    assert site_summary["failed"] >= 1
    assert site_summary["errors"], "Expected error details when template missing"


def test_execute_action_sets_spare_switch_role_and_name(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append((url, params))
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices/sw-1"):
            return DummyResponse({"id": "sw-1", "type": "switch", "name": "NAABCIDF1XX1", "role": "access"})
        if url.endswith("/sites/site-1/stats/devices/sw-1"):
            assert params == {"type": "switch"}
            return DummyResponse({"stats": {"ports": [{"name": "ge-0/0/1", "status": "down"}]}})
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        SET_SPARE_SWITCH_ROLE_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        metadata={"selected_switch_id": "sw-1"},
    )

    assert result["ok"] is True
    summary = result["results"][0]
    assert summary["updated"] == 1
    assert summary["failed"] == 0
    assert summary["changes"][0]["status"] == "success"
    assert len(calls["put"]) == 2
    assert calls["put"][0][0].endswith("/sites/site-1/devices/sw-1")
    assert calls["put"][0][1] == {"port_config": {}}
    assert calls["put"][1][1] == {"role": "spare", "name": "NAABCMDFSPARE"}


def test_execute_action_blocks_spare_switch_in_use(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=None):
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices/sw-1"):
            return DummyResponse({"id": "sw-1", "type": "switch", "name": "NAABCIDF1AS1", "role": "access"})
        if url.endswith("/sites/site-1/stats/devices/sw-1"):
            assert params == {"type": "switch"}
            return DummyResponse({"stats": {"interfaces": [{"name": "xe-0/0/2", "up": True}]}})
        raise AssertionError(f"Unexpected GET {url}")

    put_calls = []

    def fake_put(url, headers=None, json=None, timeout=None):
        put_calls.append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        SET_SPARE_SWITCH_ROLE_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        metadata={"selected_switch_id": "sw-1"},
    )

    summary = result["results"][0]
    assert summary["updated"] == 0
    assert summary["failed"] == 1
    assert "Devices are currently connected" in summary["errors"][0]["reason"]
    assert put_calls == []


def test_execute_action_normalizes_spare_switch_name(monkeypatch):
    calls = {"put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices/sw-1"):
            return DummyResponse({"id": "sw-1", "type": "switch", "name": "NAWHPMDF_SPARE", "role": "access"})
        if url.endswith("/sites/site-1/stats/devices/sw-1"):
            assert params == {"type": "switch"}
            return DummyResponse({"stats": {"ports": [{"name": "ge-0/0/1", "status": "down"}]}})
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        SET_SPARE_SWITCH_ROLE_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        metadata={"selected_switch_id": "sw-1"},
    )

    assert result["ok"] is True
    summary = result["results"][0]
    assert summary["updated"] == 1
    assert summary["failed"] == 0
    assert len(calls["put"]) == 2
    assert calls["put"][1][1] == {"role": "spare", "name": "NAWHPMDFSPARE"}


def test_execute_action_allows_active_uplink_pic_interfaces(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=None):
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices/sw-1"):
            return DummyResponse({"id": "sw-1", "type": "switch", "name": "NAABCIDF1AS1", "role": "access"})
        if url.endswith("/sites/site-1/stats/devices/sw-1"):
            assert params == {"type": "switch"}
            return DummyResponse({"stats": {"interfaces": [{"name": "xe-0/1/2", "up": True}]}})
        raise AssertionError(f"Unexpected GET {url}")

    put_calls = []

    def fake_put(url, headers=None, json=None, timeout=None):
        put_calls.append((url, json))
        return DummyResponse({})

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        SET_SPARE_SWITCH_ROLE_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=False,
        metadata={"selected_switch_id": "sw-1"},
    )

    summary = result["results"][0]
    assert summary["updated"] == 1
    assert summary["failed"] == 0
    assert summary["changes"][0]["status"] == "success"
    assert len(put_calls) == 2
