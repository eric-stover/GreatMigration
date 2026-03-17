import importlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("SWITCH_TEMPLATE_ID", "template-1")
    app = importlib.reload(importlib.import_module("app"))
    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    return app


def test_fetch_site_context_merges_device_details(monkeypatch, app_module):
    now_ts = 1_700_000_000.0
    monkeypatch.setattr(app_module, "_current_timestamp", lambda: now_ts)

    calls: list[str] = []

    responses: Dict[str, Any] = {
        "/sites/site-1": {"id": "site-1", "name": "HQ"},
        "/sites/site-1/setting": {"variables": {}},
        "/sites/site-1/networktemplates": [],
        "/sites/site-1/devices": [
            {
                "id": "dev-2",
                "name": "AP 2",
                "status": "connected",
                "last_seen": now_ts - 300,
            },
            {
                "id": "dev-3",
                "name": "Switch 3",
                "status": "offline",
                "last_seen": now_ts - (20 * 24 * 60 * 60),
            },
        ],
        "/sites/site-1/devices?type=switch": [
            {
                "id": "dev-1",
                "name": "Switch 1",
                "status": "connected",
                "last_seen": now_ts - 120,
            },
        ],
        "/sites/site-1/stats/devices?type=switch&limit=1000": {
            "results": [
                {
                    "id": "dev-1",
                    "name": "Switch 1",
                    "version": "23.4R2-S4.11",
                    "last_seen": now_ts - 60,
                },
            ]
        },
        "/sites/site-1/stats/devices?type=ap&limit=1000": {
            "results": [
                {
                    "id": "dev-2",
                    "name": "AP 2",
                    "version": "0.12.27452",
                    "last_seen": now_ts - 240,
                },
            ]
        },
        "/sites/site-1/devices/dev-1": {
            "id": "dev-1",
            "status": {"state": "online"},
            "switch_config": {"vlans": [10]},
            "extra": "detail",
        },
        "/sites/site-1/stats/devices/dev-1?type=switch": {
            "if_stat": {
                "ge-0/0/0.0": {"port_id": "ge-0/0/0", "up": True}
            }
        },
        "/sites/site-1/devices/dev-2": None,
        "/sites/site-1/devices/dev-3": None,
        "/sites/site-1/switch_templates/template-1": {
            "id": "template-1",
            "switch_config": {"port_config": {"ge-0/0/1": {"usage": "end_user"}}},
        },
    }

    def fake_get(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        calls.append(path)
        return responses.get(path)

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get)

    context = app_module._fetch_site_context("https://example.com/api/v1", {"Authorization": "token"}, "site-1")

    assert {d.get("id") for d in context.devices} == {"dev-1", "dev-2"}

    devices_by_id = {d.get("id"): d for d in context.devices if d.get("id")}

    dev1 = devices_by_id["dev-1"]
    # Base fields remain, detail fields are merged, and structured statuses are preserved.
    assert dev1["name"] == "Switch 1"
    assert dev1["status"] == {"state": "online"}
    assert dev1["switch_config"] == {"vlans": [10]}
    assert dev1["extra"] == "detail"
    assert dev1["version"] == "23.4R2-S4.11"

    dev2 = devices_by_id["dev-2"]
    # Device without detail fallback retains base information.
    assert dev2["name"] == "AP 2"
    assert dev2["status"] == "connected"
    assert dev2["version"] == "0.12.27452"

    assert all(device.get("id") != "dev-3" for device in context.devices)

    assert "/sites/site-1/devices" in calls
    assert "/sites/site-1/devices?type=switch" in calls
    assert "/sites/site-1/stats/devices?type=switch&limit=1000" in calls
    assert "/sites/site-1/stats/devices?type=ap&limit=1000" in calls
    assert "/sites/site-1/devices/dev-1" in calls
    assert "/sites/site-1/stats/devices/dev-1?type=switch" in calls
    assert "/sites/site-1/devices/dev-2" in calls
    assert "/sites/site-1/switch_templates/template-1" in calls

    template_ids = {t.get("id") for t in context.templates if isinstance(t, dict)}
    assert "template-1" in template_ids


def test_fetch_site_context_filters_recent_last_seen(monkeypatch, app_module):
    now_ts = 1_700_000_000.0
    monkeypatch.setattr(app_module, "_current_timestamp", lambda: now_ts)

    recent_iso_value = datetime.fromtimestamp(now_ts - 600, tz=timezone.utc).isoformat()

    responses: Dict[str, Any] = {
        "/sites/site-1": {"id": "site-1", "name": "HQ"},
        "/sites/site-1/setting": {"variables": {}},
        "/sites/site-1/networktemplates": [],
        "/sites/site-1/devices": [
            {"id": "recent", "name": "Recent", "last_seen": now_ts - 90},
            {"id": "stale", "name": "Stale", "last_seen": now_ts - (15 * 24 * 60 * 60)},
            {"id": "missing", "name": "Missing"},
            {"id": "recent-iso", "name": "Recent ISO", "last_seen": recent_iso_value},
        ],
        "/sites/site-1/devices?type=switch": [
            {
                "id": "recent-ms",
                "name": "Recent Millis",
                "last_seen": (now_ts - 180) * 1000,
            }
        ],
        "/sites/site-1/stats/devices?type=switch&limit=1000": {
            "results": [
                {"id": "recent", "last_seen": now_ts - 60},
                {"id": "stale", "last_seen": now_ts - (20 * 24 * 60 * 60)},
                {"id": "missing", "status": "connected"},
                {"id": "recent-ms", "last_seen": (now_ts - 120) * 1000},
            ]
        },
        "/sites/site-1/stats/devices?type=ap&limit=1000": [],
        "/sites/site-1/devices/recent": None,
        "/sites/site-1/devices/stale": None,
        "/sites/site-1/devices/missing": None,
        "/sites/site-1/devices/recent-iso": None,
        "/sites/site-1/devices/recent-ms": None,
        "/sites/site-1/stats/devices/recent-ms?type=switch": {},
        "/sites/site-1/switch_templates/template-1": {"id": "template-1"},
    }

    def fake_get(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        return responses.get(path)

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get)

    context = app_module._fetch_site_context("https://example.com/api/v1", {"Authorization": "token"}, "site-1")

    device_ids = [device.get("id") for device in context.devices if device.get("id")]

    assert device_ids == ["recent", "recent-iso", "recent-ms"]


def test_build_temp_config_payload_groups_port_profiles(app_module):
    row = {
        "_temp_config_source": {
            "vlans": [
                {"id": 17, "name": "17"},
                {"id": 100, "name": "Data"},
                {"id": 120, "name": "Voice"},
            ],
            "interfaces": [],
        }
    }

    for idx in range(1, 17):
        row["_temp_config_source"]["interfaces"].append(
            {
                "mode": "access",
                "data_vlan": 17,
                "juniper_if": f"ge-0/0/{idx}",
                "name": f"Gig{idx}",
            }
        )

    for idx in range(17, 27):
        row["_temp_config_source"]["interfaces"].append(
            {
                "mode": "access",
                "data_vlan": 100,
                "voice_vlan": 120,
                "juniper_if": f"ge-0/0/{idx}",
                "name": f"Gig{idx}",
            }
        )

    payload = app_module._build_temp_config_payload(row)
    assert payload is not None

    usages = payload.get("port_usages")
    assert isinstance(usages, dict)
    assert len(usages) == 2
    assert all(isinstance(name, str) and name for name in usages)
    networks = {net.get("name"): net for net in payload.get("networks", []) if isinstance(net, dict)}
    for usage_payload in usages.values():
        port_network = usage_payload.get("port_network")
        assert isinstance(port_network, str)
        assert port_network in networks
    assert "port_config" not in payload
    assert "port_overrides" not in payload


def test_prepare_payload_excludes_port_overrides(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "_collect_candidate_org_ids", lambda *args, **kwargs: set())
    monkeypatch.setattr(app_module, "_load_site_template_networks", lambda *args, **kwargs: {})
    monkeypatch.setattr(app_module, "_collect_existing_vlan_details", lambda *args, **kwargs: (set(), []))
    monkeypatch.setattr(
        app_module,
        "_resolve_network_conflicts",
        lambda networks, profiles, usages, conflicts: (networks, profiles, usages, {}, []),
    )
    monkeypatch.setattr(
        app_module, "_merge_new_vlan_networks", lambda existing, new, vlan_ids: {}
    )

    class FakeResp:
        status_code = 200

        @staticmethod
        def json():
            return {}

    monkeypatch.setattr(app_module.requests, "get", lambda *args, **kwargs: FakeResp())

    payload = {
        "port_usages": [
            {"name": "temp1", "port_network": "data_vlan", "mode": "access"},
            {"name": "temp2", "port_network": "data_vlan", "mode": "access"},
        ],
        "port_overrides": [
            {"port_id": "ge-0/0/1", "usage": "temp1", "device_id": "dev-1"},
            {"port_id": "ge-0/0/1", "usage": "temp2", "device_id": "dev-2"},
        ]
    }

    request_body, warnings, rename_map = app_module._prepare_switch_port_profile_payload(
        "https://example.com/api/v1", "token", "site-1", payload
    )

    assert "switch" not in request_body
    assert "port_overrides" not in request_body
    assert "port_usages" in request_body
    assert warnings == []
    assert rename_map == {}


def test_apply_temp_config_payload_strips_port_assignments(monkeypatch, app_module):
    captured_payloads: list[Dict[str, Any]] = []

    def fake_prepare(base_url: str, token: str, site_id: str, payload: Dict[str, Any], **kwargs):
        captured_payloads.append(payload)
        return payload, [], {}

    monkeypatch.setattr(app_module, "_prepare_switch_port_profile_payload", fake_prepare)

    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_temp_config_source": {
            "vlans": [{"id": 10, "name": "Data"}],
            "interfaces": [
                {
                    "mode": "access",
                    "data_vlan": 10,
                    "juniper_if": "ge-0/0/1",
                    "name": "Gig1",
                }
            ],
        },
    }

    result = app_module._apply_temporary_config_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=True,
    )

    assert result["successes"] == 1
    preview_payload = result["payloads"][0]["payload"]

    assert captured_payloads
    assert "port_config" not in captured_payloads[0]
    assert "port_overrides" not in captured_payloads[0]
    assert "port_usages" in captured_payloads[0]
    assert "port_config" in preview_payload
    assert "port_overrides" not in preview_payload




def test_finalize_assignments_preview_preserves_site_and_device_payloads(monkeypatch, app_module):
    monkeypatch.setattr(
        app_module,
        "_prepare_switch_port_profile_payload",
        lambda *args, **kwargs: (kwargs.get("payload") if "payload" in kwargs else args[3], [], {}),
    )

    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_temp_config_source": {
            "vlans": [{"id": 10, "name": "Data"}],
            "interfaces": [
                {
                    "mode": "access",
                    "data_vlan": 10,
                    "juniper_if": "ge-0/0/1",
                    "name": "Gig1",
                }
            ],
        },
    }

    result = app_module._finalize_assignments_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=True,
    )

    assert result["ok"] is True
    assert result["skipped"] is True
    assert result["total"] == 1
    payloads = result.get("payloads") or []
    assert len(payloads) == 1
    record = payloads[0]
    assert record.get("site_id") == "site-1"
    assert record.get("device_payloads", {}).get("device-1", {}).get("port_config", {}).get("ge-0/0/1")


def test_finalize_assignments_live_pushes_site_and_device(monkeypatch, app_module):
    calls: list[Dict[str, Any]] = []

    def fake_site_override(base_url: str, token: str, site_id: str, payload: Dict[str, Any]):
        calls.append({"kind": "site", "site_id": site_id, "payload": payload})
        return {"ok": True, "status": 200, "response": {"ok": True}}

    def fake_put_device(base_url: str, token: str, site_id: str, device_id: str, payload: Dict[str, Any]):
        calls.append({"kind": "device", "site_id": site_id, "device_id": device_id, "payload": payload})
        return {"status": 200, "response": {"ok": True}}

    monkeypatch.setattr(app_module, "_configure_switch_port_profile_override", fake_site_override)
    monkeypatch.setattr(app_module, "_put_device_payload", fake_put_device)

    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_temp_config_source": {
            "vlans": [{"id": 10, "name": "Data"}],
            "interfaces": [
                {
                    "mode": "access",
                    "data_vlan": 10,
                    "juniper_if": "ge-0/0/1",
                    "name": "Gig1",
                }
            ],
        },
    }

    result = app_module._finalize_assignments_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=False,
    )

    assert result["ok"] is True
    assert result["successes"] == 1
    assert result["failures"] == []
    assert [c["kind"] for c in calls] == ["site", "device"]
    assert calls[1]["payload"].get("port_config", {}).get("ge-0/0/1")

def test_remove_temp_config_returns_preview_when_dry_run(monkeypatch, app_module):
    def fake_get(url: str, headers=None, timeout: int = 60):
        class Resp:
            status_code = 200

            def json(self):
                return {"switch": {}}

            text = ""

        return Resp()

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_site_deployment_payload": {"port_config": {"ge-0/0/1": {"usage": "end_user"}}},
    }

    monkeypatch.setattr(
        app_module,
        "_derive_port_config_from_port_profiles",
        lambda *args, **kwargs: {"ge-0/0/1": {"usage": "derived_user"}},
    )

    result = app_module._remove_temporary_config_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=True,
    )

    assert result["skipped"] is True
    assert result["total"] == 1
    payloads = result.get("payloads") or []
    assert len(payloads) == 1
    preview = payloads[0]["payload"]
    assert preview["cleanup_request"] == {
        "networks": {},
        "port_usages": {},
        "port_config": {},
        "port_overrides": [],
    }
    assert preview["push_request"]["port_config"]["ge-0/0/1"]["usage"] == "derived_user"


def test_remove_temp_config_wipes_and_pushes(monkeypatch, app_module):
    calls: list[Dict[str, Any]] = []

    def fake_get(url: str, headers: Dict[str, str], timeout: int = 60):
        calls.append({"url": url, "json": None})

        class Resp:
            status_code = 200

            def json(self):
                return {"switch": {}}

            text = ""

        return Resp()

    def fake_put(url: str, headers: Dict[str, str], json: Dict[str, Any], timeout: int = 60):
        calls.append({"url": url, "json": json})

        class Resp:
            status_code = 200

            def json(self):
                return {"ok": True}

            text = ""

        return Resp()

    monkeypatch.setattr(app_module.requests, "put", fake_put)
    monkeypatch.setattr(app_module.requests, "get", fake_get)
    monkeypatch.setattr(
        app_module,
        "_derive_port_config_from_port_profiles",
        lambda *args, **kwargs: {"ge-0/0/5": {"usage": "access"}},
    )

    final_payload = {"port_config": {"ge-0/0/5": {"usage": "access"}}}
    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_site_deployment_payload": final_payload,
    }

    result = app_module._remove_temporary_config_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=False,
    )

    assert result["ok"] is True
    assert result["successes"] == 1
    assert result["failures"] == []
    assert len(calls) == 3
    assert calls[0]["url"] == "https://example.com/api/v1/sites/site-1/setting"
    assert calls[1]["url"] == "https://example.com/api/v1/sites/site-1/setting"
    assert calls[1]["json"] == {
        "networks": {},
        "port_usages": {},
        "port_config": {},
        "port_overrides": [],
    }
    assert calls[2]["json"] == final_payload


def test_remove_temp_config_preserves_legacy_vlan(monkeypatch, app_module):
    calls: list[Dict[str, Any]] = []

    def fake_get(url: str, headers: Dict[str, str], timeout: int = 60):
        calls.append({"method": "get", "url": url})

        class Resp:
            status_code = 200

            def json(self):
                return {
                    "networks": {
                        "legacy_net": {"vlan_id": 501, "note": "keep"},
                        "temp_net": {"vlan_id": 200, "note": "drop"},
                    },
                    "switch": {
                        "port_usages": {
                            "legacy_profile": {"port_network": "legacy_net", "note": "keep"},
                            "temp_profile": {"port_network": "temp_net"},
                        },
                        "port_overrides": [
                            {"port_id": "1", "usage": "legacy_profile"},
                            {"port_id": "2", "usage": "temp_profile"},
                        ],
                    },
                }

            text = ""

        return Resp()

    def fake_put(url: str, headers: Dict[str, str], json: Dict[str, Any], timeout: int = 60):
        calls.append({"method": "put", "url": url, "json": json})

        class Resp:
            status_code = 200

            def json(self):
                return {"ok": True}

            text = ""

        return Resp()

    monkeypatch.setattr(app_module.requests, "get", fake_get)
    monkeypatch.setattr(app_module.requests, "put", fake_put)

    final_payload = {"port_config": {"ge-0/0/5": {"usage": "access"}}}
    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_site_deployment_payload": final_payload,
    }

    result = app_module._remove_temporary_config_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=False,
    )

    assert result["ok"] is True
    assert result["successes"] == 1
    assert result["failures"] == []
    assert [call.get("method") for call in calls] == ["get", "get", "put", "put"]
    cleanup = calls[2]["json"]
    assert cleanup["networks"] == {"legacy_net": {"vlan_id": 501, "note": "keep"}}
    assert cleanup.get("port_usages") == {
        "legacy_profile": {"port_network": "legacy_net", "note": "keep"}
    }
    assert cleanup.get("port_overrides") == [{"port_id": "1", "usage": "legacy_profile"}]


def test_cleanup_payload_preserves_legacy_usage_name(app_module):
    settings = {
        "networks": {
            "legacy_net": {"vlan_id": 10, "note": "keep"},
            "temp_net": {"vlan_id": 200, "note": "drop"},
        },
        "switch": {
            "port_config": {
                "ge-0/0/20": {"usage": "legacy_AUTO_ACCESS_V10_POE_EDGE"},
                "ge-0/0/21": {"usage": "legacy_AUTO_ACCESS_V200_POE_EDGE"},
            }
        },
    }

    cleanup = app_module._build_site_cleanup_payload_for_setting(
        settings,
        preserve_legacy_vlans=True,
        legacy_vlan_ids={10},
    )

    assert cleanup["networks"] == {"legacy_net": {"vlan_id": 10, "note": "keep"}}
    assert cleanup["port_config"] == {"ge-0/0/20": {"usage": "legacy_AUTO_ACCESS_V10_POE_EDGE"}}


def test_cleanup_payload_preserves_network_only_trunk_port_config(app_module):
    settings = {
        "networks": {
            "legacy_net": {"vlan_id": 10, "note": "keep"},
            "temp_net": {"vlan_id": 200, "note": "drop"},
        },
        "switch": {
            "port_config": {
                "ge-0/0/10": {
                    "mode": "trunk",
                    "native_network": "legacy_net",
                    "networks": ["legacy_net"],
                }
            }
        },
    }

    cleanup = app_module._build_site_cleanup_payload_for_setting(
        settings,
        preserve_legacy_vlans=True,
        legacy_vlan_ids={10},
    )

    assert cleanup["networks"] == {"legacy_net": {"vlan_id": 10, "note": "keep"}}
    assert cleanup["port_config"] == {
        "ge-0/0/10": {
            "mode": "trunk",
            "native_network": "legacy_net",
            "networks": ["legacy_net"],
        }
    }


def test_cleanup_payload_preserves_all_networks_trunk(app_module):
    settings = {
        "networks": {
            "legacy_net": {"vlan_id": 10, "note": "keep"},
            "temp_net": {"vlan_id": 200, "note": "drop"},
        },
        "switch": {
            "port_usages": {
                "legacy_TRUNK_ALL": {"mode": "trunk", "all_networks": True},
                "temp_profile": {"port_network": "temp_net"},
            }
        },
    }

    cleanup = app_module._build_site_cleanup_payload_for_setting(
        settings,
        preserve_legacy_vlans=True,
        legacy_vlan_ids={10},
    )

    assert cleanup["networks"] == {"legacy_net": {"vlan_id": 10, "note": "keep"}}
    assert cleanup.get("port_usages") == {"legacy_TRUNK_ALL": {"mode": "trunk", "all_networks": True}}




def test_resolve_interface_name_from_available_ports_supports_ge_mge(app_module):
    available = {"ge-0/0/9", "mge-0/0/7"}
    assert app_module._resolve_interface_name_from_available_ports("mge-0/0/9", available) == "ge-0/0/9"
    assert app_module._resolve_interface_name_from_available_ports("ge-0/0/7", available) == "mge-0/0/7"
    assert app_module._resolve_interface_name_from_available_ports("xe-0/2/1", available) is None


def test_derive_port_config_keeps_port_ids_without_model_normalization(monkeypatch, app_module):
    device_info = {
        "model": "EX4100-24MP",
        "port_config": {
            "mge-0/0/9": {"usage": "AUTO_ACCESS"},
            "mge-0/0/23": {"usage": "AUTO_ACCESS"},
            "xe-0/2/1": {"usage": "AUTO_UPLINK"},
        },
    }
    derived_settings = {
        "port_usages": {
            "AUTO_ACCESS": {"mode": "access"},
            "AUTO_UPLINK": {"mode": "trunk"},
        },
        "networks": {},
    }

    def fake_get_json(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        if path.endswith("/setting/derived"):
            return derived_settings
        return device_info

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get_json)
    monkeypatch.setattr(
        app_module.pm,
        "RULES_DOC",
        {"rules": [{"when": {"any": True}, "set": {"usage": "end_user"}}]},
    )

    derived = app_module._derive_port_config_from_port_profiles(
        "https://example.com/api/v1",
        "token",
        "site-1",
        "device-1",
    )

    assert derived["mge-0/0/9"]["usage"] == "end_user"
    assert derived["mge-0/0/23"]["usage"] == "end_user"
    assert derived["xe-0/2/1"]["usage"] == "end_user"


def test_derive_port_config_uses_model_hint_when_device_model_unknown(monkeypatch, app_module):
    device_info = {
        "model": "EX4100",
        "port_config": {
            "mge-0/0/9": {"usage": "AUTO_ACCESS"},
        },
    }
    derived_settings = {
        "port_usages": {
            "AUTO_ACCESS": {"mode": "access"},
        },
        "networks": {},
    }

    def fake_get_json(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        if path.endswith("/setting/derived"):
            return derived_settings
        return device_info

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get_json)
    monkeypatch.setattr(
        app_module.pm,
        "RULES_DOC",
        {"rules": [{"when": {"any": True}, "set": {"usage": "end_user"}}]},
    )

    derived = app_module._derive_port_config_from_port_profiles(
        "https://example.com/api/v1",
        "token",
        "site-1",
        "device-1",
        model_hint="EX4100-24MP",
    )

    assert derived["mge-0/0/9"]["usage"] == "end_user"




def test_candidate_device_model_keys_trims_suffixes(app_module):
    keys = app_module._candidate_device_model_keys("EX4100-48MP-VC")
    assert keys[0] == "EX4100-48MP-VC"
    assert "EX4100-48MP" in keys


def test_get_switch_physical_ports_for_model_handles_model_suffixes(monkeypatch, app_module):
    app_module._NETBOX_DEVICE_TYPE_URL_CACHE.clear()
    app_module._NETBOX_MODEL_PORT_CACHE.clear()

    class _Resp:
        def __init__(self, status_code: int, payload=None, text: str = ""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    def fake_get(url: str, timeout: int = 60):
        if url.endswith("/EX4100-48MP-VC.yaml"):
            return _Resp(404, payload={})
        if url.endswith("/EX4100-48MP.yaml"):
            return _Resp(
                200,
                text="""interfaces:
  - name: mge-0/0/0
  - name: ge-0/0/16
""",
            )
        return _Resp(404, payload={})

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    ports, err = app_module._get_switch_physical_ports_for_model_with_diagnostics("EX4100-48MP-VC")

    assert err is None
    assert ports == {"mge-0/0/0", "ge-0/0/16"}
def test_extract_physical_port_ids_from_devicetype_yaml(app_module):
    yaml_text = """
manufacturer: Juniper
model: EX4100-48MP
interfaces:
  - name: ge-0/0/0
    type: 1000base-t
  - name: ge-0/0/1
    type: 1000base-t
  - name: xe-0/2/0
    type: 10gbase-x-sfpp
console-ports:
  - name: con0
"""

    ports = app_module._extract_physical_port_ids_from_devicetype_yaml(yaml_text)

    assert ports == {"ge-0/0/0", "ge-0/0/1", "xe-0/2/0"}


def test_extract_physical_port_ids_from_if_stat_filters_non_physical(app_module):
    if_stat = {
        "irb.150": {"port_id": "irb", "up": True},
        "lo0.0": {"port_id": "lo0", "up": True},
        "ge-0/0/23.0": {"port_id": "ge-0/0/23", "up": False},
        "xe-0/2/0.0": {"port_id": "xe-0/2/0", "up": True},
        "mge-0/0/6.0": {"port_id": "mge-0/0/6", "up": False},
        "vme.0": {"port_id": "vme", "up": False},
    }

    ports = app_module._extract_physical_port_ids_from_if_stat(if_stat)

    assert ports == {"ge-0/0/23", "xe-0/2/0", "mge-0/0/6"}


def test_build_payload_for_row_filters_ports_not_present_in_if_stat(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "get_device_model", lambda *args, **kwargs: "EX4100-24MP")
    monkeypatch.setattr(app_module, "timestamp_str", lambda tz: "2026-01-01 00:00")

    monkeypatch.setattr(
        app_module,
        "_get_switch_physical_ports_for_model_with_diagnostics",
        lambda model: ({"ge-0/0/0", "ge-0/0/1"}, None),
    )

    result = app_module._build_payload_for_row(
        base_url="https://example.com/api/v1",
        tz="UTC",
        token="token",
        site_id="site-1",
        device_id="device-1",
        payload_in={
            "interfaces": [
                {"name": "ge-0/0/0", "juniper_if": "ge-0/0/0", "mode": "access", "description": "a"},
                {"name": "ge-0/0/1", "juniper_if": "ge-0/0/1", "mode": "access", "description": "b"},
                {"name": "ge-0/0/2", "juniper_if": "ge-0/0/2", "mode": "access", "description": "c"},
            ]
        },
        model_override=None,
        excludes=None,
        exclude_uplinks=False,
        member_offset=0,
        port_offset=0,
        normalize_modules=False,
        dry_run=True,
    )

    assert result["ok"] is True
    payload_port_config = result["payload"]["port_config"]
    assert set(payload_port_config.keys()) == {"ge-0/0/0", "ge-0/0/1"}
    warnings = result["validation"].get("warnings", [])
    assert any("not present in destination switch interface inventory" in w for w in warnings)


def test_build_payload_for_row_keeps_ports_when_ge_mge_prefix_differs(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "get_device_model", lambda *args, **kwargs: "EX4100")
    monkeypatch.setattr(app_module, "timestamp_str", lambda tz: "2026-01-01 00:00")

    monkeypatch.setattr(
        app_module,
        "_get_switch_physical_ports_for_model_with_diagnostics",
        lambda model: ({"ge-0/0/8", "ge-0/0/9"}, None),
    )

    result = app_module._build_payload_for_row(
        base_url="https://example.com/api/v1",
        tz="UTC",
        token="token",
        site_id="site-1",
        device_id="device-1",
        payload_in={
            "port_config": {
                "mge-0/0/8": {"usage": "end_user", "description": "a"},
                "mge-0/0/9": {"usage": "end_user", "description": "b"},
            }
        },
        model_override=None,
        excludes=None,
        exclude_uplinks=False,
        member_offset=0,
        port_offset=0,
        normalize_modules=False,
        dry_run=True,
    )

    payload_port_config = result["payload"]["port_config"]
    assert set(payload_port_config.keys()) == {"ge-0/0/8", "ge-0/0/9"}
    warnings = result["validation"].get("warnings", [])
    assert not any("not present in destination switch interface inventory" in w for w in warnings)





def test_build_payload_for_row_warns_when_inventory_unavailable(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "get_device_model", lambda *args, **kwargs: "EX4100-48MP")
    monkeypatch.setattr(app_module, "timestamp_str", lambda tz: "2026-01-01 00:00")
    monkeypatch.setattr(
        app_module,
        "_get_switch_physical_ports_for_model_with_diagnostics",
        lambda model: (None, "unable to load NetBox Juniper index"),
    )

    result = app_module._build_payload_for_row(
        base_url="https://example.com/api/v1",
        tz="UTC",
        token="token",
        site_id="site-1",
        device_id="device-1",
        payload_in={"port_config": {"ge-0/0/0": {"usage": "end_user"}}},
        model_override=None,
        excludes=None,
        exclude_uplinks=False,
        member_offset=0,
        port_offset=0,
        normalize_modules=False,
        dry_run=True,
    )

    warnings = result["validation"].get("warnings", [])
    assert any("Destination interface inventory unavailable" in w for w in warnings)
def test_build_payload_for_row_uses_source_interface_numbering_for_dynamic_mapping(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "get_device_model", lambda *args, **kwargs: "EX4100")
    monkeypatch.setattr(app_module, "timestamp_str", lambda tz: "2026-01-01 00:00")

    monkeypatch.setattr(
        app_module,
        "_get_switch_physical_ports_for_model_with_diagnostics",
        lambda model: ({"ge-0/0/0", "ge-0/0/23"}, None),
    )

    result = app_module._build_payload_for_row(
        base_url="https://example.com/api/v1",
        tz="UTC",
        token="token",
        site_id="site-1",
        device_id="device-1",
        payload_in={
            "interfaces": [
                {
                    "name": "GigabitEthernet1/0/1",
                    "juniper_if": "ge-0/0/10",
                    "mode": "access",
                    "description": "first",
                },
                {
                    "name": "GigabitEthernet1/0/24",
                    "juniper_if": "ge-0/0/11",
                    "mode": "access",
                    "description": "last",
                },
            ]
        },
        model_override=None,
        excludes=None,
        exclude_uplinks=False,
        member_offset=0,
        port_offset=0,
        normalize_modules=False,
        dry_run=True,
    )

    payload_port_config = result["payload"]["port_config"]
    assert set(payload_port_config.keys()) == {"ge-0/0/0", "ge-0/0/23"}
def test_derive_port_config_preserves_usage_names(monkeypatch, app_module):
    device_info = {
        "port_config": {
            "ge-0/0/20": {"usage": "legacy_AUTO_ACCESS_V10_POE_EDGE"},
            "ge-0/0/21": {"usage": "AUTO_ACCESS"},
        }
    }
    derived_settings = {
        "port_usages": {"AUTO_ACCESS": {"mode": "access"}},
        "networks": {},
    }

    def fake_get_json(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        if path.endswith("/setting/derived"):
            return derived_settings
        return device_info

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get_json)
    monkeypatch.setattr(
        app_module.pm,
        "RULES_DOC",
        {"rules": [{"when": {"any": True}, "set": {"usage": "end_user"}}]},
    )

    derived = app_module._derive_port_config_from_port_profiles(
        "https://example.com/api/v1",
        "token",
        "site-1",
        "device-1",
        preserve_usage_names={"legacy_AUTO_ACCESS_V10_POE_EDGE"},
    )

    assert derived["ge-0/0/20"]["usage"] == "legacy_AUTO_ACCESS_V10_POE_EDGE"
    assert derived["ge-0/0/21"]["usage"] == "end_user"





def test_derive_port_config_does_not_preserve_trunk_usage_names(monkeypatch, app_module):
    device_info = {
        "port_config": {
            "ge-0/0/20": {"usage": "legacy_AUTO_TRUNK_N4_POE"},
        }
    }
    derived_settings = {
        "port_usages": {
            "legacy_AUTO_TRUNK_N4_POE": {
                "mode": "trunk",
                "native_network": "corp",
                "networks": ["corp"],
            },
        },
        "networks": {"corp": {"vlan_id": 4}},
    }

    def fake_get_json(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        if path.endswith("/setting/derived"):
            return derived_settings
        return device_info

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get_json)
    monkeypatch.setattr(
        app_module.pm,
        "RULES_DOC",
        {"rules": [{"name": "to-ap", "when": {"mode": "trunk"}, "set": {"usage": "ap"}}]},
    )

    derived = app_module._derive_port_config_from_port_profiles(
        "https://example.com/api/v1",
        "token",
        "site-1",
        "device-1",
        preserve_usage_names={"legacy_AUTO_TRUNK_N4_POE"},
        include_decisions=True,
    )

    assert derived["port_config"]["ge-0/0/20"]["usage"] == "ap"
    decision = derived["decisions"][0]
    assert decision["preserved"] is False
    assert decision["matched_rule"] == "to-ap"

def test_derive_port_config_trunk_port_network_falls_back_to_native_vlan(monkeypatch, app_module):
    device_info = {
        "port_config": {
            "mge-0/0/15": {
                "usage": "legacy_AUTO_TRUNK_N3_POE",
                "description": "Access point -NASPRLWAP03",
            },
        }
    }
    derived_settings = {
        "port_usages": {
            "legacy_AUTO_TRUNK_N3_POE": {
                "mode": "trunk",
                "port_network": "legacy_data",
            },
        },
        "networks": {"legacy_data": {"vlan_id": 3}},
    }

    def fake_get_json(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        if path.endswith("/setting/derived"):
            return derived_settings
        return device_info

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get_json)
    monkeypatch.setattr(
        app_module.pm,
        "RULES_DOC",
        {
            "rules": [
                {"name": "ap-native-3", "when": {"mode": "trunk", "native_vlan": 3}, "set": {"usage": "ap"}},
                {"name": "catch-all-blackhole", "when": {"any": True}, "set": {"usage": "blackhole"}},
            ]
        },
    )

    derived = app_module._derive_port_config_from_port_profiles(
        "https://example.com/api/v1",
        "token",
        "site-1",
        "device-1",
        include_decisions=True,
    )

    assert derived["port_config"]["mge-0/0/15"]["usage"] == "ap"
    decision = derived["decisions"][0]
    assert decision["matched_rule"] == "ap-native-3"
    assert decision["interface"]["native_vlan"] == 3


def test_derive_port_config_returns_decisions_when_requested(monkeypatch, app_module):
    device_info = {
        "port_config": {
            "ge-0/0/1": {"usage": "legacy_keep"},
            "ge-0/0/2": {"usage": "AUTO_ACCESS"},
        }
    }
    derived_settings = {
        "port_usages": {
            "AUTO_ACCESS": {"mode": "access"},
        },
        "networks": {},
    }

    def fake_get_json(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        if path.endswith("/setting/derived"):
            return derived_settings
        return device_info

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get_json)
    monkeypatch.setattr(
        app_module.pm,
        "RULES_DOC",
        {"rules": [{"name": "default-user", "when": {"any": True}, "set": {"usage": "end_user"}}]},
    )

    derived = app_module._derive_port_config_from_port_profiles(
        "https://example.com/api/v1",
        "token",
        "site-1",
        "device-1",
        preserve_usage_names={"legacy_keep"},
        include_decisions=True,
    )

    assert derived["port_config"]["ge-0/0/1"]["usage"] == "legacy_keep"
    assert derived["port_config"]["ge-0/0/2"]["usage"] == "end_user"
    decisions = derived.get("decisions")
    assert isinstance(decisions, list)
    assert len(decisions) == 2
    assert any(d.get("preserved") is True and d.get("port_id") == "ge-0/0/1" for d in decisions)
    assert any(d.get("matched_rule") == "default-user" and d.get("port_id") == "ge-0/0/2" for d in decisions)

def test_load_site_history_parses_breakdown(tmp_path):
    from audit_history import load_site_history

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    log_contents = (
        "2025-10-13 08:05:38,905 | INFO | user=Eric Stover action=audit_run sites=2 devices=52 "
        "issues=52 errors=0 started=2025-10-13T08:05:30.074244 duration_ms=8831 "
        "site_issue_breakdown=West Chicago:51, Wahpeton:1 site_device_breakdown=West Chicago:30, Wahpeton:22\n"
    )
    (log_dir / "13102025.log").write_text(log_contents, encoding="utf-8")

    history = load_site_history(
        ["West Chicago", "Wahpeton", "Unknown"],
        now=datetime(2025, 10, 13, 12, 0, 0),
        log_dir=log_dir,
    )

    assert history["West Chicago"].issues_total == 51
    assert history["West Chicago"].devices_total == 30
    assert history["West Chicago"].run_count == 1
    assert history["West Chicago"].last_audit_at == datetime(2025, 10, 13, 8, 5, 38, 905000)
    assert len(history["West Chicago"].runs) == 1
    assert history["West Chicago"].runs[0].issues == 51
    assert history["West Chicago"].runs[0].devices == 30
    west_dict = history["West Chicago"].as_dict()
    assert west_dict["runs"][0]["issues"] == 51
    assert west_dict["runs"][0]["devices"] == 30
    assert history["Wahpeton"].issues_total == 1
    assert history["Unknown"].run_count == 0


def test_get_switch_physical_ports_for_model_uses_direct_model_yaml_lookup(monkeypatch, app_module):
    app_module._NETBOX_DEVICE_TYPE_URL_CACHE.clear()
    app_module._NETBOX_MODEL_PORT_CACHE.clear()

    class _Resp:
        def __init__(self, status_code: int, payload=None, text: str = ""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    calls: list[str] = []

    def fake_get(url: str, timeout: int = 60):
        calls.append(url)
        if url.endswith("/device-types/Juniper/EX4100-48MP.yaml"):
            return _Resp(
                200,
                text="""interfaces:
  - name: mge-0/0/0
  - name: ge-0/0/16
  - name: xe-0/2/0
console-ports:
  - name: con0
""",
            )
        if url == app_module.NETBOX_JUNIPER_DEVICETYPE_INDEX_URL:
            return _Resp(500, payload={})
        return _Resp(404, payload={})

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    ports, err = app_module._get_switch_physical_ports_for_model_with_diagnostics("EX4100-48MP")

    assert err is None
    assert ports == {"mge-0/0/0", "ge-0/0/16", "xe-0/2/0"}
    assert any(url.endswith("/device-types/Juniper/EX4100-48MP.yaml") for url in calls)
