import importlib
import json
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def test_build_standards_table_payload_limits_and_pads(monkeypatch, tmp_path):
    app = importlib.reload(importlib.import_module("app"))

    standards_path = tmp_path / "standard_fw_versions.json"
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-01-02T03:04:05Z",
                "models": {
                    "switch": {
                        "EX4400-48P": [
                            {"version": "24.4R2.10"},
                            {"version": "24.2R1.8"},
                            {"version": "23.4R2"},
                            {"version": "23.2R1"},
                            {"version": "22.4R3"},
                            {"version": "22.3R2"},
                            {"version": "22.2R1"},
                        ]
                    },
                    "ap": {"AP32": [{"version": "0.14.12345"}]},
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(app, "_firmware_standards_path", lambda: standards_path)

    payload = app._build_standards_table_payload()

    assert payload["columns"] == [
        "Standard 1",
        "Standard 2",
        "Standard 3",
        "Standard 4",
        "Standard 5",
        "Standard 6",
    ]
    assert payload["generated_at"] == "2026-01-02T03:04:05Z"
    assert payload["rows"][0]["model"] == "AP32"
    assert payload["rows"][0]["device_type"] == "AP"
    assert payload["rows"][0]["standards"] == ["0.14.12345", "", "", "", "", ""]
    assert payload["rows"][1]["model"] == "EX4400-48P"
    assert payload["rows"][1]["standards"] == [
        "24.4R2.10",
        "24.2R1.8",
        "23.4R2",
        "23.2R1",
        "22.4R3",
        "22.3R2",
    ]


def test_api_standards_table_ok_shape(monkeypatch, tmp_path):
    app = importlib.reload(importlib.import_module("app"))

    standards_path = tmp_path / "standard_fw_versions.json"
    standards_path.write_text('{"generated_at": null, "models": {"switch": {}, "ap": {}}}', encoding="utf-8")
    monkeypatch.setattr(app, "_firmware_standards_path", lambda: standards_path)

    # Mock the refresh call so it doesn't trigger a real network fetch
    monkeypatch.setattr(app, "_refresh_firmware_standards_if_needed", lambda path: None)

    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    monkeypatch.setattr(app, "_discover_org_ids", lambda base_url, headers: ["org-1"])
    monkeypatch.setattr(
        app,
        "_mist_get_json",
        lambda base_url, headers, path, optional=False: {"results": [{"model": "EX4400-48P", "count": 10}]},
    )

    data = app.api_standards_table()

    assert data["ok"] is True
    assert data["table"]["rows"] == []
    assert len(data["table"]["columns"]) == 6




def test_api_standards_table_triggers_refresh_before_read(monkeypatch, tmp_path):
    app = importlib.reload(importlib.import_module("app"))

    standards_path = tmp_path / "standard_fw_versions.json"
    standards_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(app, "_firmware_standards_path", lambda: standards_path)

    calls = {}

    def _fake_refresh(path):
        calls["path"] = path
        standards_path.write_text(
            json.dumps(
                {
                    "generated_at": "2026-01-02T03:04:05Z",
                    "models": {"switch": {"EX4400-48P": [{"version": "24.4R2.10"}]}, "ap": {}},
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(app, "_refresh_firmware_standards_if_needed", _fake_refresh)
    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    monkeypatch.setattr(app, "_discover_org_ids", lambda base_url, headers: ["org-1"])
    monkeypatch.setattr(
        app,
        "_mist_get_json",
        lambda base_url, headers, path, optional=False: {"results": [{"model": "EX4400-48P", "count": 10}]},
    )

    data = app.api_standards_table()

    assert calls["path"] == standards_path
    assert [row["model"] for row in data["table"]["rows"]] == ["EX4400-48P"]

def test_api_standards_table_filters_rows_to_production_models(monkeypatch, tmp_path):
    app = importlib.reload(importlib.import_module("app"))

    standards_path = tmp_path / "standard_fw_versions.json"
    standards_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-01-02T03:04:05Z",
                "models": {
                    "switch": {"EX4400-48P": [{"version": "24.4R2.10"}]},
                    "ap": {"AP32": [{"version": "0.14.12345"}]},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "_firmware_standards_path", lambda: standards_path)
    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    monkeypatch.setattr(app, "_discover_org_ids", lambda base_url, headers: ["org-1"])
    monkeypatch.setattr(
        app,
        "_mist_get_json",
        lambda base_url, headers, path, optional=False: {"results": [{"model": "AP32", "count": 4}]},
    )

    data = app.api_standards_table()

    assert data["ok"] is True
    assert [row["model"] for row in data["table"]["rows"]] == ["AP32"]


def test_fetch_production_models_uses_inventory_count_endpoint(monkeypatch):
    app = importlib.reload(importlib.import_module("app"))

    captured = {}

    def fake_get(base_url, headers, path, optional=False):
        captured["path"] = path
        return {"results": [{"model": "AP32", "count": 4}]}

    monkeypatch.setattr(app, "_mist_get_json", fake_get)

    models = app._fetch_production_models("https://api.ac2.mist.com/api/v1", {"Authorization": "Token t"}, "org-1")

    assert models == {"ap32"}
    assert captured["path"] == "/orgs/org-1/inventory/count?distinct=model&limit=1000"
