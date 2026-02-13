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

    data = app.api_standards_table()

    assert data["ok"] is True
    assert data["table"]["rows"] == []
    assert len(data["table"]["columns"]) == 6
