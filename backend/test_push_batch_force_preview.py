from pathlib import Path


def test_push_batch_force_preview_flag_supported():
    app_py = (Path(__file__).resolve().parent / "app.py").read_text(encoding="utf-8")

    assert "force_preview: bool = Form(False)" in app_py
    assert "preview_only = force_preview or not (" in app_py
