from pathlib import Path


def test_preserve_legacy_vlan_checkbox_serialized():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")

    assert 'id="preserve_legacy_vlans"' in index_html
    assert "form.append('preserve_legacy_vlans'" in index_html


def test_lcm_step3_preview_button_states_serialized():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")

    assert "Preview Selected Automation" in index_html
    assert "Apply Configuration" in index_html
    assert "form.append('force_preview'" in index_html


def test_audit_check_level_map_includes_psu_health_as_device():
    audit_html = (Path(__file__).resolve().parent.parent / "templates" / "audit.html").read_text(encoding="utf-8")

    assert "switch_power_supply_health: 'device'" in audit_html
