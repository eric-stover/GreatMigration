from ciscoconfparse import CiscoConfParse

from convertciscotojson import infer_member_models, parse_show_power_inline


def test_parse_show_power_inline_extracts_power_draw():
    text = """
Interface Admin  Oper       Power   Device              Class Max
                            (Watts)
--------- ------ ---------- ------- ------------------- ----- ----
Gi1/0/9   auto   on         15.4    Ieee PD             4     30.0
Gi1/0/10  auto   off        0.0     n/a                 n/a   30.0
"""
    parsed = parse_show_power_inline(text)

    assert parsed["gi1/0/9"] == 15.4
    assert parsed["gi1/0/10"] == 0.0


def test_infer_member_models_treats_gi_1_0_28_as_24mp():
    conf = CiscoConfParse([
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        "interface GigabitEthernet1/0/24",
        " switchport mode access",
        "interface GigabitEthernet1/0/28",
        " switchport mode trunk",
    ])

    models = infer_member_models(conf, uplink_module=1)

    assert models[1] == "observed-max-port:28"


def test_infer_member_models_classifies_high_access_ports_as_48mp():
    conf = CiscoConfParse([
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        "interface GigabitEthernet1/0/47",
        " switchport mode access",
        "interface GigabitEthernet1/0/52",
        " switchport mode trunk",
    ])

    models = infer_member_models(conf, uplink_module=1)

    assert models[1] == "observed-max-port:52"
