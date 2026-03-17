from convertciscotojson import parse_show_power_inline


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
