#!/usr/bin/env python3
"""
push_mist_port_config.py

Build/normalize a Mist switch port_config and (optionally) push it.

Key features:
- Cisco -> Juniper interface mapping:
    * 3-part names (Gi<SW>/<MOD>/<PORT>): trust module
        - MOD 0 => PIC 0 (front panel), PORT 1..48 -> /0/<PORT-1>
        - MOD 1 => PIC 2 (uplinks),     PORT 1..4  -> /2/<PORT-1>   (uplink type xe on EX4100)
        - member = SW - 1
    * 2-part names (Gi<SW>/<PORT>): fallback
        - 1..48 => PIC 0; 49..52 => PIC 2 (uplinks)
        - member = SW - 1
- Per-row member offset remap (shifts <member>), optional normalization
- Rules engine (first match wins) with your one-liner rules
- Capacity validator by model (blocks live push, warns in dry-run)
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


class PortConfigError(Exception):
    """Raised when building or validating Mist port configuration."""

# -------------------------------
# Defaults
# -------------------------------
API_TOKEN = ""  # prefer env var MIST_TOKEN
BASE_URL  = "https://api.mist.com/api/v1"
TZ        = "America/New_York"

# -------------------------------
# Rules (first match wins) — kept compact & readable
# -------------------------------
RULES_PATH = Path(__file__).with_name("port_rules.json")
RULES_LOCAL_PATH = Path(__file__).with_name("port_rules.local.json")
RULES_SAMPLE_PATH = Path(__file__).with_name("port_rules.sample.json")


def load_rules(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load rule document from JSON file."""
    candidates = [path] if path is not None else [RULES_LOCAL_PATH, RULES_PATH, RULES_SAMPLE_PATH]
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            with candidate.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            continue
    return {"rules": []}


RULES_DOC: Dict[str, Any] = load_rules()

def validate_rules_doc(doc: Dict[str, Any]) -> None:
    """Validate structure and field types for a rules document.

    Raises ValueError with a descriptive message on problems.
    """
    if not isinstance(doc, dict):
        raise ValueError("Rules document must be a JSON object")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise ValueError("Rules document missing 'rules' list")

    allowed_when = {
        "mode",
        "data_vlan",
        "data_vlan_in",
        "voice_vlan",
        "native_vlan",
        "allowed_vlans",
        "poe_active",
        "has_voice",
        "description_regex",
        "name_regex",
        "juniper_if_regex",
        "any",
    }
    allowed_set = {"usage"}

    for idx, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule {idx} is not an object")
        when = rule.get("when", {})
        if not isinstance(when, dict):
            raise ValueError(f"Rule {idx} 'when' must be an object")
        for k, v in when.items():
            if k not in allowed_when:
                raise ValueError(f"Rule {idx} uses unknown condition '{k}'")
            if k.endswith("_vlan"):
                try:
                    int(v)
                except Exception:
                    raise ValueError(f"Rule {idx} condition '{k}' must be an integer")
            if k == "data_vlan_in":
                if not isinstance(v, (list, tuple, set)):
                    raise ValueError("data_vlan_in condition must be a list of VLAN IDs")
                for item in v:
                    try:
                        int(item)
                    except Exception:
                        raise ValueError("data_vlan_in values must be integers")
            if k == "allowed_vlans":
                if not isinstance(v, (list, tuple, set, str)):
                    raise ValueError("allowed_vlans conditions must be a list or comma string")
            if k == "description_regex":
                try:
                    re.compile(str(v))
                except re.error as e:
                    raise ValueError(f"Rule {idx} has invalid regex: {e}")
            if k in {"name_regex", "juniper_if_regex"}:
                try:
                    re.compile(str(v))
                except re.error as e:
                    raise ValueError(f"Rule {idx} has invalid regex: {e}")
            if k == "has_voice" and not isinstance(v, bool):
                raise ValueError("has_voice condition must be boolean")
            if k == "poe_active" and not isinstance(v, bool):
                raise ValueError("poe_active condition must be boolean")
            if k == "any" and not isinstance(v, bool):
                raise ValueError("any condition must be boolean")
        setp = rule.get("set", {})
        if not isinstance(setp, dict):
            raise ValueError(f"Rule {idx} 'set' must be an object")
        for k in setp:
            if k not in allowed_set:
                raise ValueError(f"Rule {idx} has unknown action '{k}'")

BLACKLIST_PATTERNS = [
    r"^\s*$", r"^\s*vla?n?\s*\d+\s*$", r"^\s*(data|voice)\s*(port)?\s*$",
    r"^\s*end\s*user\s*$", r"^\s*user\s*$", r".*\bdata\s*vla?n?\b.*",
    r".*\bvoice\s*vla?n?\b.*", r".*\b(auto\s*qos|portfast|service-?policy)\b.*",
]

def _norm_desc(s: str) -> str:
    s = re.sub(r"\s+", " ", s or "")
    return s.strip(" -_.,;")

def filter_description_blacklist(raw: str) -> str:
    d = _norm_desc(raw)
    low = d.lower()
    for p in BLACKLIST_PATTERNS:
        if re.search(p, low):
            return ""
    return d

def load_token() -> str:
    tok = (API_TOKEN or "").strip() or (os.getenv("MIST_TOKEN") or "").strip()
    if not tok:
        raise PortConfigError("Missing API token: set env var MIST_TOKEN (preferred) or edit API_TOKEN.")
    return tok

def timestamp_str(tz_name: str) -> str:
    if ZoneInfo is not None:
        try:
            now = datetime.now(ZoneInfo(tz_name))
        except Exception:
            now = datetime.now()
    else:
        now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M")

def tag_description(desc: str, ts: str) -> str:
    d = (desc or "").strip()
    return f"{d} - converted by API {ts}" if d else f"converted by API {ts}"

def _match_regex(val: Optional[str], pattern: str) -> bool:
    if val is None:
        return False
    return re.search(pattern, val) is not None

def _normalize_vlan_list(v) -> List[int]:
    if v is None:
        return []
    if isinstance(v, list):
        out: List[int] = []
        for x in v:
            try: out.append(int(x))
            except Exception: pass
        return out
    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",") if p.strip()]
        out = []
        for p in parts:
            try: out.append(int(p))
            except Exception: pass
        return out
    return []

def evaluate_rule(when: Dict[str, Any], intf: Dict[str, Any]) -> bool:
    if not when or when.get("any") is True:
        return True
    mode = (intf.get("mode") or "").lower()
    data_vlan   = int(intf["data_vlan"])   if intf.get("data_vlan")   is not None else None
    if mode == "access" and data_vlan is None:
        # Cisco access interfaces default to VLAN 1 when no explicit
        # `switchport access vlan` statement exists.
        data_vlan = 1
    voice_vlan  = int(intf["voice_vlan"])  if intf.get("voice_vlan")  is not None else None
    native_vlan = int(intf["native_vlan"]) if intf.get("native_vlan") is not None else None
    allowed_vlans_set  = set(_normalize_vlan_list(intf.get("allowed_vlans")))
    poe_active = intf.get("poe_active")
    if poe_active is None:
        poe_on = intf.get("poe_on")
        if isinstance(poe_on, bool):
            poe_active = poe_on
        else:
            power_draw = intf.get("power_draw")
            try:
                poe_active = float(power_draw) > 0.0
            except (TypeError, ValueError):
                poe_active = False
    else:
        poe_active = bool(poe_active)
    name       = intf.get("name") or ""
    juniper_if = intf.get("juniper_if") or ""
    port_network = intf.get("port_network")
    voip_network = intf.get("voip_network")
    native_network = intf.get("native_network")
    networks_value = intf.get("networks") or intf.get("dynamic_vlan_networks") or []
    networks_set = set(str(v) for v in networks_value if str(v))

    for k, v in when.items():
        if k == "mode":
            if mode != str(v).lower(): return False
        elif k == "data_vlan":
            if data_vlan != int(v): return False
        elif k == "data_vlan_in":
            if data_vlan not in set(int(x) for x in v): return False
        elif k == "voice_vlan":
            if voice_vlan != int(v): return False
        elif k == "native_vlan":
            if native_vlan != int(v): return False
        elif k == "allowed_vlans":
            if allowed_vlans_set != set(_normalize_vlan_list(v)): return False
        elif k == "poe_active":
            if bool(poe_active) != bool(v): return False
        elif k == "has_voice":
            if bool(voice_vlan) != bool(v): return False
        elif k == "description_regex":
            if not _match_regex(intf.get("description") or "", v): return False
        elif k == "name_regex":
            if not _match_regex(name, v): return False
        elif k == "juniper_if_regex":
            if not _match_regex(juniper_if, v): return False
        elif k == "port_network":
            if str(port_network or "") != str(v): return False
        elif k == "voip_network":
            if str(voip_network or "") != str(v): return False
        elif k == "native_network":
            if str(native_network or "") != str(v): return False
        elif k == "networks_contains":
            if str(v) not in networks_set: return False
        elif k == "networks_equals":
            if networks_set != set(str(x) for x in (v or [])): return False
        elif k == "any":
            pass
        else:
            return False
    return True

# -------------------------------
# Cisco parsing / mapping
# -------------------------------
CISCO_2OR3_RE = re.compile(
    r'(?ix)^(?:ten|tengig|te|gi|gigabitethernet|fa|fastethernet)\s*'
    r'(?P<sw>\d+)\s*/\s*(?:(?P<mod>\d+)\s*/\s*)?(?P<port>\d+)$'
)

def cisco_split(name: str) -> Optional[Dict[str, int]]:
    n = (name or "").replace("Ethernet", "ethernet").strip()
    m = CISCO_2OR3_RE.match(n)
    if not m:
        return None
    sw = int(m.group("sw"))
    mod = int(m.group("mod")) if m.group("mod") is not None else 0
    port = int(m.group("port"))
    return {"sw": sw, "mod": mod, "port": port}

def cisco_to_index(name: str) -> Optional[int]:
    # legacy fallback; unused in normal paths now
    return None

def index_to_ex4100_if(model: Optional[str], index_1based: int) -> Optional[str]:
    if index_1based is None or index_1based <= 0:
        return None
    p = index_1based - 1
    if model and model.startswith("EX4100-48MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 15 else f"ge-0/0/{p}"
    if model and model.startswith("EX4100-24MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 7 else f"ge-0/0/{p}"
    return f"ge-0/0/{p}"

def cisco_to_ex_if_enhanced(model: Optional[str], name: str) -> Optional[str]:
    """
    Cisco Gi<SW>/<MOD>/<PORT> -> <type>-<member>/<pic>/<port>
      * member = SW - 1
      * MOD 0 => PIC 0 (front), PORT 1..48 -> jport=PORT-1
      * MOD 1 => PIC 2 (uplinks), PORT 1..4 -> jport=PORT-1
    Fallback for 2-part names (Gi<SW>/<PORT>): 49..52 -> PIC 2; else PIC 0.
    """
    p = cisco_split(name)
    if not p:
        return None
    sw, mod, port = p["sw"], p["mod"], p["port"]
    member = max(sw - 1, 0)

    if mod == 1:
        pic, jport = 2, port - 1
        itype = "xe" if (model or "").startswith("EX4100") else "ge"
        return f"{itype}-{member}/{pic}/{jport}"

    if mod == 0:
        pic, jport = 0, port - 1
        if model and model.startswith("EX4100-48MP"):
            itype = "mge" if 0 <= jport <= 15 else "ge"
        elif model and model.startswith("EX4100-24MP"):
            itype = "mge" if 0 <= jport <= 7 else "ge"
        else:
            itype = "ge"
        return f"{itype}-{member}/{pic}/{jport}"

    # Fallback when MOD missing (2-part names)
    if 49 <= port <= 52:
        pic, jport = 2, port - 49
        itype = "xe" if (model or "").startswith("EX4100") else "ge"
        return f"{itype}-{member}/{pic}/{jport}"

    pic, jport = 0, port - 1
    if model and model.startswith("EX4100-48MP"):
        itype = "mge" if 0 <= jport <= 15 else "ge"
    elif model and model.startswith("EX4100-24MP"):
        itype = "mge" if 0 <= jport <= 7 else "ge"
    else:
        itype = "ge"
    return f"{itype}-{member}/{pic}/{jport}"

# Accept ge/mge/xe/et; used by remap & capacity checks
MIST_IF_RE = re.compile(r'^(?P<type>ge|mge|xe|et)-(?P<member>\d+)/(?P<pic>\d+)/(?P<port>\d+)$')

def _collect_members(port_config: Dict[str, Any]) -> List[int]:
    mems: List[int] = []
    for ifname in port_config.keys():
        m = MIST_IF_RE.match(ifname)
        if m:
            mems.append(int(m.group("member")))
    return mems

def remap_members(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
    if member_offset == 0 and not normalize:
        return port_config
    base = 0
    if normalize:
        mems = _collect_members(port_config)
        base = min(mems) if mems else 0
    out: Dict[str, Any] = {}
    for ifname, cfg in port_config.items():
        m = MIST_IF_RE.match(ifname)
        if not m:
            out[ifname] = cfg
            continue
        itype  = m.group("type")
        member = int(m.group("member"))
        pic    = int(m.group("pic"))
        port   = int(m.group("port"))
        new_member = (member - base) + int(member_offset or 0)
        new_name = f"{itype}-{new_member}/{pic}/{port}"
        if new_name in out:
            raise PortConfigError(f"Member remap collision on {new_name}")
        out[new_name] = cfg
    return out

def remap_ports(
    port_config: Dict[str, Any],
    port_offset: int = 0,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Shift the ``<port>`` component in interface names by ``port_offset`` and
    adjust ``ge``/``mge`` prefixes when the shifted port crosses the model's
    speed boundary.

    Example: ``mge-0/0/0`` with ``port_offset=24`` on an EX4100-48MP becomes
    ``ge-0/0/24``.  Collisions raise :class:`PortConfigError` to match
    :func:`remap_members` behaviour.
    """
    if int(port_offset or 0) == 0:
        return port_config

    # Determine mge/ge cutoff based on model (default 16 like EX4100-48MP)
    cutoff = 16
    if model:
        m = model.strip().lower()
        if m.startswith("ex4100-24"):
            cutoff = 8
        elif m.startswith("ex4100-48"):
            cutoff = 16

    out: Dict[str, Any] = {}
    for ifname, cfg in port_config.items():
        m = MIST_IF_RE.match(ifname)
        if not m:
            out[ifname] = cfg
            continue
        itype = m.group("type")
        member = int(m.group("member"))
        pic = int(m.group("pic"))
        port = int(m.group("port"))
        new_port = port + int(port_offset or 0)

        new_type = itype
        if itype in {"ge", "mge"}:
            new_type = "mge" if new_port < cutoff else "ge"

        new_name = f"{new_type}-{member}/{pic}/{new_port}"
        if new_name in out:
            raise PortConfigError(f"Port remap collision on {new_name}")
        out[new_name] = cfg
    return out

def remap_modules(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
    return remap_members(port_config, member_offset=member_offset, normalize=normalize)

def map_interfaces_to_port_config(intfs: List[Dict[str, Any]], model: Optional[str]) -> Dict[str, Dict[str, Any]]:
    rules = RULES_DOC.get("rules", []) or []

    port_config: Dict[str, Dict[str, Any]] = {}
    for intf in intfs:
        if (intf.get("mode") or "").lower() == "routed":
            continue

        derived_if = cisco_to_ex_if_enhanced(model, intf.get("name", ""))
        if not derived_if:
            idx = None
            derived_if = index_to_ex4100_if(model, idx) if idx is not None else None

        mist_if = derived_if or intf.get("juniper_if") or intf.get("name", "")

        chosen = None
        for r in rules:
            if evaluate_rule(r.get("when", {}) or {}, intf):
                chosen = r
                break

        usage = None
        if chosen:
            s = chosen.get("set", {}) or {}
            usage = s.get("usage", usage)

        raw_desc = intf.get("description", "") or ""
        filtered_desc = filter_description_blacklist(raw_desc)

        cfg: Dict[str, Any] = {"usage": usage or "blackhole", "description": filtered_desc}

        if mist_if in port_config:
            raise PortConfigError(f"Key collision for {mist_if} (from {intf.get('name')}); check Cisco mapping.")
        port_config[mist_if] = cfg

    return port_config

def extract_port_config(input_json: Dict[str, Any], model: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    if "interfaces" in input_json and isinstance(input_json["interfaces"], list):
        return map_interfaces_to_port_config(input_json["interfaces"], model)
    if "port_config" in input_json and isinstance(input_json["port_config"], dict):
        return input_json["port_config"]
    raise PortConfigError("Input JSON must contain either 'interfaces' or 'port_config'.")

def ensure_port_config(*args) -> Dict[str, Dict[str, Any]]:
    if len(args) == 1:
        return extract_port_config(args[0], model=None)
    elif len(args) >= 2:
        return extract_port_config(args[0], model=args[1])
    else:
        raise PortConfigError("ensure_port_config requires 1 or 2 arguments.")

# -------------------------------
# Model capacity map & validator
# -------------------------------
MODEL_CAPS = {
    "EX4100-24":   {"access_pic0": 24, "uplink_pic2": 4},
    "EX4100-24MP": {"access_pic0": 24, "uplink_pic2": 4},
    "EX4100-48":   {"access_pic0": 48, "uplink_pic2": 4},
    "EX4100-48MP": {"access_pic0": 48, "uplink_pic2": 4},
    # extend here as needed
}

def _model_key(model: Optional[str]) -> Optional[str]:
    if not model:
        return None
    m = model.strip().upper()
    for k in MODEL_CAPS.keys():
        if m.startswith(k.upper()):
            return k
    return m

def validate_port_config_against_model(port_config: Dict[str, Any], model: Optional[str]) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    mk = _model_key(model)
    caps = MODEL_CAPS.get(mk) if mk else None
    if not caps:
        warnings.append(f"Unknown/unsupported model '{model}'. Capacity checks skipped.")
        return {"ok": True, "errors": [], "warnings": warnings, "counts": {}, "limits": {}}

    access_cap = caps["access_pic0"]
    uplink_cap = caps.get("uplink_pic2", 0)

    bad_access: List[str] = []
    bad_uplink: List[str] = []
    seen_pic0: set[int] = set()
    seen_pic2: set[int] = set()

    for ifname in port_config.keys():
        m = MIST_IF_RE.match(ifname)
        if not m:
            continue
        pic = int(m.group("pic"))
        port = int(m.group("port"))
        if pic == 0:
            seen_pic0.add(port)
            if port >= access_cap:
                bad_access.append(ifname)
        elif pic == 2:
            seen_pic2.add(port)
            if port >= uplink_cap:
                bad_uplink.append(ifname)

    counts = {"pic0_ports": len(seen_pic0), "pic2_ports": len(seen_pic2)}
    limits = {"pic0_max": access_cap, "pic2_max": uplink_cap}

    if bad_access:
        errors.append(f"{len(bad_access)} interface(s) exceed access capacity for {model} (PIC 0 supports 0..{access_cap-1}): {', '.join(sorted(bad_access)[:6])}{' …' if len(bad_access)>6 else ''}")
    if bad_uplink:
        errors.append(f"{len(bad_uplink)} interface(s) exceed uplink capacity for {model} (PIC 2 supports 0..{uplink_cap-1}): {', '.join(sorted(bad_uplink)[:6])}{' …' if len(bad_uplink)>6 else ''}")

    ok = not errors
    return {"ok": ok, "errors": errors, "warnings": warnings, "counts": counts, "limits": limits}

# -------------------------------
# Device model lookup
# -------------------------------
def get_device_model(base_url: str, site_id: str, device_id: str, token: str) -> Optional[str]:
    url = f"{base_url.rstrip('/')}/sites/{site_id}/devices/{device_id}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Token {token}"}, timeout=20)
        if 200 <= resp.status_code < 300:
            return resp.json().get("model")
    except Exception:
        pass
    return None

# -------------------------------
# CLI
# -------------------------------
def main():
    ap = argparse.ArgumentParser(description="Map and push Mist port_config with EX4100 uplink mapping and member/port offsets.")
    ap.add_argument("--site-id", required=True)
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--input", required=True, help="Path to converter JSON ('interfaces') or Mist 'port_config'")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--tz", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--save-output", default=None)
    ap.add_argument("--model", default=None, help="Override device model (skip API lookup)")
    ap.add_argument("--exclude-interface", action="append", default=None)
    ap.add_argument("--member-offset", type=int, default=0)
    ap.add_argument("--port-offset", type=int, default=0)
    ap.add_argument("--normalize-modules", action="store_true")

    args = ap.parse_args()

    token = load_token()
    base_url = (args.base_url or BASE_URL).rstrip("/")
    tz_name = (args.tz or TZ)
    model = args.model or get_device_model(base_url, args.site_id, args.device_id, token)

    with open(args.input, "r", encoding="utf-8") as f:
        inp = json.load(f)

    # Build/obtain port_config
    port_config = extract_port_config(inp, model=model)

    # Apply member/port remap BEFORE excludes
    port_config = remap_members(port_config, member_offset=int(args.member_offset or 0), normalize=bool(args.normalize_modules))
    port_config = remap_ports(port_config, port_offset=int(args.port_offset or 0), model=model)

    # Apply excludes AFTER remap
    excludes = set(args.exclude_interface or [])
    if excludes:
        port_config = {k: v for k, v in port_config.items() if k not in excludes}

    # Capacity validation
    validation = validate_port_config_against_model(port_config, model)
    if not args.dry_run and not validation.get("ok"):
        print("❌ Capacity error:")
        print(json.dumps(validation, indent=2))
        raise PortConfigError("Capacity validation failed.")

    # Timestamp descriptions
    ts = timestamp_str(tz_name)
    final_port_config: Dict[str, Dict[str, Any]] = {}
    for ifname, cfg in port_config.items():
        c = dict(cfg)
        c["description"] = tag_description(c.get("description", ""), ts)
        final_port_config[ifname] = c

    body = {"port_config": final_port_config}
    url = f"{base_url}/sites/{args.site_id}/devices/{args.device_id}"
    headers = {"Authorization": f"Token {token}", "Content-Type": "application/json", "Accept": "application/json"}

    if args.dry_run:
        print(f"Device model: {model or 'unknown'}")
        print(f"Member offset: {args.member_offset} (normalize: {bool(args.normalize_modules)})")
        print(f"Port offset: {args.port_offset}")
        print("Validation:")
        print(json.dumps(validation, indent=2))
        print(f"PUT {url}")
        print(json.dumps(body, indent=2))
        return

    resp = requests.put(url, headers=headers, json=body, timeout=60)
    try:
        content = resp.json()
    except Exception:
        content = {"text": resp.text}

    if 200 <= resp.status_code < 300:
        print("✅ Success")
        print(json.dumps(content, indent=2))
    else:
        print(f"❌ Error {resp.status_code} on PUT {url}")
        print(json.dumps(content, indent=2))
        if resp.status_code == 404:
            print("Hint: 404 usually means wrong site/device or wrong region base URL.")
        resp.raise_for_status()

if __name__ == "__main__":
    try:
        main()
    except PortConfigError as exc:  # pragma: no cover - CLI convenience
        print(f"❌ {exc}")
        raise SystemExit(2)
