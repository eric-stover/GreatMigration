"""Utilities to execute compliance auto-remediation actions."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import requests

from audit_actions import (
    AP_RENAME_ACTION_ID,
    CLEAR_DNS_OVERRIDE_ACTION_ID,
    ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
    SET_SITE_VARIABLES_ACTION_ID,
    SET_SPARE_SWITCH_ROLE_ACTION_ID,
)
from compliance import (
    DEFAULT_AP_NAME_PATTERN,
    DEFAULT_SWITCH_NAME_PATTERN,
    DEFAULT_REQUIRED_SITE_VARIABLES,
    DNS_OVERRIDE_LAB_TEMPLATE_IDS,
    DNS_OVERRIDE_LAB_TEMPLATE_NAME,
    DNS_OVERRIDE_PROD_TEMPLATE_IDS,
    DNS_OVERRIDE_REQUIRED_VAR_GROUPS,
    DNS_OVERRIDE_TEMPLATE_NAME,
    ENV_SWITCH_NAME_PATTERN,
    load_site_variable_config,
)

AP_NAME_PATTERN = re.compile(DEFAULT_AP_NAME_PATTERN)
if ENV_SWITCH_NAME_PATTERN is not None:
    SWITCH_LLDPNAME_PATTERN = ENV_SWITCH_NAME_PATTERN
else:
    SWITCH_LLDPNAME_PATTERN = re.compile(DEFAULT_SWITCH_NAME_PATTERN)


SWITCH_LOCATION_EXTRACT_PATTERN = re.compile(
    r"^(?P<region>NA|LA|EU|AP)(?P<site>[A-Z]{3})(?P<location>MDF|IDF\d+)[A-Z]{2}\d+$"
)


def _mist_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _paginated_get(
    base_url: str,
    headers: Dict[str, str],
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    url = f"{base_url}{path}"
    collected: List[Dict[str, Any]] = []
    query = dict(params or {})
    while url:
        response = requests.get(url, headers=headers, params=query or None, timeout=30)
        response.raise_for_status()
        data = response.json() or []
        if isinstance(data, dict):
            items = data.get("results") or data.get("data") or []
            if isinstance(items, list):
                collected.extend(item for item in items if isinstance(item, dict))
            else:
                items = []
            next_url = data.get("next")
            url = next_url if isinstance(next_url, str) and next_url else None
            query = {}
        elif isinstance(data, list):
            collected.extend(item for item in data if isinstance(item, dict))
            url = None
        else:
            url = None
    return collected


def _list_site_aps(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
) -> List[Dict[str, Any]]:
    return _paginated_get(
        base_url,
        headers,
        f"/sites/{site_id}/devices",
        params={"type": "ap"},
    )


def _get_device_stats(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    device_id: str,
) -> Dict[str, Any]:
    response = requests.get(
        f"{base_url}/sites/{site_id}/stats/devices/{device_id}",
        headers=headers,
        params={"type": "ap"},
        timeout=30,
    )
    response.raise_for_status()
    try:
        payload = response.json()
    except Exception:
        return {}
    if isinstance(payload, dict):
        stats = payload.get("stats")
        if isinstance(stats, dict):
            return stats
        return payload
    return {}


def _fetch_site_name(base_url: str, headers: Dict[str, str], site_id: str) -> str:
    try:
        response = requests.get(f"{base_url}/sites/{site_id}", headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json() or {}
        if isinstance(payload, dict):
            for key in ("name", "site_name", "display_name"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value
    except Exception:
        pass
    return site_id


def _format_summary_message(verb: str, count: int) -> str:
    plural = "" if count == 1 else "s"
    return f"{verb} {count} device{plural}"


def _get_json(
    base_url: str,
    headers: Dict[str, str],
    path: str,
    *,
    optional: bool = False,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    url = f"{base_url}{path}"
    response = requests.get(url, headers=headers, params=params or None, timeout=30)
    if optional and response.status_code == 404:
        return {}
    response.raise_for_status()
    try:
        data = response.json()
    except Exception:
        return {}
    return data


def _collect_template_names_from_docs(*docs: Any) -> Set[str]:
    names: Set[str] = set()

    def _maybe_add(value: Any) -> None:
        if isinstance(value, str):
            text = value.strip()
            if text:
                names.add(text)

    for doc in docs:
        if isinstance(doc, dict):
            for key in ("networktemplate_name", "template_name", "name"):
                _maybe_add(doc.get(key))
        elif isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict):
                    for key in ("name", "template_name", "networktemplate_name"):
                        _maybe_add(item.get(key))
    return names


def _collect_template_ids_from_docs(*docs: Any) -> Set[str]:
    identifiers: Set[str] = set()

    def _maybe_add(value: Any) -> None:
        if isinstance(value, str):
            text = value.strip()
            if text:
                identifiers.add(text)

    for doc in docs:
        if isinstance(doc, dict):
            for key in ("id", "template_id", "networktemplate_id", "network_template_id"):
                _maybe_add(doc.get(key))
        elif isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict):
                    for key in ("id", "template_id"):
                        _maybe_add(item.get(key))
    return identifiers


def _collect_site_variables_from_docs(*docs: Any) -> Dict[str, Any]:
    variables: Dict[str, Any] = {}
    keys = ("variables", "vars", "site_vars", "site_variables")
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for key in keys:
            value = doc.get(key)
            if isinstance(value, dict):
                for var_key, var_value in value.items():
                    if isinstance(var_key, str):
                        variables[var_key] = var_value
    return variables


def _load_site_variable_defaults() -> Dict[str, str]:
    _, defaults = load_site_variable_config("MIST_SITE_VARIABLES", DEFAULT_REQUIRED_SITE_VARIABLES)
    return defaults


def _site_display_name(doc: Any, default: str) -> str:
    if isinstance(doc, dict):
        for key in ("name", "site_name", "display_name"):
            value = doc.get(key)
            if isinstance(value, str):
                text = value.strip()
                if text:
                    return text
    return default


def _site_is_lab(site_name: str) -> bool:
    return "lab" in (site_name or "").lower()


def _format_dns_var_group_label(options: Sequence[str]) -> str:
    labels = [opt for opt in options if isinstance(opt, str) and opt]
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} or {labels[1]}"
    return ", ".join(labels[:-1]) + f", or {labels[-1]}"


def _evaluate_dns_variable_groups(variables: Mapping[str, Any]) -> Tuple[bool, List[str]]:
    missing: List[str] = []
    for group in DNS_OVERRIDE_REQUIRED_VAR_GROUPS:
        if not any(_value_is_set(variables.get(name)) for name in group):
            label = _format_dns_var_group_label(group)
            if label:
                missing.append(label)
    return (not missing, missing)


def _allowed_templates_for_site(site_name: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    if _site_is_lab(site_name):
        allowed_names = tuple(
            dict.fromkeys(
                name
                for name in (
                    DNS_OVERRIDE_LAB_TEMPLATE_NAME,
                    DNS_OVERRIDE_TEMPLATE_NAME,
                )
                if isinstance(name, str) and name
            )
        )
        allowed_ids = tuple(
            dict.fromkeys(
                value
                for value in (
                    *(DNS_OVERRIDE_LAB_TEMPLATE_IDS or ()),
                    *(DNS_OVERRIDE_PROD_TEMPLATE_IDS or ()),
                )
                if isinstance(value, str) and value
            )
        )
        return allowed_names, allowed_ids
    allowed_names = tuple(
        dict.fromkeys(
            name
            for name in (DNS_OVERRIDE_TEMPLATE_NAME,)
            if isinstance(name, str) and name
        )
    )
    allowed_ids = tuple(
        dict.fromkeys(
            value
            for value in (DNS_OVERRIDE_PROD_TEMPLATE_IDS or ())
            if isinstance(value, str) and value
        )
    )
    return allowed_names, allowed_ids


def _templates_match(
    template_names: Set[str],
    template_ids: Set[str],
    allowed_names: Sequence[str],
    allowed_ids: Sequence[str],
    device_docs: Iterable[Mapping[str, Any]] = (),
) -> bool:
    normalized_names = {name for name in allowed_names if isinstance(name, str) and name}
    normalized_ids = {tid for tid in allowed_ids if isinstance(tid, str) and tid}

    if normalized_names and template_names.intersection(normalized_names):
        return True
    if normalized_ids and template_ids.intersection(normalized_ids):
        return True

    for doc in device_docs:
        if not isinstance(doc, Mapping):
            continue
        for key in ("template_id", "switch_template_id"):
            value = doc.get(key)
            if isinstance(value, str):
                text = value.strip()
                if text and text in normalized_ids:
                    return True
    return False


def _format_template_error_message(allowed_names: Sequence[str]) -> str:
    filtered = [name for name in allowed_names if isinstance(name, str) and name]
    if not filtered:
        return "Required switch template is not applied to this site."
    if len(filtered) == 1:
        return f"Required template '{filtered[0]}' is not applied."
    if len(filtered) == 2:
        return f"Required templates '{filtered[0]}' or '{filtered[1]}' are not applied."
    joined = ", ".join(f"'{name}'" for name in filtered[:-1])
    return f"None of the required templates are applied. Expected one of: {joined}, or '{filtered[-1]}'."


def _fetch_device_document(
    base_url: str, headers: Dict[str, str], site_id: str, device_id: str
) -> Dict[str, Any]:
    payload = _get_json(
        base_url,
        headers,
        f"/sites/{site_id}/devices/{device_id}",
    )
    return payload if isinstance(payload, dict) else {}


def _device_display_name(doc: Mapping[str, Any], default: str) -> str:
    for key in ("name", "device_name", "hostname", "display_name"):
        value = doc.get(key)
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return default


def _normalize_dns_values(values: Any) -> List[str]:
    normalized: List[str] = []
    if isinstance(values, list):
        for value in values:
            if isinstance(value, (str, bytes)):
                text = str(value).strip()
                if text:
                    normalized.append(text)
    return normalized


def _value_is_set(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes)):
        return bool(str(value).strip())
    return True


DNS_KEYS = ("dns", "dns_servers", "dns_server")


def _sanitize_ip_config_dns(ip_config: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Remove DNS keys defined directly on an ip_config document."""

    cleaned_config: Dict[str, Any] = dict(ip_config)
    removed: List[str] = []

    for key in DNS_KEYS:
        values = _normalize_dns_values(cleaned_config.get(key))
        if values:
            removed.extend(values)
        if key in cleaned_config:
            cleaned_config.pop(key, None)

    return cleaned_config, removed


def _build_dns_update_payload(
    device_doc: Mapping[str, Any],
    sanitized_direct_ip: Optional[Mapping[str, Any]],
    sanitized_switch_ip: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    if isinstance(device_doc.get("ip_config"), dict) and sanitized_direct_ip is not None:
        payload["ip_config"] = dict(sanitized_direct_ip)
    switch_config = device_doc.get("switch_config")
    if (
        isinstance(switch_config, dict)
        and isinstance(switch_config.get("ip_config"), dict)
        and sanitized_switch_ip is not None
    ):
        new_switch_config = dict(switch_config)
        new_switch_config["ip_config"] = dict(sanitized_switch_ip)
        payload["switch_config"] = new_switch_config
    return payload


def _update_device_payload(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    device_id: str,
    payload: Mapping[str, Any],
) -> None:
    response = requests.put(
        f"{base_url}/sites/{site_id}/devices/{device_id}",
        headers=headers,
        json=dict(payload),
        timeout=30,
    )
    response.raise_for_status()


PHYSICAL_SWITCH_INTERFACE_PATTERN = re.compile(
    r"^(?:ge|xe|et|mge)-(?P<fpc>\d+)/(?P<pic>\d+)/(?P<port>\d+)(?:\.\d+)?$",
    re.IGNORECASE,
)


def _is_truthy_link_state(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized in {"up", "connected", "online", "active"}
    return False


def _interface_name_from_entry(entry: Mapping[str, Any]) -> str:
    for key in ("name", "port_name", "port", "port_id", "interface", "if_name", "id"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _interface_up_from_entry(entry: Mapping[str, Any]) -> bool:
    for key in ("up", "oper_up", "link_up", "is_up", "connected"):
        if key in entry and _is_truthy_link_state(entry.get(key)):
            return True
    status = entry.get("status")
    if _is_truthy_link_state(status):
        return True
    return False


def _has_active_physical_switch_ports(value: Any, visited: Optional[Set[int]] = None) -> bool:
    if visited is None:
        visited = set()
    obj_id = id(value)
    if obj_id in visited:
        return False
    visited.add(obj_id)

    if isinstance(value, Mapping):
        interface_name = _interface_name_from_entry(value)
        if interface_name:
            match = PHYSICAL_SWITCH_INTERFACE_PATTERN.match(interface_name)
            if match and match.group("pic") == "0" and _interface_up_from_entry(value):
                return True
        for nested in value.values():
            if _has_active_physical_switch_ports(nested, visited):
                return True
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            if _has_active_physical_switch_ports(nested, visited):
                return True
    return False


def _propose_spare_switch_name(current_name: str) -> Optional[str]:
    match = SWITCH_LOCATION_EXTRACT_PATTERN.match((current_name or "").strip())
    if not match:
        return None
    candidate = f"{match.group('region')}{match.group('site')}MDFSPARE"
    if SWITCH_LLDPNAME_PATTERN and SWITCH_LLDPNAME_PATTERN.fullmatch(candidate) is None:
        return None
    return candidate


def _execute_set_spare_switch_role_action(
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    headers = _mist_headers(token)
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    target_switch_id = ""
    if isinstance(metadata, Mapping):
        raw = metadata.get("selected_switch_id")
        if raw is not None:
            target_switch_id = str(raw).strip()

    if not target_switch_id:
        raise ValueError("Select a switch before running the spare-switch fix.")

    results: List[Dict[str, Any]] = []
    totals = {"updated": 0, "skipped": 0, "failed": 0}

    for site_id in normalized_site_ids:
        site_name = _fetch_site_name(base_url, headers, site_id)
        summary: Dict[str, Any] = {
            "site_id": site_id,
            "site_name": site_name,
            "updated": 0,
            "skipped": 0,
            "failed": 0,
            "changes": [],
            "errors": [],
        }

        try:
            device_doc = _fetch_device_document(base_url, headers, site_id, target_switch_id)
        except requests.HTTPError as exc:
            summary["failed"] += 1
            summary["errors"].append({"device_id": target_switch_id, "reason": f"Device lookup failed: {exc}"})
            results.append(summary)
            totals["failed"] += 1
            continue

        device_type = str(device_doc.get("type") or "").strip().lower()
        device_name = _device_display_name(device_doc, target_switch_id)
        if device_type != "switch":
            summary["failed"] += 1
            summary["errors"].append({"device_id": target_switch_id, "reason": "Selected device is not a switch."})
            results.append(summary)
            totals["failed"] += 1
            continue

        stats_doc = _get_json(
            base_url,
            headers,
            f"/sites/{site_id}/stats/devices/{target_switch_id}",
            optional=True,
            params={"type": "switch"},
        )
        if _has_active_physical_switch_ports(stats_doc):
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": target_switch_id,
                    "device_name": device_name,
                    "reason": "Devices are currently connected to the spare switch and should be moved to the MDF access layer first",
                }
            )
            summary["changes"].append(
                {
                    "device_id": target_switch_id,
                    "device_name": device_name,
                    "status": "failed",
                    "reason": "Devices are currently connected to the spare switch and should be moved to the MDF access layer first",
                }
            )
            results.append(summary)
            totals["failed"] += 1
            continue

        current_name = str(device_doc.get("name") or "").strip()
        role_payload = {"role": "spare"}
        compliant_name = True
        if SWITCH_LLDPNAME_PATTERN is not None:
            compliant_name = bool(current_name and SWITCH_LLDPNAME_PATTERN.fullmatch(current_name))
        rename_to: Optional[str] = None
        if not compliant_name:
            rename_to = _propose_spare_switch_name(current_name)
            if not rename_to:
                summary["failed"] += 1
                summary["errors"].append(
                    {
                        "device_id": target_switch_id,
                        "device_name": device_name,
                        "reason": "Unable to derive a compliant spare-switch name from the current device name.",
                    }
                )
                summary["changes"].append(
                    {
                        "device_id": target_switch_id,
                        "device_name": device_name,
                        "status": "failed",
                        "reason": "Unable to derive a compliant spare-switch name from the current device name.",
                    }
                )
                results.append(summary)
                totals["failed"] += 1
                continue

        payload = dict(role_payload)
        if rename_to:
            payload["name"] = rename_to

        change_entry: Dict[str, Any] = {
            "device_id": target_switch_id,
            "device_name": device_name,
            "previous_role": device_doc.get("role"),
            "new_role": "spare",
        }
        if rename_to:
            change_entry["previous_name"] = current_name
            change_entry["new_name"] = rename_to

        if dry_run:
            change_entry["status"] = "preview"
            change_entry["message"] = "Would clear port config, assign spare role, and enforce switch naming convention."
            summary["updated"] += 1
        else:
            try:
                _update_device_payload(base_url, headers, site_id, target_switch_id, {"port_config": {}})
                _update_device_payload(base_url, headers, site_id, target_switch_id, payload)
            except requests.HTTPError as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    {
                        "device_id": target_switch_id,
                        "device_name": device_name,
                        "reason": f"Failed to update switch role/name: {exc}",
                    }
                )
                change_entry["status"] = "failed"
                change_entry["reason"] = "Failed to update switch role/name."
            else:
                change_entry["status"] = "success"
                change_entry["message"] = "Cleared port config and assigned spare switch role."
                summary["updated"] += 1

        summary["changes"].append(change_entry)
        results.append(summary)
        totals["updated"] += summary.get("updated", 0)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    totals_with_sites = {**totals, "sites": len(results)}
    totals_with_sites.setdefault(
        "summary",
        _format_summary_message("Updated spare switch configuration for", totals_with_sites.get("updated", 0)),
    )

    return {
        "ok": True,
        "action_id": SET_SPARE_SWITCH_ROLE_ACTION_ID,
        "dry_run": dry_run,
        "results": results,
        "totals": totals_with_sites,
    }


def _parse_switch_location(name: str) -> Optional[Tuple[str, str, str]]:
    text = (name or "").strip()
    if SWITCH_LLDPNAME_PATTERN is not None and not SWITCH_LLDPNAME_PATTERN.fullmatch(text):
        return None
    match = SWITCH_LOCATION_EXTRACT_PATTERN.match(text)
    if not match:
        return None
    return match.group("region"), match.group("site"), match.group("location")


def _initial_number_map(names: Iterable[str]) -> Tuple[Dict[str, int], Set[int]]:
    numbers: Dict[str, int] = {}
    used_suffixes: Set[int] = set()
    for name in names:
        if not isinstance(name, str):
            continue
        m = AP_NAME_PATTERN.fullmatch(name.strip())
        if not m:
            continue
        try:
            prefix, number = name.rsplit("AP", 1)
            base = f"{prefix}AP"
            current = int(number)
        except Exception:
            continue
        numbers[base] = max(numbers.get(base, 0), current)
        used_suffixes.add(current)
    return numbers, used_suffixes


def _next_available_name(
    base: str,
    existing: set[str],
    numbers: Dict[str, int],
    used_suffixes: Set[int],
) -> str:
    start = numbers.get(base, 0) + 1
    while True:
        if start in used_suffixes:
            start += 1
            continue
        candidate = f"{base}{start}"
        if candidate not in existing:
            break
        start += 1
    numbers[base] = start
    used_suffixes.add(start)
    existing.add(candidate)
    return candidate


def _needs_rename(name: Optional[str]) -> bool:
    if not name:
        return True
    return AP_NAME_PATTERN.fullmatch(name.strip()) is None


def _rename_device(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    device_id: str,
    new_name: str,
) -> None:
    response = requests.put(
        f"{base_url}/sites/{site_id}/devices/{device_id}",
        headers=headers,
        json={"name": new_name},
        timeout=30,
    )
    response.raise_for_status()


def _neighbor_system_name(stats: Dict[str, Any]) -> Optional[str]:
    uplink = stats.get("uplink") if isinstance(stats, dict) else None
    if isinstance(uplink, dict):
        neighbor = uplink.get("neighbor")
        if isinstance(neighbor, dict):
            for key in ("system_name", "sys_name", "name"):
                value = neighbor.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    if isinstance(stats, dict):
        lldp_stats = stats.get("lldp_stats")
        entries: Iterable[Any]
        if isinstance(lldp_stats, dict):
            entries = list(lldp_stats.values())
        elif isinstance(lldp_stats, (list, tuple, set)):
            entries = lldp_stats
        else:
            entries = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            for key in (
                "system_name",
                "sys_name",
                "name",
                "remote_system_name",
                "lldp_remote_system_name",
            ):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            neighbor = entry.get("neighbor")
            if isinstance(neighbor, Mapping):
                for key in ("system_name", "sys_name", "name"):
                    value = neighbor.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
            neighbors = entry.get("neighbors")
            if isinstance(neighbors, Mapping):
                for nested in neighbors.values():
                    if isinstance(nested, Mapping):
                        for key in ("system_name", "sys_name", "name"):
                            value = nested.get(key)
                            if isinstance(value, str) and value.strip():
                                return value.strip()
            if isinstance(neighbors, (list, tuple, set)):
                for nested in neighbors:
                    if isinstance(nested, Mapping):
                        for key in ("system_name", "sys_name", "name"):
                            value = nested.get(key)
                            if isinstance(value, str) and value.strip():
                                return value.strip()
    return None


def _summarize_site(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    *,
    dry_run: bool,
    pause: float,
    limit_device_ids: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    site_name = _fetch_site_name(base_url, headers, site_id)
    devices = _list_site_aps(base_url, headers, site_id)

    existing_names = {d.get("name", "") for d in devices if isinstance(d, dict)}
    name_numbers, used_suffixes = _initial_number_map(existing_names)

    summary: Dict[str, Any] = {
        "site_id": site_id,
        "site_name": site_name,
        "renamed": 0,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
        "changes": [],
        "errors": [],
    }

    normalized_limit: Optional[Set[str]] = None
    if limit_device_ids is not None:
        normalized_limit = {str(device_id) for device_id in limit_device_ids if str(device_id).strip()}

    stats_cache: Dict[str, Dict[str, Any]] = {}
    stats_errors: Dict[str, str] = {}

    for device in devices:
        if not isinstance(device, dict):
            continue
        mac = device.get("mac")
        mac_key = mac.lower() if isinstance(mac, str) else None
        device_id = device.get("id")
        if not isinstance(device_id, str) or not device_id:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "mac": mac,
                    "reason": "Device record missing identifier.",
                }
            )
            continue
        if normalized_limit is not None and device_id not in normalized_limit:
            continue
        current_name = (device.get("name") or "").strip() or None
        force_processing = normalized_limit is not None
        if not _needs_rename(current_name) and not force_processing:
            summary["skipped"] += 1
            continue

        if device_id not in stats_cache and device_id not in stats_errors:
            try:
                stats_doc = _get_device_stats(base_url, headers, site_id, device_id)
                stats_cache[device_id] = stats_doc
                if mac_key:
                    stats_cache[mac_key] = stats_doc
            except requests.HTTPError as exc:
                stats_errors[device_id] = f"Failed to retrieve device stats: {exc}"
            except requests.RequestException as exc:
                stats_errors[device_id] = f"Failed to retrieve device stats: {exc}"

        error_reason = stats_errors.get(device_id)
        if error_reason:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "mac": mac,
                    "reason": error_reason,
                }
            )
            continue

        stats_entry = stats_cache.get(device_id)
        if not stats_entry and mac_key:
            stats_entry = stats_cache.get(mac_key)

        neighbor = _neighbor_system_name(stats_entry or {}) if stats_entry else None
        if not neighbor:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "mac": mac,
                    "reason": "Missing LLDP neighbor system_name.",
                }
            )
            continue

        parsed = _parse_switch_location(neighbor)
        if not parsed:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "mac": mac,
                    "neighbor": neighbor,
                    "reason": "Switch name does not meet naming standards. Please correct that first.",
                }
            )
            continue

        region, site, location = parsed
        base = f"{region}{site}{location}AP"
        candidate = _next_available_name(base, existing_names, name_numbers, used_suffixes)

        if not dry_run:
            try:
                _rename_device(base_url, headers, site_id, device_id, candidate)
                time.sleep(max(pause, 0.0))
            except requests.HTTPError as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    {
                        "device_id": device_id,
                        "mac": mac,
                        "neighbor": neighbor,
                        "reason": "Change Failed! Please see device logs",
                        "details": {
                            "error": f"Rename failed: {exc}",
                            "attempted_name": candidate,
                        },
                    }
                )
                existing_names.discard(candidate)
                continue
        summary["renamed"] += 1
        summary["updated"] += 1
        change_entry = {
            "device_id": device_id,
            "mac": mac,
            "old_name": current_name,
            "new_name": candidate,
            "neighbor": neighbor,
        }
        if dry_run:
            change_entry["status"] = "preview"
            change_entry["message"] = f"Would rename to {candidate}"
        else:
            change_entry["status"] = "success"
            change_entry["message"] = "Success!"
        summary["changes"].append(change_entry)
    return summary


def _clear_dns_overrides_for_site(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    *,
    dry_run: bool,
    device_ids: Optional[Sequence[str]],
) -> Dict[str, Any]:
    site_doc = _get_json(base_url, headers, f"/sites/{site_id}")
    setting_doc = _get_json(base_url, headers, f"/sites/{site_id}/setting", optional=True)
    templates_doc = _get_json(
        base_url,
        headers,
        f"/sites/{site_id}/networktemplates",
        optional=True,
    )
    template_list = templates_doc if isinstance(templates_doc, list) else []

    site_name = _site_display_name(site_doc, site_id)

    normalized_devices: List[str] = []
    if device_ids:
        seen: Set[str] = set()
        for device_id in device_ids:
            if device_id is None:
                continue
            text = str(device_id).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized_devices.append(text)

    summary: Dict[str, Any] = {
        "site_id": site_id,
        "site_name": site_name,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
        "changes": [],
        "errors": [],
    }

    if not normalized_devices:
        summary["failed"] = 1
        summary["errors"].append({"reason": "No target devices provided."})
        return summary

    template_names = _collect_template_names_from_docs(site_doc, setting_doc, template_list)
    template_ids = _collect_template_ids_from_docs(site_doc, setting_doc, template_list)
    site_variables = _collect_site_variables_from_docs(site_doc, setting_doc)
    allowed_template_names, allowed_template_ids = _allowed_templates_for_site(site_name)
    required_dns_labels = [
        label
        for label in (
            _format_dns_var_group_label(group)
            for group in DNS_OVERRIDE_REQUIRED_VAR_GROUPS
        )
        if label
    ]
    dns_ok, missing_dns_labels = _evaluate_dns_variable_groups(site_variables)

    device_docs: Dict[str, Dict[str, Any]] = {}
    for device_id in normalized_devices:
        try:
            device_doc = _fetch_device_document(base_url, headers, site_id, device_id)
        except requests.HTTPError as exc:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "reason": f"Device lookup failed: {exc}",
                }
            )
            continue
        device_docs[device_id] = device_doc

    if not _templates_match(
        template_names,
        template_ids,
        allowed_template_names,
        allowed_template_ids,
        device_docs.values(),
    ):
        already_failed = summary["failed"]
        summary["failed"] = already_failed + max(0, len(normalized_devices) - already_failed)
        summary["errors"].append(
            {
                "reason": _format_template_error_message(allowed_template_names),
                "templates": sorted(template_names),
                "allowed_templates": list(allowed_template_names),
            }
        )
        return summary

    if not dns_ok:
        already_failed = summary["failed"]
        summary["failed"] = already_failed + max(0, len(normalized_devices) - already_failed)
        summary["errors"].append(
            {
                "reason": "Required site DNS variables are missing or empty.",
                "missing": missing_dns_labels,
                "required": required_dns_labels,
            }
        )
        return summary

    allowed_template_id_set = {tid for tid in allowed_template_ids if tid}

    for device_id in normalized_devices:
        device_doc = device_docs.get(device_id)
        if not device_doc:
            continue

        device_name = _device_display_name(device_doc, device_id)

        device_template_id = None
        for key in ("template_id", "switch_template_id"):
            value = device_doc.get(key)
            if isinstance(value, str) and value.strip():
                device_template_id = value.strip()
                break

        if device_template_id and allowed_template_id_set and device_template_id not in allowed_template_id_set:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "device_name": device_name,
                    "reason": (
                        "Device template does not match allowed templates for this site."
                    ),
                    "template_id": device_template_id,
                    "allowed_template_ids": list(allowed_template_id_set),
                }
            )
            continue

        direct_ip = device_doc.get("ip_config")
        has_direct_ip = isinstance(direct_ip, dict)

        if not has_direct_ip:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "reason": "Device does not expose ip_config overrides.",
                }
            )
            continue

        removed_dns: List[str] = []
        sanitized_direct: Optional[Dict[str, Any]] = None

        if has_direct_ip and direct_ip.get("type") == "static":
            sanitized_direct, direct_removed = _sanitize_ip_config_dns(direct_ip)
            removed_dns.extend(direct_removed)

        deduped_removed: List[str] = []
        seen_dns: Set[str] = set()
        for value in removed_dns:
            if value not in seen_dns:
                deduped_removed.append(value)
                seen_dns.add(value)

        if not deduped_removed:
            summary["skipped"] += 1
            summary["changes"].append(
                {
                    "device_id": device_id,
                    "device_name": device_name,
                    "removed_dns": [],
                    "reason": "No static DNS overrides present.",
                }
            )
            continue

        payload = _build_dns_update_payload(device_doc, sanitized_direct, None)
        if not payload:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "reason": "Unable to construct update payload for device.",
                }
            )
            continue

        if not dry_run:
            try:
                _update_device_payload(base_url, headers, site_id, device_id, payload)
            except requests.HTTPError as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    {
                        "device_id": device_id,
                        "reason": f"Failed to clear DNS override: {exc}",
                    }
                )
                continue

        summary["updated"] += 1
        summary["changes"].append(
            {
                "device_id": device_id,
                "device_name": device_name,
                "removed_dns": deduped_removed,
            }
        )

    return summary


def _apply_site_variables_for_site(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    *,
    dry_run: bool,
    defaults: Mapping[str, str],
) -> Dict[str, Any]:
    site_doc = _get_json(base_url, headers, f"/sites/{site_id}")
    site_name = _site_display_name(site_doc, site_id)
    summary: Dict[str, Any] = {
        "site_id": site_id,
        "site_name": site_name,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
        "changes": [],
        "errors": [],
    }

    if not defaults:
        summary["skipped"] = 1
        summary["errors"].append({"reason": "No site variable defaults configured."})
        return summary

    current_vars = _collect_site_variables_from_docs(site_doc)
    updates: Dict[str, str] = {}
    for key, value in defaults.items():
        if not isinstance(key, str) or not key.strip():
            continue
        if not _value_is_set(value):
            continue
        if _value_is_set(current_vars.get(key)):
            continue
        updates[key.strip()] = str(value).strip()

    if not updates:
        summary["skipped"] = 1
        summary["changes"].append(
            {
                "status": "skipped",
                "message": "All configured site variables are already set.",
            }
        )
        return summary

    merged = dict(current_vars)
    merged.update(updates)
    if not dry_run:
        response = requests.put(
            f"{base_url}/sites/{site_id}",
            headers=headers,
            json={"variables": merged},
            timeout=30,
        )
        response.raise_for_status()

    for key, value in updates.items():
        summary["changes"].append(
            {
                "status": "preview" if dry_run else "success",
                "variable": key,
                "value": value,
                "message": ("Would set" if dry_run else "Set") + f" '{key}' from environment default.",
            }
        )
    summary["updated"] = len(updates)
    return summary


def _execute_cloud_management_action(
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool,
    device_map: Optional[Mapping[str, Sequence[str]]],
) -> Dict[str, Any]:
    headers = _mist_headers(token)
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    results: List[Dict[str, Any]] = []
    totals = {"updated": 0, "skipped": 0, "failed": 0}

    for site_id in normalized_site_ids:
        site_name = _fetch_site_name(base_url, headers, site_id)
        target_devices = device_map.get(site_id) if device_map else None
        normalized_devices: List[str] = []
        if target_devices:
            seen: Set[str] = set()
            for device_id in target_devices:
                if device_id is None:
                    continue
                text = str(device_id).strip()
                if not text or text in seen:
                    continue
                seen.add(text)
                normalized_devices.append(text)

        summary: Dict[str, Any] = {
            "site_id": site_id,
            "site_name": site_name,
            "updated": 0,
            "skipped": 0,
            "failed": 0,
            "changes": [],
            "errors": [],
        }

        if not normalized_devices:
            summary["failed"] = 1
            summary["errors"].append({"reason": "No target devices provided."})
            results.append(summary)
            totals["failed"] += 1
            continue

        for device_id in normalized_devices:
            try:
                device_doc = _fetch_device_document(base_url, headers, site_id, device_id)
            except requests.HTTPError as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    {
                        "device_id": device_id,
                        "reason": f"Device lookup failed: {exc}",
                    }
                )
                continue

            device_name = _device_display_name(device_doc, device_id)
            device_type = device_doc.get("type")
            if device_type != "switch":
                summary["skipped"] += 1
                summary["changes"].append(
                    {
                        "device_id": device_id,
                        "device_name": device_name,
                        "reason": "Device is not a switch.",
                        "status": "skipped",
                    }
                )
                continue

            disable_auto_config = device_doc.get("disable_auto_config")
            if disable_auto_config is not True:
                summary["skipped"] += 1
                summary["changes"].append(
                    {
                        "device_id": device_id,
                        "device_name": device_name,
                        "previous_disable_auto_config": disable_auto_config,
                        "reason": "Cloud management already enabled.",
                        "status": "skipped",
                    }
                )
                continue

            payload = {"disable_auto_config": False}
            change_entry = {
                "device_id": device_id,
                "device_name": device_name,
                "previous_disable_auto_config": disable_auto_config,
            }

            if not dry_run:
                try:
                    _update_device_payload(base_url, headers, site_id, device_id, payload)
                except requests.HTTPError as exc:
                    summary["failed"] += 1
                    summary["errors"].append(
                        {
                            "device_id": device_id,
                            "reason": f"Failed to enable cloud management: {exc}",
                        }
                    )
                    continue
                change_entry["status"] = "success"
                change_entry["message"] = "Cloud management enabled."
                summary["updated"] += 1
            else:
                change_entry["status"] = "preview"
                change_entry["message"] = "Would enable cloud management."
                summary["updated"] += 1

            summary["changes"].append(change_entry)

        results.append(summary)
        totals["updated"] += summary.get("updated", 0)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    totals_with_sites = {**totals, "sites": len(results)}
    totals_with_sites.setdefault(
        "summary",
        _format_summary_message("Enabled cloud management for", totals_with_sites.get("updated", 0)),
    )

    return {
        "ok": True,
        "action_id": ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
        "dry_run": dry_run,
        "results": results,
        "totals": totals_with_sites,
    }


def _execute_ap_rename_action(
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool,
    pause: float,
    device_map: Optional[Mapping[str, Sequence[str]]],
) -> Dict[str, Any]:
    headers = _mist_headers(token)
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    results: List[Dict[str, Any]] = []
    totals = {"renamed": 0, "updated": 0, "skipped": 0, "failed": 0}
    for site_id in normalized_site_ids:
        try:
            limit_ids: Optional[Set[str]] = None
            if device_map is not None:
                device_ids = device_map.get(site_id)
                if device_ids:
                    limit_ids = {str(device_id) for device_id in device_ids if str(device_id).strip()}
            summary = _summarize_site(
                base_url,
                headers,
                site_id,
                dry_run=dry_run,
                pause=pause,
                limit_device_ids=limit_ids,
            )
        except requests.HTTPError as exc:
            results.append(
                {
                    "site_id": site_id,
                    "site_name": site_id,
                    "renamed": 0,
                    "updated": 0,
                    "skipped": 0,
                    "failed": 1,
                    "changes": [],
                    "errors": [
                        {
                            "reason": f"API error: {exc}",
                        }
                    ],
                }
            )
            totals["failed"] += 1
            continue
        results.append(summary)
        renamed_count = summary.get("renamed", 0)
        totals["renamed"] += renamed_count
        totals["updated"] += summary.get("updated", renamed_count)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    totals_with_sites = {**totals, "sites": len(results)}
    totals_with_sites.setdefault("updated", totals_with_sites.get("renamed", 0))
    totals_with_sites.setdefault(
        "summary", _format_summary_message("Renamed", totals_with_sites.get("renamed", 0))
    )

    return {
        "ok": True,
        "action_id": AP_RENAME_ACTION_ID,
        "dry_run": dry_run,
        "results": results,
        "totals": totals_with_sites,
    }


def _execute_dns_override_action(
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool,
    device_map: Optional[Mapping[str, Sequence[str]]],
) -> Dict[str, Any]:
    headers = _mist_headers(token)
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    results: List[Dict[str, Any]] = []
    totals = {"updated": 0, "skipped": 0, "failed": 0}
    for site_id in normalized_site_ids:
        try:
            device_ids = device_map.get(site_id) if device_map else None
            summary = _clear_dns_overrides_for_site(
                base_url,
                headers,
                site_id,
                dry_run=dry_run,
                device_ids=device_ids,
            )
        except requests.HTTPError as exc:
            results.append(
                {
                    "site_id": site_id,
                    "site_name": site_id,
                    "updated": 0,
                    "skipped": 0,
                    "failed": 1,
                    "changes": [],
                    "errors": [
                        {
                            "reason": f"API error: {exc}",
                        }
                    ],
                }
            )
            totals["failed"] += 1
            continue
        results.append(summary)
        totals["updated"] += summary.get("updated", 0)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    totals_with_sites = {**totals, "sites": len(results)}
    totals_with_sites.setdefault(
        "summary",
        _format_summary_message("Cleared DNS overrides for", totals_with_sites.get("updated", 0)),
    )

    return {
        "ok": True,
        "action_id": CLEAR_DNS_OVERRIDE_ACTION_ID,
        "dry_run": dry_run,
        "results": results,
        "totals": totals_with_sites,
    }


def _execute_set_site_variables_action(
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    headers = _mist_headers(token)
    defaults = _load_site_variable_defaults()
    requested_defaults: Dict[str, str] = {}
    if isinstance(metadata, Mapping):
        variables = metadata.get("variables")
        if isinstance(variables, Mapping):
            for key, value in variables.items():
                if not isinstance(key, str) or not key.strip():
                    continue
                if _value_is_set(value):
                    requested_defaults[key.strip()] = str(value).strip()
                elif _value_is_set(defaults.get(key)):
                    requested_defaults[key.strip()] = str(defaults[key]).strip()
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    results: List[Dict[str, Any]] = []
    totals = {"updated": 0, "skipped": 0, "failed": 0}
    effective_defaults = requested_defaults or defaults

    for site_id in normalized_site_ids:
        try:
            summary = _apply_site_variables_for_site(
                base_url,
                headers,
                site_id,
                dry_run=dry_run,
                defaults=effective_defaults,
            )
        except requests.HTTPError as exc:
            results.append(
                {
                    "site_id": site_id,
                    "site_name": site_id,
                    "updated": 0,
                    "skipped": 0,
                    "failed": 1,
                    "changes": [],
                    "errors": [
                        {
                            "reason": f"API error: {exc}",
                        }
                    ],
                }
            )
            totals["failed"] += 1
            continue
        results.append(summary)
        totals["updated"] += summary.get("updated", 0)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    totals_with_sites = {**totals, "sites": len(results)}
    totals_with_sites.setdefault(
        "summary",
        _format_summary_message("Updated site variables for", totals_with_sites.get("updated", 0)),
    )

    return {
        "ok": True,
        "action_id": SET_SITE_VARIABLES_ACTION_ID,
        "dry_run": dry_run,
        "results": results,
        "totals": totals_with_sites,
    }


def execute_audit_action(
    action_id: str,
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool = False,
    pause: float = 0.2,
    device_map: Optional[Mapping[str, Sequence[str]]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    if action_id == AP_RENAME_ACTION_ID:
        return _execute_ap_rename_action(
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            pause=pause,
            device_map=device_map,
        )
    if action_id == CLEAR_DNS_OVERRIDE_ACTION_ID:
        return _execute_dns_override_action(
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            device_map=device_map,
        )
    if action_id == SET_SITE_VARIABLES_ACTION_ID:
        return _execute_set_site_variables_action(
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            metadata=metadata,
        )
    if action_id == ENABLE_CLOUD_MANAGEMENT_ACTION_ID:
        return _execute_cloud_management_action(
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            device_map=device_map,
        )
    if action_id == SET_SPARE_SWITCH_ROLE_ACTION_ID:
        return _execute_set_spare_switch_role_action(
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            metadata=metadata,
        )
    raise ValueError(f"Unsupported action_id: {action_id}")


__all__ = ["execute_audit_action"]
