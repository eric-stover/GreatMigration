"""Compliance/audit checks for Mist site configuration."""

from __future__ import annotations

import ast
import copy
import json
import os
import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import requests

from http_logging import install_http_logging

from audit_actions import (
    AP_RENAME_ACTION_ID,
    CLEAR_DNS_OVERRIDE_ACTION_ID,
    ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
    SET_SITE_VARIABLES_ACTION_ID,
    SET_SPARE_SWITCH_ROLE_ACTION_ID,
)
from logging_utils import get_user_logger


logger = get_user_logger()

install_http_logging()


@dataclass
class SiteContext:
    """Bundle of site-related data used when evaluating compliance checks."""

    site_id: str
    site_name: str
    site: Dict[str, Any] = field(default_factory=dict)
    setting: Dict[str, Any] = field(default_factory=dict)
    templates: Sequence[Dict[str, Any]] = field(default_factory=list)
    devices: Sequence[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Finding:
    """A single non-compliant item detected by a check."""

    site_id: str
    site_name: str
    message: str
    severity: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    actions: Optional[List[Dict[str, Any]]] = None

    def as_dict(self, default_severity: str) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "message": self.message,
            "severity": self.severity or default_severity,
        }
        if self.device_id:
            data["device_id"] = self.device_id
        if self.device_name:
            data["device_name"] = self.device_name
        if self.details is not None:
            data["details"] = self.details
        if self.actions:
            data["actions"] = self.actions
        return data


class ComplianceCheck:
    """Base class for checks that can be executed against a site."""

    id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "warning"

    def prepare_run(self) -> None:  # pragma: no cover - hook
        """Reset any stateful data prior to executing across all sites."""

    def run(self, context: SiteContext) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def suggest_actions(
        self,
        contexts: Sequence[SiteContext],
        findings: Sequence[Finding],
    ) -> List[Dict[str, Any]]:  # pragma: no cover - hook
        """Return optional auto-remediation actions for the given findings."""
        return []


def _normalize_site_name(site: Dict[str, Any]) -> str:
    for key in ("name", "site_name", "display_name"):
        value = site.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return site.get("id") or ""


def _collect_site_variables(context: SiteContext) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    for container in (context.site, context.setting):
        if not isinstance(container, dict):
            continue
        for key in ("variables", "vars", "site_vars", "site_variables"):
            value = container.get(key)
            if isinstance(value, dict):
                candidates.append(value)
    merged: Dict[str, Any] = {}
    for candidate in candidates:
        merged.update({k: v for k, v in candidate.items() if isinstance(k, str)})
    return merged


DEFAULT_REQUIRED_SITE_VARIABLES: Tuple[str, ...] = (
    "hubradiusserver",
    "localradiusserver",
    "siteDNS",
    "hubDNSserver1",
    "hubDNSserver2",
)


def _parse_site_variable_tokens(tokens: Sequence[str], fallback: Sequence[str]) -> Tuple[Tuple[str, ...], Dict[str, str]]:
    required: List[str] = []
    defaults: Dict[str, str] = {}
    seen: Set[str] = set()

    def _add_required(key: str) -> None:
        normalized = key.strip()
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        required.append(normalized)

    for token in tokens:
        if not isinstance(token, str):
            continue
        text = token.strip()
        if not text:
            continue
        if "=" in text:
            key, value = text.split("=", 1)
        elif ":" in text:
            key, value = text.split(":", 1)
        else:
            key, value = text, None
        _add_required(key)
        if value is not None and str(value).strip():
            defaults[key.strip()] = str(value).strip()

    if not required:
        for item in fallback:
            if isinstance(item, str):
                _add_required(item)

    return tuple(required), defaults


def load_site_variable_config(
    var_name: str = "MIST_SITE_VARIABLES",
    default: Sequence[str] = DEFAULT_REQUIRED_SITE_VARIABLES,
) -> Tuple[Tuple[str, ...], Dict[str, str]]:
    raw = os.getenv(var_name)
    tokens = [item.strip() for item in raw.split(",")] if raw is not None else []
    required, defaults = _parse_site_variable_tokens(tokens, default)
    return (required or tuple(default)), defaults


def _load_site_variable_list(var_name: str, default: Sequence[str]) -> Tuple[str, ...]:
    required, _ = load_site_variable_config(var_name, default)
    return required


def _load_version_list_from_env(var_name: str) -> Tuple[str, ...]:
    raw = os.getenv(var_name)
    if raw is None:
        return ()
    values = [item.strip() for item in raw.split(",")]
    return tuple(value for value in values if value)


FIRMWARE_REFRESH_DAYS = 90
SUGGESTED_FIRMWARE_TAG = "junos_suggested"


def _firmware_standards_path() -> Path:
    return Path(__file__).resolve().parent / "standard_fw_versions.json"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601(raw: Any) -> Optional[datetime]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_firmware_standards_doc(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or _firmware_standards_path()
    if not path.exists():
        return {
            "generated_at": None,
            "sources": {},
            "models": {"switch": {}, "ap": {}},
        }
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {
            "generated_at": None,
            "sources": {},
            "models": {"switch": {}, "ap": {}},
        }
    if not isinstance(raw, dict):
        return {
            "generated_at": None,
            "sources": {},
            "models": {"switch": {}, "ap": {}},
        }
    return raw


def _save_firmware_standards_doc(doc: Dict[str, Any], path: Optional[Path] = None) -> None:
    path = path or _firmware_standards_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    doc["generated_at"] = _utc_now().isoformat().replace("+00:00", "Z")
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(doc, handle, indent=2)
        handle.write("\n")
    tmp.replace(path)


def _extract_inventory_models(payload: Any) -> Set[str]:
    models: Set[str] = set()
    rows: Sequence[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, Mapping):
        for key in ("results", "items", "data"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        else:
            rows = []
    else:
        rows = []

    for row in rows:
        if not isinstance(row, Mapping):
            continue
        model = row.get("model")
        if not isinstance(model, str):
            continue
        normalized = model.strip()
        if normalized:
            models.add(normalized)
    return models


def _fetch_org_switch_models(token: str, base_url: str, org_id: str) -> Set[str]:
    url = f"{base_url}/orgs/{org_id}/inventory/count"
    resp = requests.get(
        url,
        headers={"Authorization": f"Token {token}"},
        params={"distinct": "model", "limit": 1000},
        timeout=30,
    )
    resp.raise_for_status()
    return _extract_inventory_models(resp.json())


def _extract_switch_standard_one_versions(doc: Mapping[str, Any]) -> Dict[str, str]:
    models = doc.get("models") if isinstance(doc.get("models"), Mapping) else {}
    switch_rows = models.get("switch") if isinstance(models, Mapping) else {}
    if not isinstance(switch_rows, Mapping):
        return {}

    versions: Dict[str, str] = {}
    for model, entries in switch_rows.items():
        if not isinstance(model, str) or not isinstance(entries, list) or not entries:
            continue
        first = entries[0]
        if not isinstance(first, Mapping):
            continue
        raw_version = first.get("version")
        if not isinstance(raw_version, str):
            continue
        version = raw_version.strip()
        key = model.strip()
        if key and version:
            versions[key] = version
    return versions


def _sync_switch_auto_upgrade_custom_versions(doc: Mapping[str, Any]) -> None:
    token = (os.getenv("MIST_TOKEN") or "").strip()
    if not token:
        logger.info("action=switch_auto_upgrade_sync status=skipped reason=missing_token")
        return

    base_url = _mist_api_base_url()
    org_id = _resolve_mist_org_id(token, base_url)
    if not org_id:
        logger.info("action=switch_auto_upgrade_sync status=skipped reason=missing_org")
        return

    standard_one_by_model = _extract_switch_standard_one_versions(doc)
    if not standard_one_by_model:
        logger.info("action=switch_auto_upgrade_sync status=skipped reason=missing_standard_one_versions")
        return

    try:
        org_models = _fetch_org_switch_models(token, base_url, org_id)
    except requests.RequestException as exc:
        logger.warning("action=switch_auto_upgrade_sync status=failed reason=inventory_lookup error=%s", exc)
        return

    custom_versions = {
        model: version
        for model, version in standard_one_by_model.items()
        if model in org_models
    }
    if not custom_versions:
        logger.info("action=switch_auto_upgrade_sync status=skipped reason=no_matching_org_models")
        return

    headers = {"Authorization": f"Token {token}", "Content-Type": "application/json"}
    setting_url = f"{base_url}/orgs/{org_id}/setting"
    try:
        current_resp = requests.get(setting_url, headers=headers, timeout=30)
        current_resp.raise_for_status()
        current_payload = current_resp.json()
    except requests.RequestException as exc:
        logger.warning("action=switch_auto_upgrade_sync status=failed reason=setting_lookup error=%s", exc)
        return

    switch_payload = current_payload.get("switch") if isinstance(current_payload, Mapping) else {}
    auto_upgrade = switch_payload.get("auto_upgrade") if isinstance(switch_payload, Mapping) else {}
    existing_custom_versions: Dict[str, str] = {}
    if isinstance(auto_upgrade, Mapping):
        raw_custom_versions = auto_upgrade.get("custom_versions")
        if isinstance(raw_custom_versions, Mapping):
            existing_custom_versions = {
                str(model).strip(): str(version).strip()
                for model, version in raw_custom_versions.items()
                if str(model).strip() and str(version).strip()
            }

    if existing_custom_versions == custom_versions:
        logger.info("action=switch_auto_upgrade_sync status=skipped reason=unchanged")
        return

    if isinstance(auto_upgrade, Mapping):
        updated_auto_upgrade = dict(auto_upgrade)
    else:
        updated_auto_upgrade = {}
    updated_auto_upgrade["custom_versions"] = custom_versions

    put_payload = {"switch": {"auto_upgrade": updated_auto_upgrade}}
    try:
        put_resp = requests.put(setting_url, headers=headers, json=put_payload, timeout=30)
        put_resp.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("action=switch_auto_upgrade_sync status=failed reason=setting_update error=%s", exc)
        return

    logger.info(
        "action=switch_auto_upgrade_sync status=updated org_id=%s models=%s",
        org_id,
        len(custom_versions),
    )




def _mist_api_base_url() -> str:
    raw = (os.getenv("MIST_BASE_URL") or "https://api.ac2.mist.com").strip().rstrip("/")
    if not raw:
        raw = "https://api.ac2.mist.com"
    if raw.endswith("/api/v1"):
        return raw
    return f"{raw}/api/v1"


_MIST_ORG_ID_CACHE: Optional[str] = None


def _resolve_mist_org_id(token: str, base_url: str) -> Optional[str]:
    configured_org_id = (os.getenv("MIST_ORG_ID") or "").strip()
    if configured_org_id:
        return configured_org_id

    global _MIST_ORG_ID_CACHE
    if _MIST_ORG_ID_CACHE:
        return _MIST_ORG_ID_CACHE

    whoami_url = f"{base_url}/self"
    logger.info("action=mist_self_discovery url=%s", whoami_url)
    try:
        resp = requests.get(
            whoami_url,
            headers={"Authorization": f"Token {token}"},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.warning("action=mist_self_discovery status=failed error=%s", exc)
        return None

    payload = resp.json()
    if not isinstance(payload, Mapping):
        logger.warning("action=mist_self_discovery status=failed reason=unexpected_payload")
        return None

    discovered_org_id = payload.get("org_id")
    if not isinstance(discovered_org_id, str) or not discovered_org_id.strip():
        logger.warning("action=mist_self_discovery status=failed reason=missing_org_id")
        return None

    _MIST_ORG_ID_CACHE = discovered_org_id.strip()
    logger.info("action=mist_self_discovery status=resolved")
    return _MIST_ORG_ID_CACHE


def _fetch_org_site_ids(token: str, base_url: str, org_id: str) -> List[str]:
    url = f"{base_url}/orgs/{org_id}/sites"
    logger.info("action=mist_sites_discovery url=%s", url)
    resp = requests.get(
        url,
        headers={"Authorization": f"Token {token}"},
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()

    rows: Sequence[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, Mapping):
        for key in ("results", "items", "data"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        else:
            rows = []
    else:
        rows = []

    site_ids: List[str] = []
    seen: Set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        raw_site_id = row.get("id")
        if not isinstance(raw_site_id, str):
            continue
        site_id = raw_site_id.strip()
        if not site_id or site_id in seen:
            continue
        seen.add(site_id)
        site_ids.append(site_id)
    return site_ids


def _fetch_site_versions_for_type(token: str, base_url: str, site_id: str, device_type: str) -> List[Dict[str, Any]]:
    url = f"{base_url}/sites/{site_id}/devices/versions"
    logger.info("action=firmware_versions_request scope=site type=%s site_id=%s url=%s", device_type, site_id, url)
    resp = requests.get(
        url,
        headers={"Authorization": f"Token {token}"},
        params={"type": device_type},
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()

    rows: Sequence[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, Mapping):
        for key in ("results", "items", "data"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        else:
            rows = []
    else:
        rows = []

    return [row for row in rows if isinstance(row, dict)]


def _fetch_versions_for_type(device_type: str) -> List[Dict[str, Any]]:
    token = (os.getenv("MIST_TOKEN") or "").strip()
    base = _mist_api_base_url()
    org_id = _resolve_mist_org_id(token, base) if token else None
    if not token or not org_id:
        logger.info(
            "action=firmware_versions_request type=%s status=skipped reason=missing_mist_env token_present=%s org_present=%s",
            device_type,
            bool(token),
            bool(org_id),
        )
        return []
    url = f"{base}/orgs/{org_id}/devices/versions"
    logger.info("action=firmware_versions_request type=%s url=%s", device_type, url)
    resp = requests.get(
        url,
        headers={"Authorization": f"Token {token}"},
        params={"type": device_type},
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()

    rows: Sequence[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, Mapping):
        for key in ("results", "items", "data"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        else:
            rows = []
    else:
        rows = []

    filtered_rows = [row for row in rows if isinstance(row, dict)]
    if filtered_rows or device_type != "ap":
        return filtered_rows

    # AP version catalogs are sometimes empty at the org endpoint; fallback to site-level catalogs.
    try:
        site_ids = _fetch_org_site_ids(token, base, org_id)
    except requests.RequestException:
        return filtered_rows

    merged_rows: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, Any, Any]] = set()
    for site_id in site_ids:
        try:
            site_rows = _fetch_site_versions_for_type(token, base, site_id, device_type)
        except requests.RequestException:
            continue
        for row in site_rows:
            key = (
                str(row.get("model") or "").strip(),
                row.get("version"),
                row.get("record_id"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged_rows.append(row)
    return merged_rows




def _standards_doc_has_versions(doc: Mapping[str, Any]) -> bool:
    models = doc.get("models") if isinstance(doc.get("models"), Mapping) else None
    if not isinstance(models, Mapping):
        return False
    for device_type in ("switch", "ap"):
        type_blob = models.get(device_type)
        if not isinstance(type_blob, Mapping):
            continue
        for entries in type_blob.values():
            if not isinstance(entries, list):
                continue
            for item in entries:
                if not isinstance(item, Mapping):
                    continue
                version = item.get("version")
                if isinstance(version, str) and version.strip():
                    return True
    return False


def _row_matches_standard_firmware_filter(row: Mapping[str, Any], device_type: str) -> bool:
    if device_type == "ap":
        tag = row.get("tag")
        return isinstance(tag, str) and tag.strip().lower() == "alpha"

    tags = row.get("tags")
    normalized_tags: Set[str] = set()
    if isinstance(tags, list):
        normalized_tags = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
    elif isinstance(tags, str):
        normalized_tags = {part.strip().lower() for part in tags.split(",") if part.strip()}

    return SUGGESTED_FIRMWARE_TAG.lower() in normalized_tags


def _sanitize_standard_firmware_entry(row: Mapping[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in row.items():
        if key == "_version":
            continue
        sanitized[key] = value
    return sanitized

def _refresh_firmware_standards_if_needed(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or _firmware_standards_path()
    logger.info("action=firmware_standards_refresh path=%s", path)
    doc = _load_firmware_standards_doc(path)
    generated_at = _parse_iso8601(doc.get("generated_at"))
    has_versions = _standards_doc_has_versions(doc)
    if generated_at is not None and has_versions and (_utc_now() - generated_at) < timedelta(days=FIRMWARE_REFRESH_DAYS):
        logger.info("action=firmware_standards_refresh status=skipped reason=recent_cache")
        return doc

    previous_standard_one = _extract_switch_standard_one_versions(doc)
    updated = copy.deepcopy(doc)
    models = updated.setdefault("models", {})
    sources = updated.setdefault("sources", {})
    any_changes = False
    for device_type in ("switch", "ap"):
        try:
            rows = _fetch_versions_for_type(device_type)
        except requests.RequestException:
            continue
        by_model: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            model = row.get("model")
            version = row.get("version")
            if not isinstance(model, str) or not model.strip() or not isinstance(version, str) or not version.strip():
                continue
            if not _row_matches_standard_firmware_filter(row, device_type):
                continue

            entry = _sanitize_standard_firmware_entry(row)
            entry["version"] = version.strip()
            bucket = by_model.setdefault(model.strip(), [])
            if any(existing.get("version") == version for existing in bucket):
                continue
            bucket.append(entry)

        if by_model:
            models[device_type] = by_model
            resolved_org_id = _resolve_mist_org_id((os.getenv("MIST_TOKEN") or "").strip(), _mist_api_base_url()) or ""
            sources[device_type] = {
                "endpoint": f"/orgs/{resolved_org_id}/devices/versions?type={device_type}",
                "tag_filter": "alpha" if device_type == "ap" else SUGGESTED_FIRMWARE_TAG,
                "updated_at": _utc_now().isoformat().replace("+00:00", "Z"),
            }
            any_changes = True

    if any_changes:
        _save_firmware_standards_doc(updated, path)
        new_standard_one = _extract_switch_standard_one_versions(updated)
        if new_standard_one != previous_standard_one:
            _sync_switch_auto_upgrade_custom_versions(updated)
        model_counts = {
            key: len(value) for key, value in models.items() if isinstance(value, Mapping)
        }
        logger.info(
            "action=firmware_standards_refresh status=updated model_counts=%s",
            model_counts,
        )
        return updated
    logger.info("action=firmware_standards_refresh status=unchanged reason=no_suggested_versions")
    return doc


def _load_allowed_versions_from_standard_doc(device_type: str) -> Tuple[str, ...]:
    """Return distinct allowed versions for a device type across all models."""

    by_model = _load_allowed_versions_by_model_from_standard_doc(device_type)
    versions: List[str] = []
    seen: Set[str] = set()
    for allowed_versions in by_model.values():
        for version in allowed_versions:
            if version in seen:
                continue
            seen.add(version)
            versions.append(version)
    return tuple(versions)


def _normalize_device_model(model: Any) -> str:
    if not isinstance(model, str):
        return ""
    return model.strip().strip('"').strip("'").upper()


def _load_allowed_versions_by_model_from_standard_doc(device_type: str) -> Dict[str, Tuple[str, ...]]:
    doc = _refresh_firmware_standards_if_needed()
    models = doc.get("models") if isinstance(doc.get("models"), Mapping) else {}
    type_blob = models.get(device_type) if isinstance(models, Mapping) else {}
    if not isinstance(type_blob, Mapping):
        return {}
    versions_by_model: Dict[str, Tuple[str, ...]] = {}
    for model, entries in type_blob.items():
        model_key = _normalize_device_model(model)
        if not model_key:
            continue
        if not isinstance(entries, list):
            continue
        versions: List[str] = []
        seen: Set[str] = set()
        for item in entries:
            if not isinstance(item, Mapping):
                continue
            version = item.get("version")
            if not isinstance(version, str):
                continue
            normalized = version.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            versions.append(normalized)
        versions_by_model[model_key] = tuple(versions)
    return versions_by_model


class RequiredSiteVariablesCheck(ComplianceCheck):
    id = "required_site_variables"
    name = "Required site variables"
    description = "Ensure required Mist site variables are defined."
    severity = "error"

    def __init__(self, required_keys: Optional[Sequence[str]] = None) -> None:
        default_keys, default_values = load_site_variable_config("MIST_SITE_VARIABLES", DEFAULT_REQUIRED_SITE_VARIABLES)
        if required_keys is None:
            self.required_keys: Tuple[str, ...] = tuple(default_keys)
        else:
            self.required_keys = tuple(required_keys)
        self.variable_defaults: Dict[str, str] = default_values

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []
        variables = _collect_site_variables(context)
        missing = [key for key in self.required_keys if key not in variables or variables.get(key) in (None, "")]
        actions_by_key: Dict[str, Dict[str, Any]] = {}
        for key in missing:
            if key not in self.variable_defaults:
                continue
            value = self.variable_defaults.get(key)
            if value in (None, ""):
                continue
            precheck_messages = [
                f"Will set {key} using environment defaults."
            ]
            actions_by_key[key] = {
                "id": SET_SITE_VARIABLES_ACTION_ID,
                "label": "Set required site variables",
                "button_label": "1 Click Fix Now",
                "site_ids": [context.site_id],
                "metadata": {
                    "variables": {key: value},
                    "prechecks": {
                        "can_run": True,
                        "messages": precheck_messages,
                    },
                },
            }
        for key in missing:
            action = actions_by_key.get(key)
            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    message=f"Site variable '{key}' is not defined.",
                    actions=[action] if action else None,
                )
            )
        return findings


def _collect_template_names(context: SiteContext) -> Set[str]:
    names: Set[str] = set()
    for container in (context.site, context.setting):
        if not isinstance(container, dict):
            continue
        for key in ("networktemplate_name", "network_template_name", "template_name"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                names.add(value)
    for tmpl in context.templates:
        if not isinstance(tmpl, dict):
            continue
        for key in ("name", "template_name"):
            value = tmpl.get(key)
            if isinstance(value, str) and value.strip():
                names.add(value)
    return names


def _collect_template_ids(context: SiteContext) -> Set[str]:
    ids: Set[str] = set()
    for container in (context.site, context.setting):
        if not isinstance(container, dict):
            continue
        for key in (
            "networktemplate_id",
            "network_template_id",
            "template_id",
            "switch_template_id",
        ):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                ids.add(value)
    for tmpl in context.templates:
        if not isinstance(tmpl, dict):
            continue
        for key in ("id", "template_id"):
            value = tmpl.get(key)
            if isinstance(value, str) and value.strip():
                ids.add(value)
    return ids


def _resolve_device_template_id(device: Mapping[str, Any]) -> Optional[str]:
    for key in ("template_id", "switch_template_id"):
        value = device.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _site_is_lab(site_name: Optional[str]) -> bool:
    if not site_name:
        return False
    return "lab" in site_name.lower()


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
        if not any(_has_value(variables.get(name)) for name in group):
            label = _format_dns_var_group_label(group)
            if label:
                missing.append(label)
    return (not missing, missing)


def _expected_template_details(site_name: Optional[str]) -> Dict[str, Any]:
    is_lab = _site_is_lab(site_name)
    if is_lab:
        allowed_names = [
            name
            for name in (
                DNS_OVERRIDE_LAB_TEMPLATE_NAME,
                DNS_OVERRIDE_TEMPLATE_NAME,
            )
            if isinstance(name, str) and name
        ]
        allowed_ids: Tuple[str, ...] = tuple(
            dict.fromkeys(
                value
                for value in (
                    *(DNS_OVERRIDE_LAB_TEMPLATE_IDS or ()),
                    *(DNS_OVERRIDE_PROD_TEMPLATE_IDS or ()),
                )
                if isinstance(value, str) and value
            )
        )
        preferred = DNS_OVERRIDE_LAB_TEMPLATE_NAME or (allowed_names[0] if allowed_names else "")
    else:
        allowed_names = [
            name
            for name in (
                DNS_OVERRIDE_TEMPLATE_NAME,
            )
            if isinstance(name, str) and name
        ]
        allowed_ids = tuple(
            dict.fromkeys(
                value
                for value in (DNS_OVERRIDE_PROD_TEMPLATE_IDS or ())
                if isinstance(value, str) and value
            )
        )
        preferred = DNS_OVERRIDE_TEMPLATE_NAME
    return {
        "site_type": "lab" if is_lab else "production",
        "allowed_template_names": tuple(allowed_names),
        "allowed_template_ids": allowed_ids,
        "preferred_template_name": preferred,
    }


def _template_matches_requirements(
    template_names: Set[str],
    template_ids: Set[str],
    allowed_names: Sequence[str],
    allowed_ids: Sequence[str],
    device_template_id: Optional[str],
) -> bool:
    normalized_allowed_names = {name for name in allowed_names if isinstance(name, str) and name}
    normalized_allowed_ids = {tid for tid in allowed_ids if isinstance(tid, str) and tid}

    if device_template_id:
        value = device_template_id.strip()
        if value and value in normalized_allowed_ids:
            return True

    if normalized_allowed_ids and template_ids.intersection(normalized_allowed_ids):
        return True

    if normalized_allowed_names and template_names.intersection(normalized_allowed_names):
        return True

    return False


def _format_template_precheck_message(allowed_names: Sequence[str]) -> str:
    filtered = [name for name in allowed_names if isinstance(name, str) and name]
    if not filtered:
        return "Required switch template is not applied to this site."
    if len(filtered) == 1:
        return f"Apply '{filtered[0]}' template to this site."
    if len(filtered) == 2:
        return f"Apply '{filtered[0]}' or '{filtered[1]}' template to this site."
    joined = ", ".join(f"'{name}'" for name in filtered[:-1])
    return f"Apply one of these templates to this site: {joined}, or '{filtered[-1]}'."


class SwitchTemplateConfigurationCheck(ComplianceCheck):
    id = "switch_template_configuration"
    name = "Switch Template Configuration"
    description = (
        "Ensure lab sites use approved switch templates and non-lab sites remain on the production template."
    )
    severity = "warning"

    prod_template_name: str = "Prod - Standard Template"
    lab_template_name: str = "Test - Standard Template"

    def run(self, context: SiteContext) -> List[Finding]:
        template_names = _collect_template_names(context)
        if not template_names:
            return []

        site_name_upper = (context.site_name or "").upper()
        is_lab_site = "LAB" in site_name_upper
        findings: List[Finding] = []
        sorted_templates = ", ".join(sorted(template_names)) or "none"

        if is_lab_site:
            allowed = {self.prod_template_name, self.lab_template_name}
            if template_names.isdisjoint(allowed):
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        message=(
                            "Lab site should apply either "
                            f"'{self.prod_template_name}' or '{self.lab_template_name}' but current templates are: "
                            f"{sorted_templates}."
                        ),
                    )
                )
        else:
            if self.prod_template_name not in template_names:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        message=(
                            f"Site should apply '{self.prod_template_name}' but current templates are: {sorted_templates}."
                        ),
                    )
                )
            extra_templates = template_names - {self.prod_template_name}
            if self.prod_template_name in template_names and extra_templates:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        message=(
                            f"Site should not apply additional templates ({', '.join(sorted(extra_templates))}) when "
                            f"using '{self.prod_template_name}'."
                        ),
                    )
                )

        return findings


@dataclass
class OverrideEntry:
    path: str
    port_label: Optional[str] = None
    port_number: Optional[int] = None


def _collect_override_paths(data: Any, prefix: str = "") -> List[str]:
    paths: List[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            key_lower = key.lower()
            if "override" in key_lower and _has_value(value):
                paths.append(new_prefix)
                continue
            paths.extend(_collect_override_paths(value, new_prefix))
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            new_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            paths.extend(_collect_override_paths(value, new_prefix))
    return paths


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes)):
        return bool(str(value).strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _normalize_port_label(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _extract_port_number(label: Optional[str]) -> Optional[int]:
    if not label:
        return None
    digits = "".join(ch if ch.isdigit() else " " for ch in label)
    try:
        parts = [int(part) for part in digits.split() if part]
    except ValueError:
        return None
    if not parts:
        return None
    # Assume the last numeric segment represents the port number
    return parts[-1]


def _collect_port_overrides(device: Dict[str, Any]) -> List[OverrideEntry]:
    entries: List[OverrideEntry] = []
    port_overrides = device.get("port_overrides")
    if isinstance(port_overrides, list):
        for idx, item in enumerate(port_overrides):
            if not isinstance(item, dict):
                continue
            label = _normalize_port_label(
                item.get("port_id") or item.get("name") or item.get("port") or item.get("port_name")
            )
            entries.append(
                OverrideEntry(
                    path=f"port_overrides[{idx}]",
                    port_label=label,
                    port_number=_extract_port_number(label),
                )
            )
    elif isinstance(port_overrides, dict):
        for key, value in port_overrides.items():
            if not _has_value(value):
                continue
            label = _normalize_port_label(key)
            entries.append(
                OverrideEntry(
                    path=f"port_overrides.{key}",
                    port_label=label,
                    port_number=_extract_port_number(label),
                )
            )
    return entries


def _is_access_switch(device: Dict[str, Any]) -> bool:
    role_candidates: Sequence[Any] = (
        device.get("role"),
        device.get("device_profile"),
        device.get("device_profile_name"),
        device.get("profile"),
        device.get("template"),
    )
    for value in role_candidates:
        if isinstance(value, str) and "access" in value.lower():
            return True
    tags = device.get("tags")
    if isinstance(tags, (list, tuple, set)):
        for tag in tags:
            if isinstance(tag, str) and "access" in tag.lower():
                return True
    return False


def _is_switch(device: Dict[str, Any]) -> bool:
    """Best-effort heuristic to determine whether a device is a switch."""

    type_hints: Sequence[Any] = (
        device.get("type"),
        device.get("device_type"),
        device.get("category"),
        device.get("role"),
        device.get("device_profile"),
        device.get("device_profile_name"),
    )
    for value in type_hints:
        if isinstance(value, str):
            lowered = value.lower()
            if "switch" in lowered:
                return True
            if lowered in {"access", "distribution", "core", "wan"}:
                return True
    model = device.get("model")
    if isinstance(model, str) and "switch" in model.lower():
        return True
    return False


def _is_access_point(device: Dict[str, Any]) -> bool:
    """Return True when the device appears to be an access point/AP."""

    type_hints: Sequence[Any] = (
        device.get("type"),
        device.get("device_type"),
        device.get("category"),
        device.get("role"),
        device.get("device_profile"),
        device.get("device_profile_name"),
    )
    for value in type_hints:
        if isinstance(value, str) and "ap" in value.lower():
            return True
    model = device.get("model")
    if isinstance(model, str) and "ap" in model.lower():
        return True
    return False


def _iter_psu_entries(raw_psus: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(raw_psus, dict):
        yield raw_psus
        return
    if isinstance(raw_psus, list):
        for item in raw_psus:
            if isinstance(item, dict):
                yield item
            elif isinstance(item, list):
                for nested in item:
                    if isinstance(nested, dict):
                        yield nested


def _extract_module_slot(module: Mapping[str, Any]) -> Optional[str]:
    for key in ("_idx", "fpc_idx", "slot", "slot_id", "member_id", "node_id", "unit"):
        value = module.get(key)
        if isinstance(value, (int, float)):
            return str(int(value))
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _iter_device_psu_entries(device: Mapping[str, Any]) -> Iterable[Dict[str, Any]]:
    for psu in _iter_psu_entries(device.get("psus")):
        yield dict(psu)

    module_stat = device.get("module_stat")
    if not isinstance(module_stat, list):
        return

    for module in module_stat:
        if not isinstance(module, Mapping):
            continue
        module_slot = _extract_module_slot(module)
        for psu in _iter_psu_entries(module.get("psus")):
            entry = dict(psu)
            if module_slot and not entry.get("slot"):
                entry["slot"] = module_slot
            yield entry


def _extract_psu_slot(psu: Mapping[str, Any]) -> Optional[str]:
    for key in ("slot", "slot_id", "switch_id", "member_id", "node_id", "unit", "stack_member"):
        value = psu.get(key)
        if isinstance(value, (int, float)):
            return str(int(value))
        if isinstance(value, str) and value.strip():
            return value.strip()

    for candidate in (psu.get("name"), psu.get("description")):
        if not isinstance(candidate, str):
            continue
        for pattern in (
            r"(?:switch|member|slot|node|unit)\s*([0-9]+)",
            r"fpc\s*([0-9]+)",
        ):
            match = re.search(pattern, candidate, flags=re.IGNORECASE)
            if match:
                return match.group(1)
    return None


def _extract_psu_label(psu: Mapping[str, Any], index: int) -> str:
    name = psu.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return f"PSU {index}"


def _extract_firmware_version(device: Mapping[str, Any]) -> str:
    """Return a firmware version string from a device payload when possible."""

    candidates: Sequence[Any] = (
        device.get("firmware_version"),
        device.get("version"),
        device.get("ap_fw_version"),
        device.get("sw_version"),
    )
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    details = device.get("details")
    if isinstance(details, Mapping):
        nested = details.get("version")
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return ""


def _is_device_online(device: Dict[str, Any]) -> bool:
    """Return True when the device appears to be online/connected."""

    online_tokens = ("connected", "online", "up", "ready")
    offline_tokens = ("disconnected", "offline", "down", "not connected", "not-connected")

    def interpret_status_value(value: Any) -> Optional[bool]:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if value == 1:
                return True
            if value == 0:
                return False
            return None
        if isinstance(value, str):
            lower = value.strip().lower()
            if not lower:
                return None
            for token in offline_tokens:
                if token in lower:
                    return False
            for token in online_tokens:
                if re.search(rf"\b{re.escape(token)}\b", lower):
                    return True
            return None
        return None

    def iter_status_values(value: Any):
        stack: List[Any] = [value]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                stack.extend(current.values())
            elif isinstance(current, (list, tuple, set)):
                stack.extend(current)
            else:
                yield current

    candidates: List[Any] = []
    primary_status = device.get("status")
    if primary_status is not None:
        candidates.append(primary_status)
    for key in (
        "connection_state",
        "connection",
        "connectivity",
        "device_status",
        "mgmt_connection",
        "management_connection",
        "oper_status",
        "operational_status",
        "state",
        "link_state",
        "online",
        "connected",
        "ready",
        "up",
        "is_online",
    ):
        if key in device:
            candidates.append(device.get(key))

    for key, value in device.items():
        if isinstance(key, str):
            lowered = key.lower()
            if lowered.endswith("_status") or lowered.endswith("_state"):
                candidates.append(value)

    for candidate in candidates:
        for value in iter_status_values(candidate):
            result = interpret_status_value(value)
            if result is True:
                return True
    return False



def _extract_device_switch_config(device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    keys = (
        "switch_config",
        "config",
        "configuration",
        "switch",
        "device_config",
    )
    for key in keys:
        value = device.get(key)
        if isinstance(value, dict):
            return value
    for key in ("data", "details", "template"):
        nested = device.get(key)
        if isinstance(nested, dict):
            value = _extract_device_switch_config(nested)
            if value is not None:
                return value
    return None


def _extract_switch_template_config(container: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    keys = (
        "switch_config",
        "config",
        "configuration",
        "switch",
        "device_config",
    )
    for key in keys:
        value = container.get(key)
        if isinstance(value, dict):
            return value
    for key in ("template", "data", "definition"):
        nested = container.get(key)
        if isinstance(nested, dict):
            value = _extract_switch_template_config(nested)
            if value is not None:
                return value
    return None


@dataclass
class SwitchTemplateInfo:
    template_id: Optional[str]
    name: Optional[str]
    config: Dict[str, Any]


def _gather_switch_templates(context: SiteContext) -> List[SwitchTemplateInfo]:
    templates: List[SwitchTemplateInfo] = []
    containers: List[Dict[str, Any]] = []

    if isinstance(context.setting, dict):
        containers.append(context.setting)
    containers.extend([tpl for tpl in context.templates if isinstance(tpl, dict)])

    seen: Set[Tuple[Optional[str], Optional[str]]] = set()
    for container in containers:
        config = _extract_switch_template_config(container)
        if not config:
            continue
        template_id = None
        for key in ("template_id", "id", "networktemplate_id", "switch_template_id"):
            value = container.get(key)
            if value is None:
                continue
            template_id = str(value)
            break
        name = None
        for key in ("name", "template_name", "networktemplate_name"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                name = value
                break
        identity = (template_id, name)
        if identity in seen:
            continue
        seen.add(identity)
        templates.append(SwitchTemplateInfo(template_id=template_id, name=name, config=config))
    return templates


def _candidate_template_identifiers(device: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    id_candidates: List[str] = []
    name_candidates: List[str] = []
    for key in (
        "switch_template_id",
        "template_id",
        "networktemplate_id",
        "network_template_id",
        "device_template_id",
    ):
        value = device.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            id_candidates.append(text)
    for key in (
        "switch_template",
        "switch_template_name",
        "template",
        "template_name",
        "networktemplate_name",
    ):
        value = device.get(key)
        if isinstance(value, str):
            text = value.strip()
            if text:
                name_candidates.append(text)
    return id_candidates, name_candidates


def _resolve_switch_template(
    device: Dict[str, Any], templates: Sequence[SwitchTemplateInfo]
) -> Optional[SwitchTemplateInfo]:
    if not templates:
        return None
    id_candidates, name_candidates = _candidate_template_identifiers(device)
    for candidate in id_candidates:
        for template in templates:
            if template.template_id and template.template_id == candidate:
                return template
    for candidate in name_candidates:
        for template in templates:
            if template.name and template.name == candidate:
                return template
    if len(templates) == 1:
        return templates[0]
    return None


IGNORED_CONFIG_KEYS: Set[str] = {
    "id",
    "uuid",
    "mac",
    "serial",
    "last_modified",
    "modified",
    "updated",
    "updated_at",
    "updated_time",
    "created",
    "created_at",
    "created_time",
    "last_seen",
    "timestamp",
    "version",
}

ALLOWED_ADDITIONAL_CONFIG_KEYS: Set[str] = {"image1_url", "image2_url", "image3_url"}

WAN_ROLE_KEYWORDS: Tuple[str, ...] = ("wan",)
WAN_ALLOWED_UPLINK_SUFFIXES: Tuple[str, ...] = ("0/0/0", "0/0/4", "0/0/8", "0/0/12", "0/0/16")
WAN_ALLOWED_CONFIG_PATH_PREFIXES: Tuple[str, ...] = (
    "mgmt_ip_config",
    "mgmt_port_config",
    "mgmt_interface_config",
    "oob_ip_config",
    "oob_port_config",
    "oob_interface_config",
)


def _diff_configs(
    expected: Any,
    actual: Any,
    path: str = "",
    *,
    ignore_keys: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    ignore_keys = ignore_keys or set()

    if isinstance(expected, dict) and isinstance(actual, dict):
        diffs: List[Dict[str, Any]] = []
        for key, exp_value in expected.items():
            if key in ignore_keys:
                continue
            new_path = f"{path}.{key}" if path else str(key)
            if key not in actual:
                diffs.append({"path": new_path, "expected": exp_value, "actual": None})
                continue
            diffs.extend(
                _diff_configs(
                    exp_value,
                    actual[key],
                    new_path,
                    ignore_keys=ignore_keys,
                )
            )
        for key, act_value in actual.items():
            if key in ignore_keys:
                continue
            if key in expected:
                continue
            new_path = f"{path}.{key}" if path else str(key)
            diffs.append({"path": new_path, "expected": None, "actual": act_value})
        return diffs
    if isinstance(expected, list) and isinstance(actual, list):
        diffs: List[Dict[str, Any]] = []
        length = max(len(expected), len(actual))
        for idx in range(length):
            new_path = f"{path}[{idx}]" if path else f"[{idx}]"
            if idx >= len(expected):
                diffs.append({"path": new_path, "expected": None, "actual": actual[idx]})
            elif idx >= len(actual):
                diffs.append({"path": new_path, "expected": expected[idx], "actual": None})
            else:
                diffs.extend(
                    _diff_configs(
                        expected[idx],
                        actual[idx],
                        new_path,
                        ignore_keys=ignore_keys,
                    )
                )
        return diffs
    if expected != actual:
        return [
            {
                "path": path or ".",
                "expected": expected,
                "actual": actual,
            }
        ]
    return []


def _evaluate_wan_oob_ip_config(actual: Any) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []

    def _make_diff(path: str, expected: Any, value: Any) -> Dict[str, Any]:
        diff: Dict[str, Any] = {
            "path": path,
            "expected": expected,
            "actual": value,
            "wan_oob_validation": True,
        }
        return diff

    if actual is None:
        diffs.append(
            _make_diff(
                "oob_ip_config",
                "defined static out-of-band management configuration",
                actual,
            )
        )
        return diffs

    if not isinstance(actual, dict):
        diffs.append(
            _make_diff(
                "oob_ip_config",
                "dictionary of out-of-band management configuration values",
                actual,
            )
        )
        return diffs

    type_value = actual.get("type") or actual.get("ip_assignment")
    type_normalized = str(type_value).strip().lower() if isinstance(type_value, (str, bytes)) else None
    if type_normalized != "static":
        diffs.append(
            _make_diff(
                "oob_ip_config.type",
                "static",
                type_value,
            )
        )

    for key in ("ip", "netmask", "gateway"):
        value = actual.get(key)
        if not (isinstance(value, str) and value.strip()):
            diffs.append(
                _make_diff(
                    f"oob_ip_config.{key}",
                    "defined value",
                    value,
                )
            )

    use_mgmt_vrf = actual.get("use_mgmt_vrf")
    if use_mgmt_vrf is not True:
        diffs.append(
            _make_diff(
                "oob_ip_config.use_mgmt_vrf",
                True,
                use_mgmt_vrf,
            )
        )

    use_mgmt_host_out = actual.get("use_mgmt_vrf_for_host_out")
    if use_mgmt_host_out is not True:
        diffs.append(
            _make_diff(
                "oob_ip_config.use_mgmt_vrf_for_host_out",
                True,
                use_mgmt_host_out,
            )
        )

    return diffs


def _evaluate_wan_active_ports(if_stat: Any) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    if if_stat is None:
        return diffs
    if not isinstance(if_stat, dict):
        return [
            {
                "path": "if_stat",
                "expected": "dictionary of interface stats",
                "actual": if_stat,
            }
        ]

    allowed_suffixes = set(WAN_ALLOWED_UPLINK_SUFFIXES)
    unexpected_ports: Set[str] = set()
    for key, value in if_stat.items():
        if not isinstance(value, dict):
            continue
        if not value.get("up"):
            continue
        port_id_value = value.get("port_id")
        if isinstance(port_id_value, str) and port_id_value.strip():
            port_id = port_id_value.strip()
        elif isinstance(key, str):
            port_id = key.split(".", 1)[0].strip()
        else:
            continue
        match = re.search(r"(\d+/\d+/\d+)$", port_id)
        if match is None:
            continue
        if match.group(1) not in allowed_suffixes:
            unexpected_ports.add(port_id)

    if unexpected_ports:
        diffs.append(
            {
                "path": "if_stat",
                "expected": f"only allowed WAN ports can be up ({', '.join(WAN_ALLOWED_UPLINK_SUFFIXES)})",
                "actual": sorted(unexpected_ports),
            }
        )
    return diffs


def _role_scoped_switch_configs(
    role: Any,
    template_config: Dict[str, Any],
    device_config: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any], Any, Any]:
    expected_trimmed: Dict[str, Any] = copy.deepcopy(template_config)
    actual_trimmed: Dict[str, Any] = copy.deepcopy(device_config)

    expected_ip = expected_trimmed.pop("ip_config", None)
    actual_ip = actual_trimmed.pop("ip_config", None)

    expected_trimmed.pop("port_config", None)
    actual_trimmed.pop("port_config", None)

    return expected_trimmed, actual_trimmed, expected_ip, actual_ip


def _diff_path_port_number(path: str) -> Optional[int]:
    match = re.search(r"(?:port|ports|ge-|xe-|et-).*?(\d+)$", path.lower())
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    tokens = re.findall(r"(\d+)", path)
    for token in reversed(tokens):
        try:
            return int(token)
        except ValueError:
            continue
    return None


def _evaluate_ip_config(expected: Any, actual: Any) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []

    if actual is None:
        diffs.append({
            "path": "ip_config",
            "expected": expected or "defined static IP configuration",
            "actual": actual,
        })
        return diffs

    if not isinstance(actual, dict):
        diffs.append({
            "path": "ip_config",
            "expected": "dictionary of IP configuration values",
            "actual": actual,
        })
        return diffs

    expected_type = None
    expected_network = None
    if isinstance(expected, dict):
        expected_type = expected.get("type")
        expected_network = expected.get("network")

    actual_type = actual.get("type")
    target_type = expected_type or "static"
    if actual_type != target_type:
        diffs.append({
            "path": "ip_config.type",
            "expected": target_type,
            "actual": actual_type,
        })

    actual_ip = actual.get("ip")
    if not (isinstance(actual_ip, str) and actual_ip.startswith("10.")):
        diffs.append({
            "path": "ip_config.ip",
            "expected": "address beginning with '10.'",
            "actual": actual_ip,
        })

    actual_gateway = actual.get("gateway")
    if not (isinstance(actual_gateway, str) and actual_gateway.startswith("10.")):
        diffs.append({
            "path": "ip_config.gateway",
            "expected": "gateway beginning with '10.'",
            "actual": actual_gateway,
        })

    actual_network = actual.get("network")
    target_network = expected_network or "IT_Mgmt"
    if target_network and actual_network != target_network:
        diffs.append({
            "path": "ip_config.network",
            "expected": target_network,
            "actual": actual_network,
        })

    if "netmask" not in actual:
        diffs.append({
            "path": "ip_config.netmask",
            "expected": "defined netmask",
            "actual": actual.get("netmask"),
        })

    allowed_ip_keys = {"type", "ip", "netmask", "network", "gateway"}
    for key in sorted(actual.keys()):
        if key in allowed_ip_keys:
            continue
        diffs.append({
            "path": f"ip_config.{key}",
            "expected": None,
            "actual": actual.get(key),
        })

    return diffs


def _collect_standard_device_issues(device: Dict[str, Any]) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []

    role = device.get("role")
    if not (isinstance(role, str) and role.strip()):
        diffs.append({
            "path": "role",
            "expected": "non-empty role",
            "actual": role,
        })

    st_ip_base = device.get("st_ip_base")
    if st_ip_base not in (None, ""):
        diffs.append({
            "path": "st_ip_base",
            "expected": "empty string",
            "actual": st_ip_base,
        })

    for key in ("evpn_scope", "evpntopo_id", "deviceprofile_id", "bundled_mac"):
        value = device.get(key)
        if value not in (None, ""):
            diffs.append({
                "path": key,
                "expected": None,
                "actual": value,
            })

    return diffs


class ConfigurationOverridesCheck(ComplianceCheck):
    id = "configuration_overrides"
    name = "Configuration overrides"
    description = "Report site or device configuration overrides outside of approved exceptions."
    severity = "warning"

    allowed_access_port_max: int = 47

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []

        site_override_paths = _collect_override_paths(context.setting)
        if site_override_paths:
            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    message="Site configuration has overrides defined.",
                    details={"paths": sorted(site_override_paths)},
                )
            )

        template_names = _collect_template_names(context)
        template_ids = _collect_template_ids(context)
        site_variables = _collect_site_variables(context)
        template_details = _expected_template_details(context.site_name)
        allowed_template_names: Sequence[str] = template_details["allowed_template_names"]
        allowed_template_ids: Sequence[str] = template_details["allowed_template_ids"]
        site_type_label: str = template_details["site_type"]
        preferred_template_name: str = template_details["preferred_template_name"]
        required_dns_labels = [
            label
            for label in (
                _format_dns_var_group_label(group)
                for group in DNS_OVERRIDE_REQUIRED_VAR_GROUPS
            )
            if label
        ]
        dns_variables_defined, missing_dns_labels = _evaluate_dns_variable_groups(site_variables)

        templates = _gather_switch_templates(context)

        for device in context.devices:
            if not isinstance(device, dict):
                continue
            if not _is_switch(device):
                continue
            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = _normalize_site_name(device) or device_id or "device"
            role_value = device.get("role")
            role_lower = role_value.lower() if isinstance(role_value, str) else ""
            is_wan_role = bool(role_lower and any(token in role_lower for token in WAN_ROLE_KEYWORDS))

            # Non-port overrides (e.g., config_override)
            direct_paths = [path for path in _collect_override_paths(device) if not path.startswith("port_overrides")]
            for path in direct_paths:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name,
                        message="Device has configuration overrides defined.",
                        details={"paths": [path]},
                    )
                )

            # Port overrides with exception logic
            port_overrides = _collect_port_overrides(device)
            access_switch = _is_access_switch(device)
            port_override_allowed_paths: Set[str] = set()
            if port_overrides:
                for entry in port_overrides:
                    if access_switch and entry.port_number is not None and 0 <= entry.port_number <= self.allowed_access_port_max:
                        continue
                    findings.append(
                        Finding(
                            site_id=context.site_id,
                            site_name=context.site_name,
                            device_id=device_id,
                            device_name=device_name,
                            message="Device port override detected.",
                            details={
                                "path": entry.path,
                                "port": entry.port_label,
                                "port_number": entry.port_number,
                                "access_switch": access_switch,
                            },
                        )
                    )
                port_override_allowed_paths = {entry.path for entry in port_overrides}

            template = _resolve_switch_template(device, templates)
            expected_config_raw = template.config if template else None
            actual_config_raw = _extract_device_switch_config(device)
            if expected_config_raw and not isinstance(expected_config_raw, dict):
                expected_config_raw = None
            actual_config_source: Optional[Dict[str, Any]]
            if isinstance(actual_config_raw, dict):
                actual_config_source = actual_config_raw
            elif isinstance(device, dict):
                actual_config_source = {k: v for k, v in device.items() if isinstance(k, str)}
            else:
                actual_config_source = None

            expected_ip_config = None
            actual_ip_config = None

            actual_oob_config = None
            if isinstance(actual_config_source, dict):
                actual_oob_config = actual_config_source.get("oob_ip_config")
            if actual_oob_config is None and isinstance(device, dict):
                actual_oob_config = device.get("oob_ip_config")

            if expected_config_raw and actual_config_source:
                (
                    filtered_expected,
                    filtered_actual,
                    expected_ip_config,
                    actual_ip_config,
                ) = _role_scoped_switch_configs(
                    role_value,
                    expected_config_raw,
                    actual_config_source,
                )
                if filtered_expected or filtered_actual:
                    diffs = _diff_configs(
                        filtered_expected,
                        filtered_actual,
                        ignore_keys=IGNORED_CONFIG_KEYS | ALLOWED_ADDITIONAL_CONFIG_KEYS,
                    )
                else:
                    diffs = []
            else:
                diffs = []

            if actual_ip_config is None and isinstance(actual_config_source, dict):
                actual_ip_config = actual_config_source.get("ip_config")
            if expected_ip_config is None and isinstance(expected_config_raw, dict):
                expected_ip_config = expected_config_raw.get("ip_config")

            ip_config_diffs: List[Dict[str, Any]] = []
            wan_oob_diffs: List[Dict[str, Any]] = []
            wan_active_port_diffs: List[Dict[str, Any]] = []
            if expected_config_raw or actual_config_source:
                ip_config_diffs = _evaluate_ip_config(
                    expected_ip_config if expected_config_raw else None,
                    actual_ip_config if actual_config_source else None,
                )
            if is_wan_role:
                wan_oob_diffs = _evaluate_wan_oob_ip_config(actual_oob_config)
                wan_active_port_diffs = _evaluate_wan_active_ports(device.get("if_stat"))
                ip_config_diffs = []

            standard_device_diffs = _collect_standard_device_issues(device)

            combined_diffs = []
            if diffs:
                combined_diffs.extend(diffs)
            if ip_config_diffs:
                combined_diffs.extend(ip_config_diffs)
            if standard_device_diffs:
                combined_diffs.extend(standard_device_diffs)

            if wan_oob_diffs:
                combined_diffs.extend(wan_oob_diffs)
            if wan_active_port_diffs:
                combined_diffs.extend(wan_active_port_diffs)

            if combined_diffs:
                filtered_diffs: List[Dict[str, Any]] = []
                for diff in combined_diffs:
                    path = diff.get("path") or ""
                    normalized_path = path.lower()
                    if is_wan_role and not diff.get("wan_oob_validation") and any(
                        normalized_path.startswith(prefix)
                        for prefix in WAN_ALLOWED_CONFIG_PATH_PREFIXES
                    ):
                        continue
                    if any(path.startswith(p) for p in port_override_allowed_paths):
                        continue
                    filtered_diffs.append(diff)
                if filtered_diffs:
                    actions: Optional[List[Dict[str, Any]]] = None
                    if device_id:
                        dns_diff = next(
                            (
                                diff
                                for diff in filtered_diffs
                                if isinstance(diff, dict)
                                and (diff.get("path") or "").lower() == "ip_config.dns"
                            ),
                            None,
                        )
                        if dns_diff is not None:
                            actual_dns = dns_diff.get("actual") if isinstance(dns_diff, dict) else None
                            expected_dns = dns_diff.get("expected") if isinstance(dns_diff, dict) else None
                            if expected_dns in (None, [], (), "") and isinstance(actual_dns, list):
                                dns_values = [
                                    str(value).strip()
                                    for value in actual_dns
                                    if isinstance(value, (str, bytes)) and str(value).strip()
                                ]
                                if dns_values:
                                    device_template_id = _resolve_device_template_id(device)
                                    template_precheck_ok = _template_matches_requirements(
                                        template_names,
                                        template_ids,
                                        allowed_template_names,
                                        allowed_template_ids,
                                        device_template_id,
                                    )
                                    precheck_messages: List[str] = []
                                    if not template_precheck_ok:
                                        precheck_messages.append(
                                            _format_template_precheck_message(allowed_template_names)
                                        )
                                    if not dns_variables_defined:
                                        if missing_dns_labels:
                                            precheck_messages.append(
                                                f"Define site DNS variables: {', '.join(missing_dns_labels)}."
                                            )
                                        else:
                                            precheck_messages.append(
                                                "Required site DNS variables are missing."
                                            )
                                    can_run = template_precheck_ok and dns_variables_defined
                                    actions = [
                                        {
                                            "id": CLEAR_DNS_OVERRIDE_ACTION_ID,
                                            "label": "Clear DNS override",
                                            "button_label": "1 Click Fix Now",
                                            "site_ids": [context.site_id],
                                            "devices": [
                                                {
                                                    "site_id": context.site_id,
                                                    "device_id": device_id,
                                                }
                                            ],
                                            "metadata": {
                                                "device_id": device_id,
                                                "device_name": device_name,
                                                "dns_values": dns_values,
                                                "prechecks": {
                                                    "can_run": can_run,
                                                    "site_type": site_type_label,
                                                    "template_applied": bool(
                                                        template_precheck_ok
                                                    ),
                                                    "template_name": preferred_template_name,
                                                    "allowed_template_names": list(
                                                        allowed_template_names
                                                    ),
                                                    "allowed_template_ids": list(
                                                        allowed_template_ids
                                                    ),
                                                    "device_template_id": device_template_id,
                                                    "dns_variables_defined": bool(
                                                        dns_variables_defined
                                                    ),
                                                    "required_dns_variables": required_dns_labels,
                                                    "missing_dns_variables": missing_dns_labels,
                                                    "messages": precheck_messages,
                                                },
                                            },
                                        }
                                    ]
                    template_label = None
                    if template:
                        template_label = template.name or template.template_id
                    findings.append(
                        Finding(
                            site_id=context.site_id,
                            site_name=context.site_name,
                            device_id=device_id,
                            device_name=device_name,
                            message="Device configuration differs from assigned template.",
                            details={
                                "diffs": filtered_diffs,
                                **({"template": template_label} if template_label else {}),
                            },
                            actions=actions,
                        )
                    )

        return findings


DEFAULT_SWITCH_NAME_PATTERN = (
    r"^(NA|LA|EU|AP)[A-Z]{3}(?:MDFSS|MDF(AS|CS|WS)\d+|IDF\d+(AS|CS|WS)\d+)$"
)

DEFAULT_AP_NAME_PATTERN = r"^(NA|LA|EU|AP)[A-Z]{3}(?:MDF|IDF\d+)AP\d+$"


SWITCH_LOCATION_EXTRACT_PATTERN = re.compile(
    r"^(?P<region>NA|LA|EU|AP)(?P<site>[A-Z]{3})(?P<location>MDF|IDF\d+)[A-Z]{2}\d+$"
)
AP_LOCATION_EXTRACT_PATTERN = re.compile(
    r"^(?P<region>NA|LA|EU|AP)(?P<site>[A-Z]{3})(?P<location>MDF|IDF\d+)AP\d+$"
)


DNS_OVERRIDE_TEMPLATE_NAME = "Prod - Standard Template"
DNS_OVERRIDE_LAB_TEMPLATE_NAME = "Test - Standard Template"
DNS_OVERRIDE_PROD_TEMPLATE_IDS: Tuple[str, ...] = (
    "35413d62-89d5-45f7-a5dd-9d7e2ed31a23",
)
DNS_OVERRIDE_LAB_TEMPLATE_IDS: Tuple[str, ...] = (
    "40928180-ea55-48c5-9055-f34c1fe1033a",
)
DNS_OVERRIDE_REQUIRED_VAR_GROUPS: Tuple[Tuple[str, ...], ...] = (
    ("siteDNS", "siteDNSserver"),
    ("hubDNSserver1",),
    ("hubDNSserver2",),
)
DNS_OVERRIDE_REQUIRED_VARS: Tuple[str, ...] = tuple(group[0] for group in DNS_OVERRIDE_REQUIRED_VAR_GROUPS)


def _strip_pattern_wrappers(value: str) -> str:
    """Remove optional r"..." or quoted wrappers from an env-sourced pattern."""

    if len(value) >= 3 and value[0] in {"r", "R"} and value[1] in {'"', "'"} and value[-1] == value[1]:
        return value[2:-1]
    if len(value) >= 2 and value[0] in {'"', "'"} and value[-1] == value[0]:
        return value[1:-1]
    return value


def _literal_eval_pattern(value: str) -> Optional[str]:
    """Attempt to evaluate quoted patterns such as r"^...$" into plain strings."""

    try:
        evaluated = ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return None
    return evaluated if isinstance(evaluated, str) else None


def _load_pattern_from_env(var_name: str, default: Optional[str]) -> Optional[re.Pattern[str]]:
    raw = os.getenv(var_name)
    candidate = (raw or "").strip()
    if candidate:
        evaluated = _literal_eval_pattern(candidate)
        if evaluated is not None:
            candidate = evaluated
        else:
            candidate = _strip_pattern_wrappers(candidate)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                candidate = candidate.encode("utf-8").decode("unicode_escape")
        except Exception:
            pass
    if not candidate:
        candidate = default or ""
    if not candidate:
        return None
    try:
        return re.compile(candidate)
    except re.error:
        if default and candidate != default:
            try:
                return re.compile(default)
            except re.error:
                return None
        return None


def _ensure_pattern(
    pattern: Optional[re.Pattern[str] | str],
    fallback: Optional[re.Pattern[str]],
) -> Optional[re.Pattern[str]]:
    if isinstance(pattern, re.Pattern):
        return pattern
    if isinstance(pattern, str):
        stripped = pattern.strip()
        if not stripped:
            return None
        try:
            return re.compile(stripped)
        except re.error:
            return fallback
    return fallback


ENV_SWITCH_NAME_PATTERN = _load_pattern_from_env("SWITCH_NAME_REGEX_PATTERN", DEFAULT_SWITCH_NAME_PATTERN)
ENV_AP_NAME_PATTERN = _load_pattern_from_env("AP_NAME_REGEX_PATTERN", DEFAULT_AP_NAME_PATTERN)


NEIGHBOR_NAME_KEYS: Tuple[str, ...] = (
    "system_name",
    "sys_name",
    "name",
    "remote_system_name",
    "lldp_remote_system_name",
)


def _is_plausible_neighbor_name(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if SWITCH_LOCATION_EXTRACT_PATTERN.match(text):
        return True
    # Allow custom switch patterns that still expose MDF/IDF tokens
    return bool(re.search(r"IDF\d+|MDF", text))


def _extract_name_from_mapping(data: Mapping[str, Any]) -> Optional[str]:
    for key in NEIGHBOR_NAME_KEYS:
        value = data.get(key)
        if isinstance(value, str) and _is_plausible_neighbor_name(value):
            return value.strip()
    # Some APIs return the neighbor directly as a string value
    if isinstance(data.get("neighbor"), str) and _is_plausible_neighbor_name(data["neighbor"]):
        return data["neighbor"].strip()
    return None


def _search_neighbor_tree(value: Any, visited: Optional[Set[int]] = None) -> Optional[str]:
    if visited is None:
        visited = set()
    obj_id = id(value)
    if obj_id in visited:
        return None
    visited.add(obj_id)

    if isinstance(value, Mapping):
        direct = _extract_name_from_mapping(value)
        if direct:
            return direct

        # Prioritise typical neighbor containers first
        for key in (
            "neighbor",
            "neighbors",
            "uplink",
            "uplinks",
            "lldp",
            "lldp_stats",
            "ports",
            "interfaces",
            "wired",
            "wired_interfaces",
            "wired_ports",
        ):
            if key in value:
                result = _search_neighbor_tree(value[key], visited)
                if result:
                    return result

        for nested in value.values():
            result = _search_neighbor_tree(nested, visited)
            if result:
                return result

    elif isinstance(value, (list, tuple, set)):
        for item in value:
            result = _search_neighbor_tree(item, visited)
            if result:
                return result
    elif isinstance(value, str) and _is_plausible_neighbor_name(value):
        return value.strip()
    return None


def _neighbor_system_name_from_stats(stats: Mapping[str, Any]) -> Optional[str]:
    if not isinstance(stats, Mapping):
        return None

    # Common top-level keys returned by Mist device stats APIs
    for key in ("uplink", "lldp", "lldp_stats", "ports", "interfaces"):
        if key in stats:
            result = _search_neighbor_tree(stats.get(key))
            if result:
                return result

    return _search_neighbor_tree(stats)


def _extract_neighbor_system_name(device: Mapping[str, Any]) -> Optional[str]:
    candidates: List[Mapping[str, Any]] = []

    for key in ("stats", "device_stats", "stat", "status"):
        value = device.get(key)
        if isinstance(value, Mapping):
            candidates.append(value)

    lldp_value = device.get("lldp_stats")
    if isinstance(lldp_value, Mapping):
        candidates.append(lldp_value)
    elif isinstance(lldp_value, (list, tuple, set)):
        candidates.append({"lldp_stats": lldp_value})

    uplink_value = device.get("uplink")
    if isinstance(uplink_value, Mapping):
        candidates.append({"uplink": uplink_value})

    for stats in candidates:
        neighbor = _neighbor_system_name_from_stats(stats)
        if neighbor:
            return neighbor
    return None


def _parse_switch_location(
    name: str, pattern: Optional[re.Pattern[str]]
) -> Optional[Tuple[str, str, str]]:
    text = (name or "").strip()
    if not text:
        return None
    if pattern is not None and pattern.fullmatch(text) is None:
        return None
    match = SWITCH_LOCATION_EXTRACT_PATTERN.match(text)
    if not match:
        return None
    return match.group("region"), match.group("site"), match.group("location")


def _parse_ap_location(
    name: str, pattern: Optional[re.Pattern[str]]
) -> Optional[Tuple[str, str, str]]:
    text = (name or "").strip()
    if not text:
        return None
    if pattern is not None and pattern.fullmatch(text) is None:
        return None
    match = AP_LOCATION_EXTRACT_PATTERN.match(text)
    if not match:
        return None
    return match.group("region"), match.group("site"), match.group("location")


def _load_positive_int_from_env(var_name: str, default: int) -> int:
    raw = os.getenv(var_name)
    if raw is None:
        return default
    candidate = raw.strip()
    if not candidate:
        return default
    try:
        value = int(candidate)
        if value < 0:
            return default
        return value
    except ValueError:
        return default


ENV_SWITCH_IMAGE_REQUIREMENT = _load_positive_int_from_env("SW_NUM_IMG", 2)
ENV_AP_IMAGE_REQUIREMENT = _load_positive_int_from_env("AP_NUM_IMG", 2)


class FirmwareManagementCheck(ComplianceCheck):
    id = "firmware_management"
    name = "Firmware Management"
    description = "Ensure switches and access points run approved firmware versions."
    severity = "warning"

    def __init__(
        self,
        allowed_switch_versions: Optional[Sequence[str]] = None,
        allowed_ap_versions: Optional[Sequence[str]] = None,
    ) -> None:
        self._dynamic_switch_versions = allowed_switch_versions is None
        self._dynamic_ap_versions = allowed_ap_versions is None
        self.allowed_switch_versions: Tuple[str, ...] = tuple(allowed_switch_versions or ())
        self.allowed_ap_versions: Tuple[str, ...] = tuple(allowed_ap_versions or ())
        self.allowed_switch_versions_by_model: Dict[str, Tuple[str, ...]] = {}
        self.allowed_ap_versions_by_model: Dict[str, Tuple[str, ...]] = {}
        self._allowed_switch_set: Set[str] = set()
        self._allowed_ap_set: Set[str] = set()
        self._refresh_allowed_versions()

    def _refresh_allowed_versions(self) -> None:
        if self._dynamic_switch_versions:
            self.allowed_switch_versions_by_model = _load_allowed_versions_by_model_from_standard_doc("switch")
            self.allowed_switch_versions = _load_allowed_versions_from_standard_doc("switch")
        if self._dynamic_ap_versions:
            self.allowed_ap_versions_by_model = _load_allowed_versions_by_model_from_standard_doc("ap")
            self.allowed_ap_versions = _load_allowed_versions_from_standard_doc("ap")
        self._allowed_switch_set = {value for value in self.allowed_switch_versions}
        self._allowed_ap_set = {value for value in self.allowed_ap_versions}

    def prepare_run(self) -> None:
        self._refresh_allowed_versions()

    def run(self, context: SiteContext) -> List[Finding]:
        if not self.allowed_switch_versions and not self.allowed_ap_versions:
            return []

        findings: List[Finding] = []
        for device in context.devices:
            if not isinstance(device, Mapping):
                continue

            device_dict = device if isinstance(device, dict) else dict(device)

            device_type: Optional[str] = None
            allowed_versions: Tuple[str, ...]
            allowed_set: Set[str]
            allowed_by_model: Dict[str, Tuple[str, ...]]

            if self.allowed_switch_versions and _is_switch(device_dict):
                device_type = "Switch"
                allowed_versions = self.allowed_switch_versions
                allowed_set = self._allowed_switch_set
                allowed_by_model = self.allowed_switch_versions_by_model
            elif self.allowed_ap_versions and _is_access_point(device_dict):
                device_type = "Access point"
                allowed_versions = self.allowed_ap_versions
                allowed_set = self._allowed_ap_set
                allowed_by_model = self.allowed_ap_versions_by_model
            else:
                continue

            device_model = _normalize_device_model(device_dict.get("model"))
            if device_model and device_model in allowed_by_model:
                allowed_versions = allowed_by_model[device_model]
                allowed_set = set(allowed_versions)

            version = _extract_firmware_version(device_dict) or ""
            is_allowed = bool(version) and version in allowed_set
            if is_allowed:
                continue

            device_id = str(device_dict.get("id")) if device_dict.get("id") is not None else None
            name_candidates: Sequence[Any] = (
                device_dict.get("name"),
                device_dict.get("hostname"),
                device_dict.get("device_name"),
                device_dict.get("mac"),
                device_id,
            )
            device_name = next(
                (str(value).strip() for value in name_candidates if isinstance(value, str) and value.strip()),
                None,
            )
            if not device_name:
                device_name = device_id or device_type or "device"

            allowed_text = ", ".join(allowed_versions)
            if version:
                message = (
                    f"{device_type} '{device_name}' is running firmware version '{version}' "
                    f"which is not in the approved list ({allowed_text})."
                )
            else:
                message = (
                    f"{device_type} '{device_name}' does not report a firmware version. "
                    f"Approved versions: {allowed_text}."
                )

            details = {
                "device_type": device_type,
                "model": device_dict.get("model"),
                "version": version or None,
                "allowed_versions": list(allowed_versions),
            }

            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    device_id=device_id,
                    device_name=device_name,
                    message=message,
                    details=details,
                )
            )

        return findings


class CloudManagementCheck(ComplianceCheck):
    id = "cloud_management"
    name = "Cloud Management"
    description = "Ensure switches are managed by Juniper Mist cloud."
    severity = "warning"

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []
        for device in context.devices:
            if not isinstance(device, dict):
                continue
            if not _is_switch(device):
                continue
            disable_auto_config = device.get("disable_auto_config")
            if disable_auto_config is not True:
                continue

            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = _normalize_site_name(device) or device_id or "device"
            actions: Optional[List[Dict[str, Any]]] = None
            if device_id:
                actions = [
                    {
                        "id": ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
                        "label": "Enable cloud management",
                        "button_label": "1 Click Fix Now",
                        "site_ids": [context.site_id],
                        "devices": [
                            {
                                "site_id": context.site_id,
                                "device_id": device_id,
                            }
                        ],
                        "metadata": {
                            "device_id": device_id,
                            "device_name": device_name,
                        },
                    }
                ]
            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    device_id=device_id,
                    device_name=device_name,
                    message=(
                        f"Switch '{device_name}' configuration is currently locally managed "
                        "and not managed by Juniper Mist cloud."
                    ),
                    details={"disable_auto_config": disable_auto_config},
                    actions=actions,
                )
            )
        return findings


class SwitchPowerSupplyHealthCheck(ComplianceCheck):
    id = "switch_power_supply_health"
    name = "Switch power supply health"
    description = "Ensure every switch power supply reports healthy status."
    severity = "warning"

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []

        for device in context.devices:
            if not isinstance(device, dict):
                continue
            if not _is_switch(device):
                continue

            psu_entries = list(_iter_device_psu_entries(device))
            if not psu_entries:
                continue

            failed_psus: List[Dict[str, Any]] = []
            for idx, psu in enumerate(psu_entries):
                status_raw = psu.get("status")
                status = str(status_raw).strip().lower() if status_raw is not None else ""
                if status == "ok":
                    continue
                failed_psus.append(
                    {
                        "name": _extract_psu_label(psu, idx),
                        "status": status_raw,
                        "description": psu.get("description"),
                        "slot": _extract_psu_slot(psu),
                    }
                )

            if not failed_psus:
                continue

            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = _normalize_site_name(device) or device_id or "device"

            issue_fragments: List[str] = []
            for issue in failed_psus:
                slot = issue.get("slot")
                label = str(issue.get("name") or "PSU")
                status_value = issue.get("status")
                status_text = str(status_value).strip() if status_value is not None else "unknown"
                fragment = f"{label} status '{status_text}'"
                if slot:
                    fragment = f"switch slot {slot} {fragment}"
                issue_fragments.append(fragment)

            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    device_id=device_id,
                    device_name=device_name,
                    message=(
                        f"Switch '{device_name}' has PSU issues: "
                        + "; ".join(issue_fragments)
                        + "."
                    ),
                    details={"psu_issues": failed_psus},
                )
            )

        return findings


class SpareSwitchPresenceCheck(ComplianceCheck):
    id = "spare_switch_presence"
    name = "Spare switch presence"
    description = "Ensure each site has at least one spare switch available."
    severity = "warning"

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []

        switches = [device for device in context.devices if isinstance(device, dict) and _is_switch(device)]
        if not switches:
            return findings

        spare_count = 0
        for device in switches:
            role = device.get("role")
            if isinstance(role, str) and role.strip().lower() == "spare":
                spare_count += 1

        if spare_count == 0:
            candidate_switches = []
            for device in switches:
                device_id = device.get("id")
                if device_id is None:
                    continue
                name = _normalize_site_name(device) or str(device_id)
                candidate_switches.append(
                    {
                        "device_id": str(device_id),
                        "device_name": name,
                    }
                )
            actions: Optional[List[Dict[str, Any]]] = None
            if candidate_switches:
                actions = [
                    {
                        "id": SET_SPARE_SWITCH_ROLE_ACTION_ID,
                        "label": "Assign spare switch role",
                        "button_label": "1 Click Fix Now",
                        "site_ids": [context.site_id],
                        "metadata": {
                            "site_name": context.site_name,
                            "switch_options": candidate_switches,
                            "require_switch_selection": True,
                        },
                    }
                ]
            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    message="Site does not have a switch with role 'spare'.",
                    details={
                        "total_switches": len(switches),
                        "spare_switches": spare_count,
                    },
                    actions=actions,
                )
            )

        return findings


class DeviceNamingConventionCheck(ComplianceCheck):
    id = "device_naming_convention"
    name = "Device naming convention"
    description = "Ensure device names follow the configured naming convention."
    severity = "warning"

    def __init__(
        self,
        switch_pattern: Optional[re.Pattern[str] | str] = None,
        ap_pattern: Optional[re.Pattern[str] | str] = None,
    ) -> None:
        self.switch_pattern = _ensure_pattern(switch_pattern, ENV_SWITCH_NAME_PATTERN)
        self.ap_pattern = _ensure_pattern(ap_pattern, ENV_AP_NAME_PATTERN)
        self.prepare_run()

    def prepare_run(self) -> None:
        self._ap_issue_counts: Dict[str, int] = {}
        self._ap_issue_sites: Dict[str, str] = {}

    def _build_ap_rename_action(
        self, context: SiteContext, device_id: Optional[str], device_name: str
    ) -> Optional[List[Dict[str, Any]]]:
        if not device_id or not self.ap_pattern:
            return None
        return [
            {
                "id": AP_RENAME_ACTION_ID,
                "label": "Rename access point",
                "button_label": "1 Click Fix Now",
                "site_ids": [context.site_id],
                "devices": [
                    {
                        "site_id": context.site_id,
                        "device_id": device_id,
                    }
                ],
                "metadata": {
                    "device_id": device_id,
                    "current_name": device_name or "",
                    "expected_pattern": self.ap_pattern.pattern,
                },
            }
        ]

    def _check_ap_switch_alignment(
        self, device: Mapping[str, Any], device_name: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        neighbor = _extract_neighbor_system_name(device)
        if not neighbor:
            return None

        ap_tokens = _parse_ap_location(device_name, self.ap_pattern)
        if not ap_tokens:
            return None

        switch_tokens = _parse_switch_location(neighbor, self.switch_pattern)
        if not switch_tokens:
            return None

        ap_region, ap_site, ap_location = ap_tokens
        sw_region, sw_site, sw_location = switch_tokens

        mismatches: List[Tuple[str, str, str]] = []
        if (ap_region, ap_site) != (sw_region, sw_site):
            mismatches.append(("site", f"{ap_region}{ap_site}", f"{sw_region}{sw_site}"))
        if ap_location != sw_location:
            mismatches.append(("location", ap_location, sw_location))

        if not mismatches:
            return None

        parts: List[str] = []
        for category, ap_value, sw_value in mismatches:
            label = "site prefix" if category == "site" else "location token"
            parts.append(f"{label} '{ap_value}' vs '{sw_value}'")
        difference_text = "; ".join(parts)

        message = (
            "Access point name does not match uplink switch "
            f"'{neighbor}' ({difference_text})."
        )
        details = {
            "neighbor": neighbor,
            "ap_name": device_name,
            "ap_region": ap_region,
            "ap_site": ap_site,
            "ap_location": ap_location,
            "switch_region": sw_region,
            "switch_site": sw_site,
            "switch_location": sw_location,
            "mismatches": [
                {"type": category, "ap": ap_value, "switch": sw_value}
                for category, ap_value, sw_value in mismatches
            ],
        }
        return message, details

    def _register_ap_issue(self, context: SiteContext, device_name: str) -> None:
        site_id = context.site_id
        self._ap_issue_counts[site_id] = self._ap_issue_counts.get(site_id, 0) + 1
        if site_id not in self._ap_issue_sites:
            label = context.site_name or site_id
            self._ap_issue_sites[site_id] = label

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []
        for device in context.devices:
            if not isinstance(device, dict):
                continue

            pattern: Optional[re.Pattern[str]] = None
            label = "Device"
            is_ap = False
            if _is_switch(device):
                pattern = self.switch_pattern
                label = "Switch"
            elif _is_access_point(device):
                pattern = self.ap_pattern
                label = "Access point"
                is_ap = True

            if pattern is None:
                continue

            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = (
                (device.get("name") or device.get("hostname") or device.get("device_name") or "")
                .strip()
            )
            if not device_name or not pattern.fullmatch(device_name):
                if label == "Switch" and pattern.pattern == DEFAULT_SWITCH_NAME_PATTERN:
                    message = (
                        "Switch name does not match required convention (e.g., NACHIMDFWS1, "
                        "NACHIIDF1AS3, or NACHIMDFSS)."
                    )
                else:
                    message = f"{label} name does not match required convention."

                actions: Optional[List[Dict[str, Any]]] = None
                if is_ap:
                    actions = self._build_ap_rename_action(context, device_id, device_name or "")
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name or device_id or "device",
                        message=message,
                        details={"expected_pattern": pattern.pattern},
                        actions=actions,
                    )
                )
                if is_ap:
                    self._register_ap_issue(context, device_name or (device_id or ""))
                continue

            if is_ap:
                alignment_issue = self._check_ap_switch_alignment(device, device_name)
                if alignment_issue:
                    message, details = alignment_issue
                    actions = self._build_ap_rename_action(context, device_id, device_name)
                    findings.append(
                        Finding(
                            site_id=context.site_id,
                            site_name=context.site_name,
                            device_id=device_id,
                            device_name=device_name,
                            message=message,
                            details=details,
                            actions=actions,
                        )
                    )
                    self._register_ap_issue(context, device_name)
        return findings

    def suggest_actions(
        self,
        contexts: Sequence[SiteContext],
        findings: Sequence[Finding],
    ) -> List[Dict[str, Any]]:
        return []


def _collect_device_images(device: Dict[str, Any]) -> List[str]:
    image_keys = ("images", "pictures", "photos", "image_urls", "image")
    image_url_pattern = re.compile(r"^image\d+_url$", re.IGNORECASE)
    images: List[str] = []

    def append_images(value: Any) -> None:
        if isinstance(value, str):
            text = value.strip()
            if text:
                images.append(text)
        elif isinstance(value, list):
            for item in value:
                append_images(item)
        elif isinstance(value, dict):
            for item in value.values():
                append_images(item)

    for key in image_keys:
        value = device.get(key)
        if value is not None:
            append_images(value)

    for key, value in device.items():
        if isinstance(key, str) and image_url_pattern.match(key):
            append_images(value)

    # Deduplicate while preserving order
    seen: Set[str] = set()
    unique_images: List[str] = []
    for url in images:
        if url not in seen:
            seen.add(url)
            unique_images.append(url)
    return unique_images


class DeviceDocumentationCheck(ComplianceCheck):
    id = "device_documentation"
    name = "Device documentation"
    description = "Ensure devices are mapped to floorplans and have required reference images."
    severity = "warning"

    def __init__(
        self,
        *,
        switch_min_images: Optional[int] = None,
        ap_min_images: Optional[int] = None,
        default_min_images: int = 2,
    ) -> None:
        def _sanitize(value: Optional[int], fallback: int) -> int:
            if value is None:
                return max(fallback, 0)
            if value < 0:
                return max(fallback, 0)
            return value

        self.switch_min_images = _sanitize(switch_min_images, ENV_SWITCH_IMAGE_REQUIREMENT)
        self.ap_min_images = _sanitize(ap_min_images, ENV_AP_IMAGE_REQUIREMENT)
        self.default_min_images = _sanitize(default_min_images, 2)

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []
        for device in context.devices:
            if not isinstance(device, dict):
                continue
            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = _normalize_site_name(device) or device_id or "device"
            map_id = device.get("map_id")
            if not map_id:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name,
                        message="Device not assigned to any floorplan.",
                    )
                )
            images = _collect_device_images(device)
            required_images = self.default_min_images
            if _is_switch(device):
                required_images = self.switch_min_images
            elif _is_access_point(device):
                required_images = self.ap_min_images

            if required_images <= 0:
                continue

            if len(images) < required_images:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name,
                        message=(
                            f"Required images not present (found {len(images)} of {required_images})."
                        ),
                    )
                )
        return findings


class SiteAuditRunner:
    """Runs a suite of compliance checks across one or more sites."""

    def __init__(self, checks: Sequence[ComplianceCheck]):
        self.checks: List[ComplianceCheck] = list(checks)

    def run(self, contexts: Sequence[SiteContext]) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        total_sites = len(contexts)
        total_devices = 0
        site_devices: Dict[str, int] = {}
        for context in contexts:
            devices = context.devices
            if isinstance(devices, Sequence) and not isinstance(devices, (str, bytes)):
                count = len(devices)
                total_devices += count
            else:
                count = 0
            site_devices[context.site_id] = count
        total_findings = 0
        site_findings: Dict[str, int] = {context.site_id: 0 for context in contexts}
        total_quick_fix_issues = 0
        for check in self.checks:
            check.prepare_run()
            check_findings: List[Finding] = []
            for context in contexts:
                site_findings_for_check = check.run(context)
                check_findings.extend(site_findings_for_check)
                site_findings[context.site_id] = site_findings.get(context.site_id, 0) + len(
                    site_findings_for_check
                )
            total_findings += len(check_findings)
            for finding in check_findings:
                actions = finding.actions or []
                for action in actions:
                    if not isinstance(action, Mapping):
                        continue
                    label_value = action.get("button_label")
                    if label_value is None:
                        continue
                    label_text = str(label_value).strip().lower()
                    if label_text == "1 click fix now":
                        total_quick_fix_issues += 1
                        break
            failing_site_ids = sorted({finding.site_id for finding in check_findings})
            actions = check.suggest_actions(contexts, check_findings) or []
            findings_payload: List[Dict[str, Any]] = []
            site_level_findings: List[Dict[str, Any]] = []
            device_level_findings: List[Dict[str, Any]] = []
            for finding in check_findings:
                payload = finding.as_dict(check.severity)
                findings_payload.append(payload)
                if finding.device_id or finding.device_name:
                    device_level_findings.append(payload)
                else:
                    site_level_findings.append(payload)
            results.append(
                {
                    "id": check.id,
                    "name": check.name,
                    "description": check.description,
                    "severity": check.severity,
                    "findings": findings_payload,
                    "site_level_findings": site_level_findings,
                    "device_level_findings": device_level_findings,
                    "failing_sites": failing_site_ids,
                    "passing_sites": max(total_sites - len(failing_site_ids), 0),
                    "actions": actions,
                }
            )
        return {
            "checks": results,
            "total_sites": total_sites,
            "total_devices": total_devices,
            "total_findings": total_findings,
            "total_quick_fix_issues": total_quick_fix_issues,
            "site_findings": site_findings,
            "site_devices": site_devices,
        }


DEFAULT_CHECKS: Sequence[ComplianceCheck] = (
    RequiredSiteVariablesCheck(),
    SwitchTemplateConfigurationCheck(),
    ConfigurationOverridesCheck(),
    FirmwareManagementCheck(),
    CloudManagementCheck(),
    SwitchPowerSupplyHealthCheck(),
    SpareSwitchPresenceCheck(),
    DeviceNamingConventionCheck(),
    DeviceDocumentationCheck(),
)


def build_default_runner() -> SiteAuditRunner:
    return SiteAuditRunner(DEFAULT_CHECKS)
