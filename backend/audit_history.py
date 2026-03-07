"""Helpers for parsing historical audit results from user action logs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import re
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

from logging_utils import LOG_DIR

__all__ = ["SiteHistory", "SiteHistoryRun", "load_site_history"]


@dataclass
class SiteHistoryRun:
    """Represents a single audit run for a site."""

    timestamp: datetime
    issues: int
    devices: int

    def as_dict(self) -> Dict[str, object]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "issues": self.issues,
            "devices": self.devices,
        }


@dataclass
class SiteHistory:
    """Aggregated historical metrics for a Mist site."""

    site_name: str
    issues_total: int = 0
    devices_total: int = 0
    run_count: int = 0
    last_audit_at: Optional[datetime] = None
    runs: List[SiteHistoryRun] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        runs = sorted(self.runs or [], key=lambda run: run.timestamp, reverse=True)
        return {
            "site_name": self.site_name,
            "issues_total": self.issues_total,
            "devices_total": self.devices_total,
            "run_count": self.run_count,
            "last_audit_at": self.last_audit_at.isoformat() if self.last_audit_at else None,
            "runs": [run.as_dict() for run in runs],
        }


LOG_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")
AUDIT_MARKER = "action=audit_run"
DAILY_LOG_NAME_RE = re.compile(r"^\d{8}$")


def _parse_breakdown(raw: str) -> Dict[str, int]:
    """Return a name→count mapping from a serialized breakdown string."""

    if not raw:
        return {}
    text = raw.strip()
    if not text or text.lower() == "none":
        return {}
    # Normalize separators and split.
    normalized = text.replace("|", ",").replace(";", ",")
    parts = [p.strip() for p in normalized.split(",") if p.strip()]
    result: Dict[str, int] = {}
    for part in parts:
        name, _, count_text = part.partition(":")
        if not name:
            continue
        try:
            count = int(count_text.strip()) if count_text.strip() else 0
        except ValueError:
            continue
        result[name.strip()] = count
    return result


def _iter_recent_log_files(
    *,
    log_dir: Path,
    now: datetime,
    lookback_days: int,
) -> Iterable[Path]:
    cutoff_date = (now - timedelta(days=lookback_days)).date()
    for path in sorted(log_dir.glob("*.log")):
        if not DAILY_LOG_NAME_RE.match(path.stem):
            continue
        try:
            file_date = datetime.strptime(path.stem, "%d%m%Y").date()
        except ValueError:
            continue
        if file_date < cutoff_date:
            continue
        yield path


def load_site_history(
    site_names: Iterable[str],
    *,
    lookback_days: int = 365,
    now: Optional[datetime] = None,
    log_dir: Optional[Path] = None,
) -> Mapping[str, SiteHistory]:
    """Aggregate audit history for the given site names within the lookback window."""

    now = now or datetime.utcnow()
    log_dir = log_dir or LOG_DIR

    name_lookup: Dict[str, str] = {}
    history: Dict[str, SiteHistory] = {}

    for name in site_names:
        key = (name or "").strip()
        if not key:
            continue
        lower = key.lower()
        name_lookup[lower] = key
        history[key] = SiteHistory(site_name=key)

    if not history:
        return history

    cutoff = now - timedelta(days=lookback_days)

    for path in _iter_recent_log_files(log_dir=log_dir, now=now, lookback_days=lookback_days):
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if AUDIT_MARKER not in line:
                        continue
                    ts_match = LOG_TS_RE.match(line)
                    if not ts_match:
                        continue
                    try:
                        timestamp = datetime.strptime(ts_match.group("ts"), "%Y-%m-%d %H:%M:%S,%f")
                    except ValueError:
                        continue
                    if timestamp < cutoff:
                        continue

                    issue_idx = line.find("site_issue_breakdown=")
                    if issue_idx == -1:
                        continue
                    device_idx = line.find(" site_device_breakdown=")
                    if device_idx == -1:
                        issues_raw = line[issue_idx + len("site_issue_breakdown=") :].strip()
                        devices_raw = ""
                    else:
                        issues_raw = line[
                            issue_idx + len("site_issue_breakdown=") : device_idx
                        ].strip()
                        devices_raw = line[
                            device_idx + len(" site_device_breakdown=") :
                        ].strip()

                    # Remove trailing context that may follow the device breakdown (e.g., newline).
                    devices_raw = devices_raw.strip()
                    issues_raw = issues_raw.strip()

                    issue_map = _parse_breakdown(issues_raw)
                    device_map = _parse_breakdown(devices_raw)

                    all_names = set(issue_map.keys()) | set(device_map.keys())
                    for name in all_names:
                        lookup = name_lookup.get(name.lower())
                        if not lookup:
                            continue
                        stats = history[lookup]
                        issues = issue_map.get(name, 0)
                        stats.issues_total += issues
                        stats.devices_total += device_map.get(name, 0)
                        stats.runs.append(
                            SiteHistoryRun(
                                timestamp=timestamp,
                                issues=issues,
                                devices=device_map.get(name, 0),
                            )
                        )
                        stats.last_audit_at = (
                            timestamp
                            if stats.last_audit_at is None or timestamp > stats.last_audit_at
                            else stats.last_audit_at
                        )
        except FileNotFoundError:
            continue

    for stats in history.values():
        stats.run_count = len(stats.runs or [])

    return history
