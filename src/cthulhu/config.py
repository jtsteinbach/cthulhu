"""Configuration. Every value is overridable from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

PREFIX = "CTHULHU_"

# v1 used SIEM_* names; keep them working.
_LEGACY = {
    "ALERT_LOG": "SIEM_ALERT_LOG_PATH",
    "RULES": "SIEM_RULES_PATH",
    "AUDIT_LOG": "SIEM_AUDIT_LOG_PATH",
}


def _env(name: str, default: str) -> str:
    value = os.getenv(PREFIX + name)
    if value is None and name in _LEGACY:
        value = os.getenv(_LEGACY[name])
    return value if value is not None else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(PREFIX + name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(PREFIX + name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(PREFIX + name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


ROOT = _env("ROOT", "/cthulhu")


@dataclass
class Config:
    root: str = ROOT
    rules_path: str = field(default_factory=lambda: _env("RULES", f"{ROOT}/alerts.jrl"))
    alert_log: str = field(default_factory=lambda: _env("ALERT_LOG", f"{ROOT}/alerts.jsonl"))
    audit_log: str = field(default_factory=lambda: _env("AUDIT_LOG", "/var/log/audit/audit.log"))
    state_dir: str = field(default_factory=lambda: _env("STATE_DIR", f"{ROOT}/state"))
    triage_log: str = field(default_factory=lambda: _env("TRIAGE_LOG", f"{ROOT}/triage.jsonl"))
    feeds_dir: str = field(default_factory=lambda: _env("FEEDS_DIR", f"{ROOT}/feeds.d"))
    disabled_feeds: str = field(default_factory=lambda: _env("DISABLE_FEEDS", ""))

    enable_auditd: bool = field(default_factory=lambda: _env_bool("ENABLE_AUDITD", True))
    enable_journald: bool = field(default_factory=lambda: _env_bool("ENABLE_JOURNALD", True))

    read_existing: bool = field(default_factory=lambda: _env_bool("READ_EXISTING", False))
    min_severity: str = field(default_factory=lambda: _env("MIN_SEVERITY", "info"))
    default_throttle: float = field(default_factory=lambda: _env_float("DEFAULT_THROTTLE", 0.0))
    #: Drop repeats of activity already closed as a false positive, instead
    #: of writing them flagged. Benign and true positives are never dropped.
    suppress_known: bool = field(default_factory=lambda: _env_bool("SUPPRESS_KNOWN", False))

    max_alert_bytes: int = field(default_factory=lambda: _env_int("MAX_ALERT_BYTES", 64 * 1024 * 1024))
    alert_backups: int = field(default_factory=lambda: _env_int("ALERT_BACKUPS", 5))

    poll_interval: float = field(default_factory=lambda: _env_float("POLL_INTERVAL", 0.25))
    flush_seconds: float = field(default_factory=lambda: _env_float("FLUSH_SECONDS", 1.0))

    color: Optional[bool] = None  # resolved by ui.py
    quiet: bool = field(default_factory=lambda: _env_bool("QUIET", False))

    def journal_cursor(self) -> str:
        return os.path.join(self.state_dir, "journal.cursor")


def load() -> Config:
    return Config()
