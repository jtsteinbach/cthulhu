"""Alert construction, suppression, correlation and persistence.

Changes from v1:

* timestamps are ISO-8601 UTC (v1 wrote ``%m-%d-%Y %I:%M:%S %p`` in a
  hard-coded US/Pacific zone, which does not sort and does not parse);
* alert IDs are 128-bit ULID-style, so they sort by creation time;
* the writer keeps one handle open and rotates at a size cap instead of
  reopening per alert and growing without bound;
* ``throttle`` and ``threshold`` directives are enforced here, which is what
  keeps a noisy rule from producing an unbounded alert storm.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from .jrl import Rule
from .schema import severity_rank
from .triage import event_signature

__all__ = ["AlertWriter", "AlertBuilder", "Suppressor", "build_alert"]

_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32


def _alert_id(now: Optional[float] = None) -> str:
    """Lexicographically sortable 26-char identifier."""
    ms = int((now if now is not None else time.time()) * 1000)
    rand = secrets.randbits(80)
    value = (ms << 80) | rand
    out = []
    for _ in range(26):
        out.append(_ULID_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------
# Summary rendering
# --------------------------------------------------------------------------

_SUMMARY_FIELDS = (
    "host", "category", "action", "outcome",
    "exe", "exe_name", "cmdline", "cwd", "pid", "ppid",
    "parent_name", "tty", "session", "interactive",
    "uid", "euid", "auid", "user", "auser", "is_root", "priv_escalated",
    "path", "file_name", "file_ext", "mode", "owner_uid", "nametype",
    "remote_ip", "remote_port", "addr_family",
    "syscall", "syscall_name", "key", "serial", "exit_code",
    "unit", "service", "message", "priority", "priority_label",
    "auth_user", "auth_method", "auth_result",
    "sudo_command", "sudo_target_user",
)


def _summarize(event: Dict[str, Any]) -> Dict[str, Any]:
    return {k: event[k] for k in _SUMMARY_FIELDS
            if k in event and event[k] is not None}


def _one_line(event: Dict[str, Any], rule: Rule) -> str:
    """A single readable sentence describing what happened."""
    src = event.get("source")
    if src == "journald" and event.get("action") == "ssh_login":
        who = event.get("auth_user", "?")
        ip = event.get("remote_ip", "?")
        res = event.get("auth_result", "?")
        return f"ssh {res} for {who!r} from {ip}"
    if event.get("action") == "sudo":
        return (f"sudo {event.get('auth_user','?')} -> "
                f"{event.get('sudo_target_user','root')}: "
                f"{event.get('sudo_command', '?')}")
    if src == "journald":
        return (event.get("message") or "")[:180] or rule.description
    cmd = event.get("cmdline") or event.get("exe") or event.get("comm")
    path = event.get("path")
    user = event.get("user") or event.get("uid")
    if event.get("category") == "file" and path:
        return f"{event.get('syscall_name','access')} {path} by {cmd} (uid={user})"
    if event.get("category") == "network" and event.get("remote_ip"):
        return (f"{cmd} -> {event['remote_ip']}:"
                f"{event.get('remote_port','?')} (uid={user})")
    return f"{cmd} (uid={user})" if cmd else rule.description


def build_alert(event: Dict[str, Any], rule: Rule,
                match_count: int = 1,
                correlated: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Assemble the persisted alert record."""
    alert: Dict[str, Any] = {
        "alert_id": _alert_id(),
        "detected_at": _iso_now(),
        "event_time": event.get("timestamp"),
        "severity": rule.severity,
        "rule": {
            "name": rule.name,
            "severity": rule.severity,
            "description": rule.description,
            "tags": list(rule.tags),
            "mitre": list(rule.mitre),
            "conditions": list(rule.conditions),
        },
        "source": event.get("source"),
        "host": event.get("host"),
        "summary": _one_line(event, rule),
        "event": _summarize(event),
    }
    # Fingerprint of the activity, so a verdict recorded once is recognized
    # the next time this same thing happens.
    alert["signature"] = event_signature(alert)
    if rule.references:
        alert["rule"]["references"] = list(rule.references)
    if match_count > 1:
        alert["match_count"] = match_count
    if correlated:
        alert["correlated_events"] = correlated
    # Full fidelity kept last so the readable part comes first in the file.
    alert["raw"] = {
        k: v for k, v in event.items()
        if k in ("raw", "records", "argv", "paths", "keys", "message")
    }
    return alert


# --------------------------------------------------------------------------
# Suppression + correlation
# --------------------------------------------------------------------------


@dataclass
class _Bucket:
    hits: Deque[Tuple[float, Dict[str, Any]]]


class Suppressor:
    """Applies per-rule ``throttle``, ``dedup`` and ``threshold`` directives.

    Without this, one misbehaving process can emit thousands of identical
    alerts a second and bury everything else.
    """

    def __init__(self, default_throttle: float = 0.0,
                 max_keys: int = 20000) -> None:
        self.default_throttle = default_throttle
        self.max_keys = max_keys
        self._last_emit: Dict[Tuple[str, str], float] = {}
        self._windows: Dict[Tuple[str, str], _Bucket] = defaultdict(
            lambda: _Bucket(hits=deque()))
        self._lock = threading.Lock()

    @staticmethod
    def _key_for(rule: Rule, event: Dict[str, Any],
                 fields: Iterable[str]) -> str:
        parts = [str(event.get(f, "-")) for f in fields]
        return "|".join(parts) if parts else "*"

    def admit(self, rule: Rule, event: Dict[str, Any],
              now: Optional[float] = None
              ) -> Tuple[bool, int, List[Dict[str, Any]]]:
        """Decide whether a matched rule should produce an alert.

        Returns ``(emit, match_count, correlated_events)``.
        """
        now = now if now is not None else time.time()

        with self._lock:
            if rule.threshold:
                key = (rule.name, self._key_for(rule, event,
                                                rule.threshold.group_by))
                bucket = self._windows[key]
                cutoff = now - rule.threshold.window
                while bucket.hits and bucket.hits[0][0] < cutoff:
                    bucket.hits.popleft()
                bucket.hits.append((now, _summarize(event)))
                if len(bucket.hits) < rule.threshold.count:
                    return False, 0, []
                correlated = [e for _, e in bucket.hits]
                count = len(correlated)
                bucket.hits.clear()  # reset after firing
                if not self._throttled(rule, event, now):
                    self._prune()
                    return True, count, correlated[-25:]
                self._prune()
                return False, 0, []

            if self._throttled(rule, event, now):
                return False, 0, []
            self._prune()
            return True, 1, []

    def _throttled(self, rule: Rule, event: Dict[str, Any], now: float) -> bool:
        window = rule.throttle or self.default_throttle
        if window <= 0:
            return False
        fields = rule.dedup_by or ("host", "uid", "exe", "path", "remote_ip")
        key = (rule.name, self._key_for(rule, event, fields))
        last = self._last_emit.get(key)
        if last is not None and (now - last) < window:
            return True
        self._last_emit[key] = now
        return False

    def _prune(self) -> None:
        if len(self._last_emit) > self.max_keys:
            drop = len(self._last_emit) - self.max_keys // 2
            for key in list(self._last_emit)[:drop]:
                self._last_emit.pop(key, None)
        if len(self._windows) > self.max_keys:
            for key in list(self._windows)[: len(self._windows) - self.max_keys // 2]:
                self._windows.pop(key, None)


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


class AlertWriter:
    """Append-only JSONL writer with size-based rotation."""

    def __init__(self, path: str, max_bytes: int = 64 * 1024 * 1024,
                 backups: int = 5, fsync: bool = False) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups
        self.fsync = fsync
        self._fh = None
        self._lock = threading.Lock()
        self._size = 0
        self._open()

    def _open(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8")
        try:
            self._size = os.fstat(self._fh.fileno()).st_size
        except OSError:
            self._size = 0

    def _rotate(self) -> None:
        if self._fh:
            self._fh.close()
        for idx in range(self.backups - 1, 0, -1):
            older, newer = f"{self.path}.{idx}", f"{self.path}.{idx + 1}"
            if os.path.exists(older):
                os.replace(older, newer)
        if os.path.exists(self.path):
            os.replace(self.path, f"{self.path}.1")
        self._open()

    def write(self, alert: Dict[str, Any]) -> None:
        line = json.dumps(alert, separators=(",", ":"), default=str)
        data = line + "\n"
        with self._lock:
            if self._fh is None:
                self._open()
            if self.max_bytes and self._size + len(data) > self.max_bytes:
                self._rotate()
            assert self._fh is not None
            self._fh.write(data)
            self._fh.flush()
            if self.fsync:
                os.fsync(self._fh.fileno())
            self._size += len(data)

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None


class AlertBuilder:
    """Ties matching, suppression and persistence together."""

    def __init__(self, writer: AlertWriter, suppressor: Suppressor,
                 min_severity: str = "info",
                 known_signatures: Optional[Dict[str, str]] = None,
                 suppress_known: bool = False) -> None:
        self.writer = writer
        self.suppressor = suppressor
        self.min_rank = severity_rank(min_severity)
        #: signature -> verdict for activity an analyst has already closed.
        self.known_signatures: Dict[str, str] = dict(known_signatures or {})
        #: When true, alerts matching a *false positive* signature are dropped
        #: instead of written. Off by default: annotating keeps the record and
        #: lets the console hide it, whereas dropping loses it permanently.
        #: Benign and true positives are never dropped — authorized activity
        #: turning malicious is precisely what needs to stay visible.
        self.suppress_known = suppress_known
        self.stats: Dict[str, int] = defaultdict(int)

    def process(self, event: Dict[str, Any],
                matched: Iterable[Rule]) -> List[Dict[str, Any]]:
        emitted: List[Dict[str, Any]] = []
        for rule in matched:
            self.stats["matches"] += 1
            if severity_rank(rule.severity) < self.min_rank:
                continue
            ok, count, correlated = self.suppressor.admit(rule, event)
            if not ok:
                self.stats["suppressed"] += 1
                continue

            alert = build_alert(event, rule, count, correlated)
            prior = self.known_signatures.get(alert["signature"])
            if prior is not None:
                # Same activity, already reviewed. Record the earlier verdict
                # on the alert so the console can keep it out of the queue.
                alert["prior_verdict"] = prior
                self.stats["known"] += 1
                self.stats[f"known_{prior}"] += 1
                if self.suppress_known and prior == "false_positive":
                    self.stats["known_dropped"] += 1
                    continue

            try:
                self.writer.write(alert)
            except OSError:
                self.stats["write_errors"] += 1
                continue
            self.stats["alerts"] += 1
            self.stats[f"sev_{rule.severity}"] += 1
            emitted.append(alert)
        return emitted

    def refresh_known(self, signatures: Dict[str, str]) -> None:
        """Replace the dispositioned-signature index (called on rule reload)."""
        self.known_signatures = dict(signatures)
