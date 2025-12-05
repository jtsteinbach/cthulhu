"""
alert_handler.py
"""

from __future__ import annotations

import json
import os
import re
import zoneinfo
from datetime import datetime, timezone
from typing import Any, Dict, List


# Time / ID helpers

def _pst_timestamp() -> str:
    """Return current PST time."""
    pacific = zoneinfo.ZoneInfo("America/Los_Angeles")
    return datetime.now(pacific).strftime("%m-%d-%Y %I:%M:%S %p %Z")


def _generate_uuid() -> str:
    """Generate unique id."""
    return os.urandom(6).hex().upper()


# Normalization helpers

def _normalize_success(value: Any) -> Dict[str, Any]:
    """
    Normalize various 'success' representations into a bool + outcome label.

    Returns a dict that may contain:
        {
            "success_bool": True/False,
            "outcome": "success" / "failure"
        }
    """
    result: Dict[str, Any] = {}
    success_bool: bool | None = None

    if isinstance(value, bool):
        success_bool = value
    elif isinstance(value, (int, float)):
        # Treat non-zero as success, zero as failure
        success_bool = bool(value)
    elif isinstance(value, str):
        v = value.strip().lower()
        if v in {"yes", "true", "1", "ok", "success"}:
            success_bool = True
        elif v in {"no", "false", "0", "failed", "failure", "err"}:
            success_bool = False

    if success_bool is not None:
        result["success_bool"] = success_bool
        result["outcome"] = "success" if success_bool else "failure"

    return result


# Basic journald priority labels for more intuitive JRL conditions.
_JOURNALD_PRIORITY_LABELS: Dict[int, str] = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


# Enrichment: auditd

def _derive_auditd_enrichment(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build enrichment fields specifically for auditd events.
    """
    enrichment: Dict[str, Any] = {}

    exe = event.get("exe")
    command = event.get("command")
    filepath = event.get("filepath")
    cwd = event.get("cwd")
    tty = event.get("tty")
    pid = event.get("pid")
    ppid = event.get("ppid")

    # Command line: prefer full command if present, otherwise exe path.
    command_line: str | None = None
    if isinstance(command, str) and command.strip():
        command_line = command.strip()
    elif isinstance(exe, str) and exe.strip():
        command_line = exe.strip()

    if command_line:
        enrichment["command_line"] = command_line

    # Process path / name
    if isinstance(exe, str) and exe.strip():
        process_path = exe.strip()
        enrichment["process_path"] = process_path
        exe_basename = os.path.basename(process_path) or process_path
        enrichment["process_name"] = exe_basename
        enrichment["exe_basename"] = exe_basename

    # Process IDs (aliases)
    if pid is not None:
        enrichment["process_id"] = pid
    if ppid is not None:
        enrichment["parent_pid"] = ppid

    # Target file path: combine cwd + filepath when filepath is relative
    target_path: str | None = None
    if isinstance(filepath, str) and filepath.strip():
        fp = filepath.strip()
        if fp.startswith("/"):
            target_path = fp
        elif isinstance(cwd, str) and cwd.strip():
            target_path = os.path.join(cwd.strip(), fp)
        else:
            target_path = fp

    if target_path:
        enrichment["target_path"] = target_path

        # Derive name + extension from path
        file_name = os.path.basename(target_path)
        if file_name:
            enrichment["file_name"] = file_name
            if "." in file_name and not file_name.startswith("."):
                enrichment["file_ext"] = file_name.rsplit(".", 1)[-1].lower()

    # Interactive vs non-interactive execution
    if isinstance(tty, str) and tty.strip():
        t = tty.strip().lower()
        # Heuristic: non-interactive auditd often uses "?" or "none"
        enrichment["interactive"] = t not in {"?", "none", "null"}

    return enrichment


# Enrichment: journald

def _derive_journald_enrichment(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build enrichment fields specifically for journald events.
    """
    enrichment: Dict[str, Any] = {}

    message = event.get("message")
    unit = event.get("unit")
    priority_raw = event.get("priority")
    facility = event.get("facility")

    if isinstance(message, str) and message:
        enrichment["log_message"] = message
        enrichment["message_snippet"] = message[:120]

    if isinstance(unit, str) and unit:
        enrichment["log_unit"] = unit
        # Derive a cleaner service_name from typical ".service" units
        if unit.endswith(".service"):
            enrichment["service_name"] = unit.rsplit(".", 1)[0]

    if facility is not None:
        enrichment["log_facility"] = facility

    # Normalize priority to an int if possible
    priority_int: int | None = None
    if isinstance(priority_raw, int):
        priority_int = priority_raw
    elif isinstance(priority_raw, str):
        try:
            priority_int = int(priority_raw)
        except ValueError:
            priority_int = None

    if priority_int is not None:
        enrichment["log_priority"] = priority_int
        label = _JOURNALD_PRIORITY_LABELS.get(priority_int)
        if label:
            enrichment["log_priority_label"] = label

        # Basic severity flags to make JRL conditions simpler
        enrichment["is_error"] = priority_int <= 3
        enrichment["is_warning"] = priority_int == 4
        enrichment["is_info"] = priority_int == 6

    return enrichment


# Meta + Summary builders

def _build_event_meta(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract normalized meta fields from the event for quick querying
    without drilling into the full event structure.

    This includes enrichment aliases and derived fields
    to make JRL rules more expressive and intuitive.
    """
    source = event.get("source")

    meta: Dict[str, Any] = {
        "source": source,
        "timestamp": event.get("timestamp"),
        "epoch": event.get("epoch"),
        "host": event.get("host"),
        "category": event.get("category"),
    }

    # Normalize "success" into structured fields, but keep raw value too.
    success_raw = event.get("success")
    if success_raw is not None:
        meta["success"] = success_raw
        meta.update(_normalize_success(success_raw))

    if source == "auditd":
        meta.update(
            {
                "syscall": event.get("syscall"),
                "command": event.get("command"),
                "exe": event.get("exe"),
                "uid": event.get("uid"),
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "filepath": event.get("filepath"),
                "tty": event.get("tty"),
                "cwd": event.get("cwd"),
            }
        )
        meta.update(_derive_auditd_enrichment(event))

    elif source == "journald":
        meta.update(
            {
                "process_name": event.get("process_name"),
                "unit": event.get("unit"),
                "message": event.get("message"),
                "priority": event.get("priority"),
                "facility": event.get("facility"),
            }
        )
        meta.update(_derive_journald_enrichment(event))

    return meta


def _build_event_summary(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a concise, human-oriented summary of the event for triage displays.

    This mirrors the enrichment used in meta, so triage and JRL share the
    same vocabulary (command_line, process_name, target_path, etc.).
    """
    source = event.get("source")

    summary: Dict[str, Any] = {
        "source": source,
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "category": event.get("category"),
    }

    if source == "auditd":
        summary.update(
            {
                "syscall": event.get("syscall"),
                "success": event.get("success"),
                "command": event.get("command"),
                "exe": event.get("exe"),
                "uid": event.get("uid"),
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "filepath": event.get("filepath"),
                "tty": event.get("tty"),
                "cwd": event.get("cwd"),
            }
        )
        summary.update(_derive_auditd_enrichment(event))
        success_raw = event.get("success")
        if success_raw is not None:
            summary.update(_normalize_success(success_raw))

    elif source == "journald":
        summary.update(
            {
                "process_name": event.get("process_name"),
                "unit": event.get("unit"),
                "message": event.get("message"),
                "priority": event.get("priority"),
                "facility": event.get("facility"),
            }
        )
        summary.update(_derive_journald_enrichment(event))

    return summary


# "Why did this fire?" helpers

_FIELD_TOKEN_RE = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")


def _infer_matched_fields_from_expression(
    expression: str,
    event_meta: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Heuristically infer which fields were involved in a rule, based on its
    JRL expression string and the available event_meta.

    We tokenize the expression, intersect with keys present in event_meta,
    and snapshot those key->value pairs.
    """
    if not isinstance(expression, str) or not expression.strip():
        return {}

    tokens = set(_FIELD_TOKEN_RE.findall(expression))
    fields = tokens.intersection(event_meta.keys())

    snapshot: Dict[str, Any] = {}
    for field in fields:
        snapshot[field] = event_meta.get(field)

    return snapshot


def _build_rule_highlights(
    match: Dict[str, Any],
    event_meta: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build a compact "why this fired" object to live at the top of the alert.

    Uses whatever the rule engine passes in `match`, plus optionally infers
    flagged fields directly from the rule's condition (expression) and
    event_meta.

    Supported (optional) keys on `match`:
        - matched_fields: List[str] or Dict[str, Any]
        - fields:         alias for matched_fields
        - expression:     the JRL expression / condition string
        - condition:      alias for expression
        - reason:         short human explanation
        - explanation:    alias for reason
    """
    highlights: Dict[str, Any] = {}

    # 1) Human-readable reason / explanation
    reason = match.get("reason") or match.get("explanation")
    if isinstance(reason, str) and reason.strip():
        highlights["reason"] = reason.strip()
    elif isinstance(match.get("description"), str) and match["description"].strip():
        highlights["reason"] = match["description"].strip()

    # 2) Expression / condition that matched
    expression = match.get("expression") or match.get("condition")
    if isinstance(expression, str) and expression.strip():
        highlights["expression"] = expression.strip()

    # 3) Concrete field/value snapshot
    fields_snapshot: Dict[str, Any] = {}

    # 3a) If rule_handler already gave us matched_fields
    raw_matched = match.get("matched_fields") or match.get("fields")
    if isinstance(raw_matched, dict):
        fields_snapshot.update(raw_matched)
    elif isinstance(raw_matched, list):
        for field in raw_matched:
            if isinstance(field, str) and field in event_meta:
                fields_snapshot[field] = event_meta[field]

    # 3b) If still empty but we have an expression, infer from expression
    if not fields_snapshot and isinstance(expression, str) and expression.strip():
        inferred = _infer_matched_fields_from_expression(expression, event_meta)
        fields_snapshot.update(inferred)

    if fields_snapshot:
        highlights["matched_fields"] = fields_snapshot

    return highlights


# Public API

def build_alert(event: Dict[str, Any], match: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a saturated alert dict from an event and a rule match.
    """
    alert_uuid = str(_generate_uuid())
    alert_timestamp = _pst_timestamp()

    rule_info = {
        "name": match.get("rule"),
        "severity": match.get("severity"),
        "description": match.get("description"),
    }

    event_meta = _build_event_meta(event)
    event_summary = _build_event_summary(event)
    rule_highlights = _build_rule_highlights(match, event_meta)

    # Dict insertion order is preserved (Python 3.7+),
    # and json.dumps(sort_keys=False) respects it.
    # Put rule_highlights first so triage sees the "why" immediately.
    alert: Dict[str, Any] = {}

    if rule_highlights:
        alert["rule_highlights"] = rule_highlights

    alert["alert_id"] = alert_uuid
    alert["uid"] = alert_uuid  # explicit unique identifier field
    alert["alert_timestamp"] = alert_timestamp
    alert["rule"] = rule_info
    alert["event_meta"] = event_meta
    alert["event_summary"] = event_summary
    alert["event"] = event  # full normalized event

    return alert


def persist_alert(alert: Dict[str, Any], path: str) -> None:
    """
    Append a single alert as one JSON line to the given file path.
    """
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)

    line = json.dumps(alert, separators=(",", ":"), sort_keys=False)

    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()


def handle_matches(
    event: Dict[str, Any],
    matches: List[Dict[str, Any]],
    path: str,
) -> List[Dict[str, Any]]:
    """
    Given an event and a list of rule matches, build and persist an alert
    for each match.

    Returns the list of alert dicts that were created.
    """
    alerts: List[Dict[str, Any]] = []

    for match in matches:
        alert = build_alert(event, match)
        persist_alert(alert, path)
        alerts.append(alert)

    return alerts
