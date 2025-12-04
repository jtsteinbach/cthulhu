"""
alert_handler.py
"""

from __future__ import annotations

import json
import os
import zoneinfo
from datetime import datetime, timezone
from typing import Any, Dict, List


# Internal helpers

def _pst_timestamp() -> str:
    """Return current PST time"""
    pacific = zoneinfo.ZoneInfo("America/Los_Angeles")
    return datetime.now(pacific).strftime("%Y-%m-%d %I:%M:%S %p %Z")


def _generate_uuid() -> str:
    """Generate unique id"""
    return os.urandom(12).hex().upper()


def _build_event_meta(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract normalized meta fields from the event for quick querying
    without drilling into the full event structure.
    """
    source = event.get("source")

    meta: Dict[str, Any] = {
        "source": source,
        "timestamp": event.get("timestamp"),
        "epoch": event.get("epoch"),
        "host": event.get("host"),
        "category": event.get("category"),
    }

    if source == "auditd":
        meta.update(
            {
                "syscall": event.get("syscall"),
                "success": event.get("success"),
                "command": event.get("command"),
                "exe": event.get("exe"),
                "uid": event.get("uid"),
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "filepath": event.get("filepath"),
            }
        )
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

    return meta


def _build_event_summary(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a concise, human-oriented summary of the event for triage displays.
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

    return summary


# Public API

def build_alert(event: Dict[str, Any], match: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a saturated alert dict from an event and a rule match.

    `event` is the normalized event from ingest_events.py.
    `match` is a single match dict from rule_handler.evaluate_rules(event, rules):

        {
            "rule": "<rule_name>",
            "severity": "<severity>",
            "description": "<description>",
        }
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

    alert: Dict[str, Any] = {
        "alert_id": alert_uuid,
        "uid": alert_uuid,  # explicit unique identifier field
        "alert_timestamp": alert_timestamp,
        "rule": rule_info,
        "event_meta": event_meta,
        "event_summary": event_summary,
        "event": event,  # full normalized event
    }

    return alert


def persist_alert(alert: Dict[str, Any], path: str) -> None:
    """
    Append a single alert as one JSON line to the given file path.

    Creates parent directories if they do not exist.
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
