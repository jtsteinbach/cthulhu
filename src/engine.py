#!/usr/bin/env python3
"""
engine.py
"""

from __future__ import annotations

import os
import sys
import time
import threading
import subprocess
from typing import Any, Dict, List, Iterable

from ingest_events import (
    build_auditd_events_from_stream,
    parse_journald_stream,
)
from rule_handler import load_rules_from_file, evaluate_rules
from alert_handler import handle_matches, _build_event_meta, _build_event_summary


# Configuration

# Paths (keep consistent with cli.py defaults)
ALERT_LOG_PATH = "/cthulhu/alerts.jsonl"
RULES_PATH = "/cthulhu/alert.rules"
AUDIT_LOG_PATH = "/var/log/audit/audit.log"

# Enable / disable sources
ENABLE_AUDITD = True
ENABLE_JOURNALD = True

# If False, start reading audit.log from the end (only new events).
# If True, process existing history + new events.
READ_EXISTING_AUDIT_LOG = False


# Utility helpers

def print_alert_line(alert: Dict[str, Any]) -> None:
    """
    Print a single alert in the format:

        time [alert-uid] [SEVERITY] [rule_name] Alert Description human readable
    """
    ts = alert.get("alert_timestamp") or "unknown-time"
    uid = alert.get("uid") or alert.get("alert_id") or "unknown-uid"

    rule = alert.get("rule", {})
    severity = (rule.get("severity") or "unknown").upper()
    rule_name = rule.get("name") or "unknown_rule"
    description = rule.get("description") or ""

    summary = alert.get("event_summary") or {}
    msg = summary.get("message") or description

    print(f"{ts} [{uid}] [{severity}] [{rule_name}] {msg}", flush=True)


def follow_file(path: str, read_existing: bool = False) -> Iterable[str]:
    """
    Generator that yields new lines from a file in a "tail -f" fashion.

    If read_existing is False, seeks to end before starting.
    If read_existing is True, reads from the beginning and continues.
    """
    # Wait until file exists
    while not os.path.exists(path):
        print(f"[engine] Waiting for audit log file to appear: {path}")
        time.sleep(2.0)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if not read_existing:
            f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line


# Event processing

def process_event(
    event: Dict[str, Any],
    rules: List[Dict[str, Any]],
    alert_log_path: str,
    alert_lock: threading.Lock,
) -> None:
    """
    Evaluate rules against an event, build alerts for any matches,
    persist them, and print a summary line.
    """
    event_meta = _build_event_meta(event)
    event_summary = _build_event_summary(event)
    enriched_event = {**event, **event_meta, **event_summary}
    try:
        matches = evaluate_rules(enriched_event, rules)
    except Exception as e:
        # In production you may want structured logging here.
        print(f"[engine] Error evaluating rules: {e}", file=sys.stderr)
        return

    if not matches:
        return

    # Ensure alert file operations are serialized
    try:
        with alert_lock:
            alerts = handle_matches(enriched_event, matches, alert_log_path)
    except Exception as e:
        print(f"[engine] Error handling matches: {e}", file=sys.stderr)
        return

    for alert in alerts:
        print_alert_line(alert)


# Ingest loops

def auditd_ingest_loop(
    rules: List[Dict[str, Any]],
    alert_log_path: str,
    alert_lock: threading.Lock,
    stop_event: threading.Event,
) -> None:
    """
    Ingest loop for auditd. Tails the audit log and feeds normalized
    events into the rule/alert pipeline.
    """
    if not ENABLE_AUDITD:
        print("[engine] Auditd ingest disabled.")
        return

    print(f"[engine] Starting auditd ingest from {AUDIT_LOG_PATH}")
    try:
        line_stream = follow_file(AUDIT_LOG_PATH, read_existing=READ_EXISTING_AUDIT_LOG)
        event_stream = build_auditd_events_from_stream(_stop_aware_iter(line_stream, stop_event))

        for event in event_stream:
            if stop_event.is_set():
                break
            process_event(event, rules, alert_log_path, alert_lock)

    except Exception as e:
        print(f"[engine] Auditd ingest encountered an error: {e}", file=sys.stderr)


def journald_ingest_loop(
    rules: List[Dict[str, Any]],
    alert_log_path: str,
    alert_lock: threading.Lock,
    stop_event: threading.Event,
) -> None:
    """
    Ingest loop for journald using:

        journalctl -o json --since=now -f

    and feeding lines into parse_journald_stream.
    """
    if not ENABLE_JOURNALD:
        print("[engine] Journald ingest disabled.")
        return

    cmd = ["journalctl", "-o", "json", "--since=now", "-f"]
    print(f"[engine] Starting journald ingest: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        print("[engine] journalctl not found; journald ingest disabled.", file=sys.stderr)
        return
    except Exception as e:
        print(f"[engine] Failed to start journalctl: {e}", file=sys.stderr)
        return

    try:
        assert proc.stdout is not None
        line_stream = _stop_aware_iter(proc.stdout, stop_event)
        event_stream = parse_journald_stream(line_stream)

        for event in event_stream:
            if stop_event.is_set():
                break
            process_event(event, rules, alert_log_path, alert_lock)
    finally:
        # Try to terminate journalctl gracefully
        try:
            proc.terminate()
        except Exception:
            pass


def _stop_aware_iter(lines: Iterable[str], stop_event: threading.Event) -> Iterable[str]:
    """
    Wrap an iterable of lines so that it stops when stop_event is set.
    """
    for line in lines:
        if stop_event.is_set():
            break
        yield line


# Engine main

def run_engine() -> None:
    """
    Main engine entry point.

    - Loads rules
    - Starts ingest threads (auditd, journald)
    - Waits for Ctrl+C to stop
    """
    # Resolve paths from environment if set (optional overrides)
    global ALERT_LOG_PATH, RULES_PATH, AUDIT_LOG_PATH
    ALERT_LOG_PATH = os.getenv("SIEM_ALERT_LOG_PATH", ALERT_LOG_PATH)
    RULES_PATH = os.getenv("SIEM_RULES_PATH", RULES_PATH)
    AUDIT_LOG_PATH = os.getenv("SIEM_AUDIT_LOG_PATH", AUDIT_LOG_PATH)

    # Load rules
    try:
        rules = load_rules_from_file(RULES_PATH)
    except FileNotFoundError:
        print(f"[engine] Rules file not found: {RULES_PATH}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[engine] Failed to load rules from {RULES_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    if not rules:
        print(f"[engine] WARNING: no rules loaded from {RULES_PATH}", file=sys.stderr)

    print("[engine] Loaded rules:")
    for r in rules:
        print(f"  - {r['name']} ({r['severity']})")

    print()
    print(f"[engine] Alerts will be written to: {ALERT_LOG_PATH}")
    print(f"[engine] Audit log path           : {AUDIT_LOG_PATH}")
    print(f"[engine] Journald ingest          : {'enabled' if ENABLE_JOURNALD else 'disabled'}")
    print("[engine] Press Ctrl+C to stop.\n")

    alert_lock = threading.Lock()
    stop_event = threading.Event()

    threads: List[threading.Thread] = []

    if ENABLE_AUDITD:
        t_audit = threading.Thread(
            target=auditd_ingest_loop,
            args=(rules, ALERT_LOG_PATH, alert_lock, stop_event),
            name="auditd-ingest",
            daemon=True,
        )
        threads.append(t_audit)

    if ENABLE_JOURNALD:
        t_journal = threading.Thread(
            target=journald_ingest_loop,
            args=(rules, ALERT_LOG_PATH, alert_lock, stop_event),
            name="journald-ingest",
            daemon=True,
        )
        threads.append(t_journal)

    for t in threads:
        t.start()

    try:
        # Keep main thread alive while workers run.
        while any(t.is_alive() for t in threads):
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[engine] Shutdown requested, stopping ingest loops...")
        stop_event.set()
        # Give threads a moment to clean up
        for t in threads:
            t.join(timeout=5.0)
        print("[engine] All ingest threads stopped. Exiting.")


def main(argv: List[str] | None = None) -> None:
    run_engine()


if __name__ == "__main__":
    main(sys.argv[1:])
