#!/usr/bin/env python3
# CTHULHU main script    engine.py

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


# CONFIGURATION

# paths (keep consistent with cli.py defaults)
ALERT_LOG_PATH = "/cthulhu/alerts.jsonl"
RULES_PATH = "/cthulhu/alert.rules"
AUDIT_LOG_PATH = "/var/log/audit/audit.log"

# enable / disable sources
ENABLE_AUDITD = True
ENABLE_JOURNALD = True

# if false, start reading audit.log from the end (only new events).
# if true, process existing history plus new events.
READ_EXISTING_AUDIT_LOG = False


# UTILITY HELPERS

def print_alert_line(alert: Dict[str, Any]) -> None:
    # print a single alert in a human-readable summary line.

    ts = alert.get("alert_timestamp") or "unknown-time"
    uid = alert.get("uid") or alert.get("alert_id") or "unknown-uid"

    rule = alert.get("rule", {})
    severity = (rule.get("severity") or "unknown").upper()
    rule_name = rule.get("name") or "unknown_rule"
    description = rule.get("description") or ""

    meta = alert.get("event_meta") or {}
    # for journald, meta["message"] exists; for auditd it usually doesn't, so we fall back to description
    msg = meta.get("message") or description

    print(f"{ts} [{uid}] [{severity}] [{rule_name}] {msg}", flush=True)



def follow_file(path: str, read_existing: bool = False) -> Iterable[str]:
    # generator that yields new lines from a file in a "tail -f" fashion.
    # if read_existing is false, seeks to end before starting; if true, reads from the beginning.

    # wait until file exists
    while not os.path.exists(path):
        print(f"[ENGINE] Waiting for audit log file to appear: {path}")
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


def _resolve_parent_process_info(ppid: int) -> Dict[str, Any]:
    # best-effort resolution of parent process metadata, similar to what `top`/`ps` show,
    # but preferring live /proc information when available.
    
    parent_name: str | None = None
    parent_path: str | None = None

    if not isinstance(ppid, int) or ppid <= 0:
        return {
            "parent_process_name": None,
            "parent_process_path": None,
        }

    comm_path = f"/proc/{ppid}/comm"
    exe_link = f"/proc/{ppid}/exe"

    # /proc/<ppid>/comm -> process name (what top/ps usually show)
    try:
        with open(comm_path, "r", encoding="utf-8", errors="replace") as f:
            name = f.read().strip()
            if name:
                parent_name = name
    except Exception:
        pass

    # /proc/<ppid>/exe -> resolved executable path (symlink target)
    try:
        target = os.readlink(exe_link)
        if target:
            parent_path = target
    except Exception:
        pass

    return {
        "parent_process_name": parent_name,
        "parent_process_path": parent_path,
    }


def _enrich_parent_process(event: Dict[str, Any]) -> Dict[str, Any]:
    ppid = event.get("ppid")

    if not isinstance(ppid, int) or ppid <= 0:
        # nothing to do, keep event unchanged
        return event

    parent_info = _resolve_parent_process_info(ppid)

    # only set keys if we actually attempted resolution; don't touch existing keys
    # if user wants to inject their own values upstream.
    if "parent_process_name" not in event:
        event["parent_process_name"] = parent_info.get("parent_process_name")
    else:
        # If it exists but is None/empty, prefer /proc result when available.
        if not event["parent_process_name"] and parent_info.get("parent_process_name"):
            event["parent_process_name"] = parent_info["parent_process_name"]

    if "parent_process_path" not in event:
        event["parent_process_path"] = parent_info.get("parent_process_path")
    else:
        if not event["parent_process_path"] and parent_info.get("parent_process_path"):
            event["parent_process_path"] = parent_info["parent_process_path"]

    return event


# EVENT PROCESSING

def process_event(
    event: Dict[str, Any],
    rules: List[Dict[str, Any]],
    alert_log_path: str,
    alert_lock: threading.Lock,
) -> None:
    # evaluate rules against an event, build alerts for matches, persist them, and print a summary line.

    event = _enrich_parent_process(event)

    event_meta = _build_event_meta(event)
    event_summary = _build_event_summary(event)
    enriched_event = {**event, **event_meta, **event_summary}
    try:
        matches = evaluate_rules(enriched_event, rules)
    except Exception as e:
        # in production you may want structured logging here.
        print(f"[ENGINE] Error evaluating rules: {e}", file=sys.stderr)
        return

    if not matches:
        return

    # ensure alert file operations are serialized
    try:
        with alert_lock:
            alerts = handle_matches(enriched_event, matches, alert_log_path)
    except Exception as e:
        print(f"[ENGINE] Error handling matches: {e}", file=sys.stderr)
        return

    for alert in alerts:
        print_alert_line(alert)


# INGEST LOOPS

def auditd_ingest_loop(
    rules: List[Dict[str, Any]],
    alert_log_path: str,
    alert_lock: threading.Lock,
    stop_event: threading.Event,
) -> None:
    # ingest loop for auditd: tails the audit log and feeds normalized events into the rule/alert pipeline.

    if not ENABLE_AUDITD:
        print("[ENGINE] Auditd ingest disabled.")
        return

    print(f"[ENGINE] Starting auditd ingest from {AUDIT_LOG_PATH}")
    try:
        line_stream = follow_file(AUDIT_LOG_PATH, read_existing=READ_EXISTING_AUDIT_LOG)
        event_stream = build_auditd_events_from_stream(_stop_aware_iter(line_stream, stop_event))

        for event in event_stream:
            if stop_event.is_set():
                break
            process_event(event, rules, alert_log_path, alert_lock)

    except Exception as e:
        print(f"[ENGINE] Auditd ingest encountered an error: {e}", file=sys.stderr)


def journald_ingest_loop(
    rules: List[Dict[str, Any]],
    alert_log_path: str,
    alert_lock: threading.Lock,
    stop_event: threading.Event,
) -> None:
    # ingest loop for journald using journalctl -o json --since=now -f and parse_journald_stream.

    if not ENABLE_JOURNALD:
        print("[ENGINE] Journald ingest disabled.")
        return

    cmd = ["journalctl", "-o", "json", "--since=now", "-f"]
    print(f"[ENGINE] Starting journald ingest: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        print("[ENGINE] journalctl not found; journald ingest disabled.", file=sys.stderr)
        return
    except Exception as e:
        print(f"[ENGINE] Failed to start journalctl: {e}", file=sys.stderr)
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
        # try to terminate journalctl gracefully
        try:
            proc.terminate()
        except Exception:
            pass


def _stop_aware_iter(lines: Iterable[str], stop_event: threading.Event) -> Iterable[str]:
    # wrap an iterable of lines so that it stops when stop_event is set.

    for line in lines:
        if stop_event.is_set():
            break
        yield line


# ENGINE MAIN

def run_engine() -> None:
    # main engine entry point: load rules, start ingest threads, and wait for ctrl+c to stop.

    # resolve paths from environment if set (optional overrides)
    global ALERT_LOG_PATH, RULES_PATH, AUDIT_LOG_PATH
    ALERT_LOG_PATH = os.getenv("SIEM_ALERT_LOG_PATH", ALERT_LOG_PATH)
    RULES_PATH = os.getenv("SIEM_RULES_PATH", RULES_PATH)
    AUDIT_LOG_PATH = os.getenv("SIEM_AUDIT_LOG_PATH", AUDIT_LOG_PATH)

    # load rules
    try:
        rules = load_rules_from_file(RULES_PATH)
    except FileNotFoundError:
        print(f"[ENGINE] Rules file not found: {RULES_PATH}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ENGINE] Failed to load rules from {RULES_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    if not rules:
        print(f"[ENGINE] WARNING: no rules loaded from {RULES_PATH}", file=sys.stderr)

    print("[ENGINE] Loaded rules:")
    for r in rules:
        print(f"  - {r['name']} ({r['severity']})")

    print("\n^(;,;)^ CTHULHU ENGINE\n")
    print(f"    Alerts will be written to : {ALERT_LOG_PATH}")
    print(f"    Audit log path            : {AUDIT_LOG_PATH}")
    print(f"    Journald ingest           : {'enabled' if ENABLE_JOURNALD else 'disabled'}")
    print("[ENGINE] Press Ctrl+C to stop.\n")

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
        # keep main thread alive while workers run.
        while any(t.is_alive() for t in threads):
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[ENGINE] Shutdown requested, stopping ingest loops...")
        stop_event.set()
        # give threads a moment to clean up
        for t in threads:
            t.join(timeout=5.0)
        print("[ENGINE] All ingest threads stopped. Exiting.")


def main(argv: List[str] | None = None) -> None:
    run_engine()


if __name__ == "__main__":
    main(sys.argv[1:])
