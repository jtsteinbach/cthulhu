#!/usr/bin/env python3
"""
cli.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter, deque
from typing import Any, Deque, Dict, List, Optional
from rule_handler import load_rules_from_file


# Configuration

# You can change these paths to whatever you want.
ALERT_LOG_PATH = "/cthulhu/alerts.jsonl"
RULES_PATH = "/cthulhu/alert.rules"

# How many alerts to keep in memory for live feeds
MAX_LIVE_ALERTS = 200

ENTER_BUTTON = """
    ┌───────────────────────────────────────┐
    │ Press Enter to return to main menu... │
    └───────────────────────────────────────┘
"""

CTRLC_BUTTON = """
    ┌───────────────────────────────────────┐
    │ Press Ctrl+C to return to main menu.  │
    └───────────────────────────────────────┘
"""


# Utility functions

def clear_screen() -> None:
    """Clear the terminal screen."""
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def read_alerts_from_file(path: str) -> List[Dict[str, Any]]:
    """
    Read all alerts from a JSONL file.
    Returns a list of alert dicts. Invalid lines are skipped.
    """
    alerts: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return alerts

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError:
                # Skip malformed lines
                continue

    return alerts


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

    print(f"    {ts} [{uid}] [{severity}] [{rule_name}] {msg}")


# Live alert feeds

def tail_alerts_live(
    path: str,
    severity_filter: Optional[str] = None,
) -> None:
    """
    Live alert feed with optional severity filter.
    """
    if not os.path.exists(path):
        print(f"    Alert log file not found: {path}")
        input(ENTER_BUTTON)
        return

    severity_filter_norm: Optional[str] = None
    if severity_filter:
        severity_filter_norm = severity_filter.strip().lower()

    buffer: Deque[Dict[str, Any]] = deque(maxlen=MAX_LIVE_ALERTS)

    with open(path, "r", encoding="utf-8") as f:
        # Initial prefill
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            buffer.append(alert)

        try:
            while True:
                where = f.tell()
                new_line = f.readline()
                if not new_line:
                    time.sleep(1.0)
                else:
                    new_line = new_line.strip()
                    if new_line:
                        try:
                            alert = json.loads(new_line)
                            buffer.append(alert)
                        except json.JSONDecodeError:
                            pass

                clear_screen()
                print(f"""
    ┌──────────────────────────────┐
    │                              │
    │           ^(;,;)^ v1.0       │
    │         CTHULHU SIEM         │
    │                              │
    │    https://jts.gg/cthulhu    │
    │                              │
    │        ALERT LIVE FEED       │
    └──────────────────────────────┘""")
                if severity_filter_norm:
                    print(f"\n    [FILTER] {severity_filter_norm}")
                print(CTRLC_BUTTON)

                displayed = 0
                for alert in reversed(buffer):
                    if severity_filter_norm:
                        rule = alert.get("rule", {})
                        sev = (rule.get("severity") or "").lower()
                        if sev != severity_filter_norm:
                            continue
                    print_alert_line(alert)
                    displayed += 1

                if displayed == 0:
                    print("    (no alerts to display yet)")
        except KeyboardInterrupt:
            pass


# Alert triage / export

def _find_alert_by_uid(path: str, uid: str) -> Optional[Dict[str, Any]]:
    """Search the alerts file for an alert with the given UID."""
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            alert_uid = alert.get("uid") or alert.get("alert_id")
            if alert_uid == uid:
                return alert

    return None


def triage_alert_by_uid(path: str) -> None:
    """
    Prompt the user for an alert UID, search for it in the alerts file,
    and display full details if found.
    """
    uid = input("    Enter Alert UID > ").strip()
    if not uid:
        print("    No UID entered.")
        input(ENTER_BUTTON)
        return

    alert = _find_alert_by_uid(path, uid)

    clear_screen()
    if alert is None:
        print(f"    No alert found with UID: {uid}")
        input(ENTER_BUTTON)
        return

    rule = alert.get("rule", {})
    event_meta = alert.get("event_meta", {})
    event_summary = alert.get("event_summary", {})
    event = alert.get("event", {})

    print(f"""
    ┌──────────────────────────────┐
    │                              │
    │           ^(;,;)^ v1.0       │
    │         CTHULHU SIEM         │
    │                              │
    │    https://jts.gg/cthulhu    │
    │                              │
    │       ALERT INFORMATION      │
    └──────────────────────────────┘

    Alert UID      : {alert.get('uid') or alert.get('alert_id')}
    Alert Time     : {alert.get('alert_timestamp')}
    Rule Name      : {rule.get('name')}
    Severity       : {rule.get('severity')}
    Description    : {rule.get('description')}

    ┌──────────────────────────────┐
    │          EVENT META          │
    └──────────────────────────────┘

    {json.dumps(event_meta, indent=2, sort_keys=True)}

    ┌──────────────────────────────┐
    │        EVENT SUMMARY         │
    └──────────────────────────────┘

    {json.dumps(event_summary, indent=2, sort_keys=True)}

    ┌──────────────────────────────┐
    │         FULL SUMMARY         │
    └──────────────────────────────┘

    {json.dumps(event, indent=2, sort_keys=True)}""")
    input(ENTER_BUTTON)


def export_alert_by_uid(path: str) -> None:
    """
    Prompt for an alert UID and export that alert as pretty JSON to a file.
    Default export path: ./alert_<uid>.json
    """
    uid = input("    Enter alert UID to export > ").strip()
    if not uid:
        print("    No UID entered.")
        input(ENTER_BUTTON)
        return

    alert = _find_alert_by_uid(path, uid)
    clear_screen()

    if alert is None:
        print(f"    No alert found with UID: {uid}")
        input(ENTER_BUTTON)
        return

    default_path = f"./alert_{uid}.json"
    print(f"    Default export path: {default_path}")
    out_path = input("    Enter export path (leave blank for default) > ").strip()
    if not out_path:
        out_path = default_path

    directory = os.path.dirname(out_path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(alert, f, indent=2, sort_keys=True)
        print(f"    Alert {uid} exported to: {out_path}")
    except Exception as e:
        print(f"    Failed to export alert: {e}")

    input(ENTER_BUTTON)


# Rules / alerts browsing

def view_loaded_rules() -> None:
    """
    Load and display all rule names from the rules file.
    """
    if not os.path.exists(RULES_PATH):
        print(f"    Rules file not found: {RULES_PATH}")
        input(ENTER_BUTTON)
        return

    try:
        rules = load_rules_from_file(RULES_PATH)
    except Exception as e:
        print(f"    Failed to load rules: {e}")
        input(ENTER_BUTTON)
        return

    clear_screen()
    print(f"""
    ┌──────────────────────────────┐
    │                              │
    │           ^(;,;)^ v1.0       │
    │         CTHULHU SIEM         │
    │                              │
    │    https://jts.gg/cthulhu    │
    │                              │
    │         LOADED RULES         │
    └──────────────────────────────┘
    """)

    if not rules:
        print("    (no rules loaded)")
        input(ENTER_BUTTON)
        return

    rules_sorted = sorted(rules, key=lambda r: r["name"])

    for r in rules_sorted:
        name = r["name"]
        severity = r["severity"]
        desc = r["description"]
        print(f"    {name} ({severity}) - {desc}")

    input(ENTER_BUTTON)


def view_search_all_alerts(path: str) -> None:
    """
    Display all alerts in the file in the summary format.
    Optional rule-name substring filter.
    """
    if not os.path.exists(path):
        print(f"    Alert log file not found: {path}")
        input(ENTER_BUTTON)
        return

    filter_str = input("    Enter rule name filter (leave blank for all) > ").strip().lower()
    alerts = read_alerts_from_file(path)

    clear_screen()
    print(f"""
    ┌──────────────────────────────┐
    │                              │
    │           ^(;,;)^ v1.0       │
    │         CTHULHU SIEM         │
    │                              │
    │    https://jts.gg/cthulhu    │
    │                              │
    │          ALL ALERTS          │
    └──────────────────────────────┘
    """)
    if filter_str:
        print(f"    [FILTER] rule name contains {filter_str}")

    if not alerts:
        print("    (no alerts found)")
        input(ENTER_BUTTON)
        return

    count = 0
    for alert in reversed(alerts):
        rule = alert.get("rule", {})
        rule_name = (rule.get("name") or "").lower()
        if filter_str and filter_str not in rule_name:
            continue
        print_alert_line(alert)
        count += 1

    if count == 0:
        print("    (no alerts match the filter)")

    input(ENTER_BUTTON)


# Stats view

def view_alert_stats(path: str) -> None:
    """
    Show simple stats about alerts in the file:
        - Total alerts
        - Alerts per severity
        - Alerts per rule
    """
    alerts = read_alerts_from_file(path)

    clear_screen()
    print(f"""
    ┌──────────────────────────────┐
    │                              │
    │           ^(;,;)^ v1.0       │
    │         CTHULHU SIEM         │
    │                              │
    │    https://jts.gg/cthulhu    │
    │                              │
    │          ALERT STATS         │
    └──────────────────────────────┘
    """)

    if not alerts:
        print("    (no alerts found)")
        input(ENTER_BUTTON)
        return

    total = len(alerts)
    sev_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()

    for alert in alerts:
        rule = alert.get("rule", {})
        severity = (rule.get("severity") or "unknown").lower()
        name = rule.get("name") or "unknown_rule"

        sev_counter[severity] += 1
        rule_counter[name] += 1

    print(f"    Total Alerts: {total}")

    print("    Alerts by Severity:")
    for sev, count in sorted(sev_counter.items(), key=lambda x: (-x[1], x[0])):
        print(f"      {sev}: {count}")

    print("    Alerts by Rule:")
    for name, count in sorted(rule_counter.items(), key=lambda x: (-x[1], x[0])):
        print(f"      {name}: {count}")

    input(ENTER_BUTTON)


# Main menu

def main_menu() -> None:
    """
    Main interactive menu loop.
    """
    while True:
        clear_screen()
        print(f"""
    ┌──────────────────────────────┐
    │                              │
    │           ^(;,;)^ v1.0       │
    │         CTHULHU SIEM         │
    │                              │
    │    https://jts.gg/cthulhu    │
    │                              │
    └──────────────────────────────┘

    1. LIVE ALERT FEED
    2. FILTERED LIVE ALERT FEED
    3. ALERT TRIAGE
    4. VIEW/SEARCH ALL ALERTS
    5. EXPORT ALERT
    6. ALERT STATS
    7. LOADED RULES
    q. QUIT
    """)
        choice = input("    Select Action > ").strip().lower()

        if choice == "1":
            tail_alerts_live(ALERT_LOG_PATH)
        elif choice == "2":
            sev = input("    Enter severity (e.g. low, medium, high) > ").strip()
            if sev:
                tail_alerts_live(ALERT_LOG_PATH, severity_filter=sev)
            else:
                print("    No severity provided.")
                input(ENTER_BUTTON)
        elif choice == "3":
            triage_alert_by_uid(ALERT_LOG_PATH)
        elif choice == "4":
            view_search_all_alerts(ALERT_LOG_PATH)
        elif choice == "5":
            export_alert_by_uid(ALERT_LOG_PATH)
        elif choice == "6":
            view_alert_stats(ALERT_LOG_PATH)
        elif choice == "7":
            view_loaded_rules()
        elif choice in ("q", "quit", "exit"):
            print("    Exiting SIEM alert console.")
            break
        else:
            print(f"    Invalid choice: {choice!r}")
            input(ENTER_BUTTON)


def main(argv: List[str] | None = None) -> None:
    main_menu()


if __name__ == "__main__":
    main(sys.argv[1:])
