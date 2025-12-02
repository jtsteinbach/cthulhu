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

# Colors
GREEN = "\033[38;2;0;255;140m"
AQUA = "\033[38;2;0;255;183m"
YELLOW  = "\033[38;2;255;238;0m"
GRAY  = "\033[38;2;122;122;122m"
D_GRAY  = "\033[38;2;66;66;66m"
WHITE   = "\033[38;2;255;255;255m"

# How many alerts to keep in memory for live feeds
MAX_LIVE_ALERTS = 200

ENTER_BUTTON = f"""
    {GREEN}┌────────────────────────────────────────┐
    {GREEN}│  {YELLOW}Press Enter to return to main menu... {GREEN}│
    {GREEN}└────────────────────────────────────────┘
"""

CTRLC_BUTTON = f"""
    {GREEN}┌────────────────────────────────────────┐
    {GREEN}│  {YELLOW}Press Ctrl+C to return to main menu.  {GREEN}│
    {GREEN}└────────────────────────────────────────┘
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

    if severity == "high":
        severity_color = f"[{YELLOW}{severity}]"
    if severity == "medium":
        severity_color = f"[{GREEN}{severity}]"
    if severity == "high":
        severity_color = f"[{WHITE}{severity}]"

    print(f"{D_GRAY}    {ts} {D_GRAY}[{uid}] {severity_color} {AQUA}[{rule_name}] {GRAY}{msg}")


# Live alert feeds

def tail_alerts_live(
    path: str,
    severity_filter: Optional[str] = None,
) -> None:
    """
    Live alert feed with optional severity filter.
    """
    if not os.path.exists(path):
        print(f"{GRAY}    Alert log file not found: {path}")
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
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.0       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}│        {WHITE}ALERT LIVE FEED       {GREEN}│
    {GREEN}└──────────────────────────────┘""")
                if severity_filter_norm:
                    print(f"\n    {YELLOW}[FILTER]{GRAY} {severity_filter_norm}")
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
                    print(f"{GRAY}    (no alerts to display yet)")
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
    uid = input(f"{GREEN}    Enter Alert UID > ").strip()
    if not uid:
        print(f"{GRAY}    No UID entered.")
        input(ENTER_BUTTON)
        return

    alert = _find_alert_by_uid(path, uid)

    clear_screen()
    if alert is None:
        print(f"{GRAY}    No alert found with UID: {uid}")
        input(ENTER_BUTTON)
        return

    rule = alert.get("rule", {})
    event_meta = alert.get("event_meta", {})
    event_summary = alert.get("event_summary", {})
    event = alert.get("event", {})

    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.0       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}│       {WHITE}ALERT INFORMATION      {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}Alert UID      : {YELLOW}{alert.get('uid') or alert.get('alert_id')}
    {GRAY}Alert Time     : {WHITE}{alert.get('alert_timestamp')}
    {GRAY}Rule Name      : {AQUA}{rule.get('name')}
    {GRAY}Severity       : {YELLOW}{rule.get('severity')}
    {GRAY}Description    : {WHITE}{rule.get('description')}

    {GREEN}┌──────────────────────────────┐
    {GREEN}│          {YELLOW}EVENT META          {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}{json.dumps(event_meta, indent=2, sort_keys=True)}

    {GREEN}┌──────────────────────────────┐
    {GREEN}│        {YELLOW}EVENT SUMMARY         {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}{json.dumps(event_summary, indent=2, sort_keys=True)}

    {GREEN}┌──────────────────────────────┐
    {GREEN}│         {YELLOW}FULL SUMMARY         {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}{json.dumps(event, indent=2, sort_keys=True)}""")
    input(ENTER_BUTTON)


def export_alert_by_uid(path: str) -> None:
    """
    Prompt for an alert UID and export that alert as pretty JSON to a file.
    Default export path: ./alert_<uid>.json
    """
    uid = input(f"{GREEN}    Enter alert UID to export > ").strip()
    if not uid:
        print(f"{GRAY}    No UID entered.")
        input(ENTER_BUTTON)
        return

    alert = _find_alert_by_uid(path, uid)
    clear_screen()

    if alert is None:
        print(f"{GRAY}    No alert found with UID: {uid}")
        input(ENTER_BUTTON)
        return

    default_path = f"./alert_{uid}.json"
    print(f"{GRAY}    Default export path: {default_path}")
    out_path = input(f"{GREEN}    Enter export path (leave blank for default) > ").strip()
    if not out_path:
        out_path = default_path

    directory = os.path.dirname(out_path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(alert, f, indent=2, sort_keys=True)
        print(f"{GRAY}    Alert {uid} exported to: {out_path}")
    except Exception as e:
        print(f"{GRAY}    Failed to export alert: {e}")

    input(ENTER_BUTTON)


# Rules / alerts browsing

def view_loaded_rules() -> None:
    """
    Load and display all rule names from the rules file.
    """
    if not os.path.exists(RULES_PATH):
        print(f"{GRAY}    Rules file not found: {RULES_PATH}")
        input(ENTER_BUTTON)
        return

    try:
        rules = load_rules_from_file(RULES_PATH)
    except Exception as e:
        print(f"{GRAY}    Failed to load rules: {e}")
        input(ENTER_BUTTON)
        return

    clear_screen()
    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.0       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}│         {WHITE}LOADED RULES         {GREEN}│
    {GREEN}└──────────────────────────────┘
    """)

    if not rules:
        print(f"{GRAY}    (no rules loaded)")
        input(ENTER_BUTTON)
        return

    rules_sorted = sorted(rules, key=lambda r: r["name"])

    for r in rules_sorted:
        name = r["name"]
        severity = r["severity"]
        desc = r["description"]
        print(f"    {AQUA}{name} {YELLOW}({severity}) {GRAY}- {desc}")

    input(ENTER_BUTTON)


def view_search_all_alerts(path: str) -> None:
    """
    Display all alerts in the file in the summary format.
    Optional rule-name substring filter.
    """
    if not os.path.exists(path):
        print(f"{GRAY}    Alert log file not found: {path}")
        input(ENTER_BUTTON)
        return

    filter_str = input(f"{GREEN}    Enter rule name filter (leave blank for all) > ").strip().lower()
    alerts = read_alerts_from_file(path)

    clear_screen()
    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.0       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}│          {WHITE}ALL ALERTS          {GREEN}│
    {GREEN}└──────────────────────────────┘
    """)
    if filter_str:
        print(f"    {YELLOW}[FILTER]{GRAY} rule name contains {AQUA}{filter_str}")

    if not alerts:
        print(f"{GRAY}    (no alerts found)")
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
        print(f"{GRAY}    (no alerts match the filter)")

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
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.0       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}│          {WHITE}ALERT STATS         {GREEN}│
    {GREEN}└──────────────────────────────┘
    """)

    if not alerts:
        print(f"{GRAY}    (no alerts found)")
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

    print(f"{AQUA}    TOTAL: {YELLOW}{total}")

    print(f"{GREEN}    SEVERITY:")
    for sev, count in sorted(sev_counter.items(), key=lambda x: (-x[1], x[0])):
        print(f"{WHITE}      {sev}: {YELLOW}{count}")

    print(f"{GREEN}    RULE TYPE:")
    for name, count in sorted(rule_counter.items(), key=lambda x: (-x[1], x[0])):
        print(f"{WHITE}      {name}: {YELLOW}{count}")

    input(ENTER_BUTTON)


# Main menu

def main_menu() -> None:
    """
    Main interactive menu loop.
    """
    while True:
        clear_screen()
        print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.0       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}└──────────────────────────────┘

    {YELLOW}1. {AQUA}LIVE ALERT FEED
    {YELLOW}2. {GRAY}FILTERED LIVE ALERT FEED
    {YELLOW}3. {AQUA}ALERT TRIAGE
    {YELLOW}4. {GRAY}VIEW/SEARCH ALL ALERTS
    {YELLOW}5. {GRAY}EXPORT ALERT
    {YELLOW}6. {GRAY}ALERT STATS
    {YELLOW}7. {GRAY}LOADED RULES
    {YELLOW}q. {GRAY}QUIT
    """)
        choice = input(f"{GREEN}    Select Action > ").strip().lower()

        if choice == "1":
            tail_alerts_live(ALERT_LOG_PATH)
        elif choice == "2":
            sev = input(f"{GREEN}    Enter severity (e.g. low, medium, high) > ").strip()
            if sev:
                tail_alerts_live(ALERT_LOG_PATH, severity_filter=sev)
            else:
                print(f"{GRAY}    No severity provided.")
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
            print(f"{GRAY}    Exiting SIEM alert console.")
            break
        else:
            print(f"{GRAY}    Invalid choice: {choice!r}")
            input(ENTER_BUTTON)


def main(argv: List[str] | None = None) -> None:
    main_menu()


if __name__ == "__main__":
    main(sys.argv[1:])
