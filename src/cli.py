#!/usr/bin/env python3
# CTHULHU module    cli.py

from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter, deque
from typing import Any, Deque, Dict, List, Optional
from rule_handler import load_rules_from_file


# CONFIGURATION

# you can change these paths to whatever you want.
ALERT_LOG_PATH = "/cthulhu/alerts.jsonl"
RULES_PATH = "/cthulhu/alert.rules"

# COLORS
RED = "\033[38;2;255;46;46m"
GREEN = "\033[38;2;2;237;112m"
AQUA = "\033[38;2;0;255;183m"
YELLOW  = "\033[38;2;255;238;0m"
GRAY  = "\033[38;2;122;122;122m"
D_GRAY  = "\033[38;2;66;66;66m"
WHITE   = "\033[38;2;255;255;255m"

# how many alerts to keep in memory for live feeds
MAX_LIVE_ALERTS = 40

ENTER_BUTTON = f"""
    {GREEN}┌────────────────────────────────────────┐
    {GREEN}│  {WHITE}Press Enter to return to main menu... {GREEN}│
    {GREEN}└────────────────────────────────────────┘
"""

CTRLC_BUTTON = f"""
    {GREEN}┌────────────────────────────────────────┐
    {GREEN}│  {WHITE}Press Ctrl+C to return to main menu.  {GREEN}│
    {GREEN}└────────────────────────────────────────┘
"""


# UTILITY FUNCTIONS

def clear_screen() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def read_alerts_from_file(path: str) -> List[Dict[str, Any]]:
    # read all alerts from a JSONL file.
    # returns a list of alert dicts. invalid lines are skipped.

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
                # skip malformed lines
                continue

    return alerts


def _truncate(value: Optional[str], max_len: int = 120) -> str:
    """Truncate long strings for CLI display."""
    if not value:
        return "-"
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def _format_bool(value: Any) -> str:
    """Return a pretty boolean string with color."""
    if isinstance(value, bool):
        if value:
            return f"{GREEN}true{GRAY}"
        return f"{RED}false{GRAY}"

    # handle common string-ish forms
    s = str(value).strip().lower()
    if s in ("1", "yes", "y", "true"):
        return f"{GREEN}true{GRAY}"
    if s in ("0", "no", "n", "false"):
        return f"{RED}false{GRAY}"
    return f"{GRAY}{value}{GRAY}"


def _format_severity(severity: Any) -> str:
    """Return severity with the same colors everywhere."""
    sev = (str(severity) or "unknown").upper()
    if sev == "HIGH":
        color = RED
    elif sev == "MEDIUM":
        color = YELLOW
    elif sev == "LOW":
        color = WHITE
    else:
        color = GRAY
    return f"{color}[{sev}]{GRAY}"


def _extract_first(
    keys: List[str],
    *sources: Dict[str, Any],
    default: Any = None,
) -> Any:
    """
    Return the first non-None / non-empty value among a list of keys
    searched across the provided dicts in order.
    """
    for src in sources:
        if not src:
            continue
        for k in keys:
            if k in src and src[k] not in (None, ""):
                return src[k]
    return default


def _extract_identity_from_records(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull human-friendly user/group names from auditd records if present.
    e.g., UID="root", AUID="root", GID="root", etc.
    """
    result: Dict[str, Any] = {
        "uid_name": None,
        "euid_name": None,
        "auid_name": None,
        "gid_name": None,
        "egid_name": None,
    }

    for rec in event.get("records", []):
        fields = rec.get("fields", {}) or {}
        if result["uid_name"] is None and "UID" in fields:
            result["uid_name"] = fields["UID"]
        if result["euid_name"] is None and "EUID" in fields:
            result["euid_name"] = fields["EUID"]
        if result["auid_name"] is None and "AUID" in fields:
            result["auid_name"] = fields["AUID"]
        if result["gid_name"] is None and "GID" in fields:
            result["gid_name"] = fields["GID"]
        if result["egid_name"] is None and "EGID" in fields:
            result["egid_name"] = fields["EGID"]

    return result


def print_alert_line(alert: Dict[str, Any]) -> None:
    # print a single alert in a human-readable summary line.

    ts = alert.get("alert_timestamp") or "unknown-time"
    uid = alert.get("uid") or alert.get("alert_id") or "unknown-uid"

    rule = alert.get("rule", {})
    severity = rule.get("severity") or "unknown"
    rule_name = rule.get("name") or "unknown_rule"
    description = rule.get("description") or ""

    summary = alert.get("event_summary") or {}
    msg = summary.get("message") or description

    severity_color = _format_severity(severity)

    print(f"{D_GRAY}    {ts} {D_GRAY}[{uid}] {severity_color} {AQUA}[{rule_name}] {GRAY}{msg}")


# LIVE ALERT FEEDS

def tail_alerts_live(
    path: str,
    severity_filter: Optional[str] = None,
) -> None:
    # live alert feed with optional severity filter.

    if not os.path.exists(path):
        print(f"{GRAY}    Alert log file not found: {path}")
        input(ENTER_BUTTON)
        return

    severity_filter_norm: Optional[str] = None
    if severity_filter:
        severity_filter_norm = severity_filter.strip().lower()

    buffer: Deque[Dict[str, Any]] = deque(maxlen=MAX_LIVE_ALERTS)

    with open(path, "r", encoding="utf-8") as f:
        # initial prefill
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
            constant = False
            while True:
                where = f.tell()
                new_line = f.readline()
                if constant and not new_line:
                    time.sleep(30.0)
                else:
                    constant = True
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
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.1       {GREEN}│
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


# ALERT TRIAGE / EXPORT

def _find_alert_by_uid(path: str, uid: str) -> Optional[Dict[str, Any]]:
    # search the alerts file for an alert with the given uid.

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
    # prompt the user for an alert uid, search for it, and display full details
    # in a triage-friendly, summarized format.

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

    # unpack structures with sane defaults
    rule: Dict[str, Any] = alert.get("rule", {}) or {}
    event_meta: Dict[str, Any] = alert.get("event_meta", {}) or {}
    event_summary: Dict[str, Any] = alert.get("event_summary", {}) or {}
    event: Dict[str, Any] = alert.get("event", {}) or {}

    summary = event_summary or event_meta or event

    # --- basic alert fields ---
    alert_uid = alert.get("uid") or alert.get("alert_id") or "unknown"
    alert_time = alert.get("alert_timestamp") or event.get("timestamp") or "unknown-time"
    rule_name = rule.get("name") or "unknown_rule"
    severity = rule.get("severity") or "unknown"
    description = rule.get("description") or "(no description)"

    severity_fmt = _format_severity(severity)

    # --- source context ---
    source = _extract_first(["source"], summary, event_meta, event, default="unknown")
    category = _extract_first(["category"], summary, event_meta, event, default="unknown")
    outcome = _extract_first(["outcome"], summary, event_meta, event, default=None)
    success_val = _extract_first(["success", "success_bool"], summary, event_meta, event, default=None)
    host = _extract_first(["host", "hostname"], summary, event_meta, event, default="(local)")

    # --- process context ---
    process_name = _extract_first(
        ["process_name", "exe_basename", "comm", "command"],
        summary,
        event_meta,
        event,
        default="unknown",
    )
    exe = _extract_first(["exe", "process_path"], summary, event_meta, event, default="-")
    cmdline = _extract_first(["command_line", "cmdline"], summary, event_meta, event, default="")
    cwd = _extract_first(["cwd"], summary, event_meta, event, default="-")
    pid = _extract_first(["pid", "process_id"], summary, event_meta, event, default="-")
    ppid = _extract_first(["ppid", "parent_pid"], summary, event_meta, event, default="-")
    tty = _extract_first(["tty"], summary, event_meta, event, default="-")
    session = _extract_first(["session", "ses"], summary, event_meta, event, default="-")
    interactive = _extract_first(["interactive"], summary, event_meta, event, default=None)

    # --- file context (auditd) ---
    target_path = _extract_first(["target_path"], summary, event_meta, event, default=None)
    file_name = _extract_first(["file_name"], summary, event_meta, event, default=None)
    file_ext = _extract_first(["file_ext"], summary, event_meta, event, default=None)
    filepath_raw = _extract_first(["filepath"], summary, event_meta, event, default=None)

    # --- identity / privilege ---
    uid_val = _extract_first(["uid"], summary, event_meta, event, default=None)
    euid_val = _extract_first(["euid", "EUID"], summary, event_meta, event, default=None)
    auid_val = _extract_first(["auid", "AUID"], summary, event_meta, event, default=None)
    gid_val = _extract_first(["gid", "GID"], summary, event_meta, event, default=None)
    egid_val = _extract_first(["egid", "EGID"], summary, event_meta, event, default=None)

    uid_str = "-" if uid_val is None else str(uid_val)
    euid_str = "-" if euid_val is None else str(euid_val)
    auid_str = "-" if auid_val is None else str(auid_val)
    gid_str = "-" if gid_val is None else str(gid_val)
    egid_str = "-" if egid_val is None else str(egid_val)

    # pull name forms from auditd records (UID="root", etc.)
    identity_names = _extract_identity_from_records(event)
    uid_name = identity_names.get("uid_name")
    euid_name = identity_names.get("euid_name")
    auid_name = identity_names.get("auid_name")
    gid_name = identity_names.get("gid_name")
    egid_name = identity_names.get("egid_name")

    # compute privilege level
    privilege_level = "UNPRIVILEGED"
    is_root = False
    try:
        numeric_uid = int(uid_val) if uid_val is not None else None
        if numeric_uid == 0:
            privilege_level = "ROOT"
            is_root = True
        elif numeric_uid is not None and numeric_uid < 1000:
            privilege_level = "PRIVILEGED (uid < 1000)"
    except Exception:
        # fall back to name-based heuristic
        if str(uid_name).lower() == "root":
            privilege_level = "ROOT"
            is_root = True

    privilege_color = RED if is_root else YELLOW if "PRIVILEGED" in privilege_level else GREEN

    # --- audit context ---
    syscall_num = _extract_first(["syscall"], summary, event_meta, event, default=None)
    syscall_name = None
    serial = _extract_first(["serial", "event_id"], event, default=None)
    epoch = _extract_first(["epoch"], summary, event_meta, event, default=None)

    for rec in event.get("records", []):
        fields = rec.get("fields", {}) or {}
        if "SYSCALL" in fields and not syscall_name:
            syscall_name = fields["SYSCALL"]
        if not serial and "serial" in rec:
            serial = rec["serial"]

    record_types = Counter(rec.get("type", "unknown") for rec in event.get("records", []))

    # --- journald log context (if applicable) ---
    service_name = _extract_first(["service_name"], summary, event_meta, event, default=None)
    log_unit = _extract_first(["log_unit", "unit"], summary, event_meta, event, default=None)
    log_priority_label = _extract_first(["log_priority_label"], summary, event_meta, event, default=None)
    message_snippet = _extract_first(["message_snippet", "log_message", "message"], summary, event_meta, event, default=None)

    # header
    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.1       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}│       {WHITE}ALERT INFORMATION      {GREEN}│
    {GREEN}└──────────────────────────────┘
""")

    # ALERT OVERVIEW
    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│        {AQUA}ALERT OVERVIEW        {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}Alert UID      : {YELLOW}{alert_uid}
    {GRAY}Alert Time     : {WHITE}{alert_time}
    {GRAY}Rule Name      : {AQUA}{rule_name}
    {GRAY}Severity       : {severity_fmt}
    {GRAY}Description    : {WHITE}{description}
""")

    # SOURCE CONTEXT
    success_str = _format_bool(success_val) if success_val is not None else f"{GRAY}-"
    outcome_str = outcome if outcome is not None else "-"
    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│        {AQUA}SOURCE CONTEXT        {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}Source         : {WHITE}{source}
    {GRAY}Category       : {WHITE}{category}
    {GRAY}Outcome        : {WHITE}{outcome_str}  {success_str}
    {GRAY}Host           : {WHITE}{host}
""")

    # PROCESS CONTEXT
    cmdline_display = _truncate(cmdline)
    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│       {AQUA}PROCESS CONTEXT        {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}Process        : {WHITE}{process_name}{GRAY} (PID {WHITE}{pid}{GRAY}, PPID {WHITE}{ppid}{GRAY})
    {GRAY}Executable     : {WHITE}{exe}
    {GRAY}Command Line   : {WHITE}{cmdline_display}
    {GRAY}CWD            : {WHITE}{cwd}
    {GRAY}TTY / Session  : {WHITE}{tty}{GRAY} / {WHITE}{session}
""")

    if interactive is not None:
        print(f"    {GRAY}Interactive    : {_format_bool(interactive)}\n")
    else:
        print(f"    {GRAY}Interactive    : {WHITE}-\n")

    # FILE CONTEXT (only if relevant fields exist)
    if target_path or file_name or file_ext or filepath_raw:
        print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│         {AQUA}FILE CONTEXT         {GREEN}│
    {GREEN}└──────────────────────────────┘
""")
        if target_path:
            print(f"    {GRAY}Target Path    : {WHITE}{target_path}")
        if filepath_raw and filepath_raw != target_path:
            print(f"    {GRAY}Raw Filepath   : {WHITE}{filepath_raw}")
        if file_name:
            print(f"    {GRAY}File Name      : {WHITE}{file_name}")
        if file_ext:
            print(f"    {GRAY}File Ext       : {WHITE}{file_ext}\n")

    # IDENTITY / PRIVILEGE (cleaned)
    effective_display = f"{euid_name} (uid={uid_str})" if euid_name else f"uid={uid_str}"
    audit_display = f"{auid_name} (auid={auid_str})" if auid_name else f"auid={auid_str}"
    real_display = f"{uid_name} (uid={uid_str})" if uid_name else f"uid={uid_str}"
    group_display = f"{gid_name} (gid={gid_str})" if gid_name else f"gid={gid_str}"
    egid_display = f"{egid_name} (egid={egid_str})" if egid_name else f"egid={egid_str}"

    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│    {AQUA}IDENTITY / PRIVILEGE      {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}Effective User : {WHITE}{effective_display}
    {GRAY}Real User      : {WHITE}{real_display}
    {GRAY}Audit User     : {WHITE}{audit_display}
    {GRAY}Groups         : {WHITE}{group_display}{GRAY} / {WHITE}{egid_display}
    {GRAY}Privilege      : {privilege_color}{privilege_level}{GRAY}
""")

    # AUDIT CONTEXT
    syscall_display = "-"
    if syscall_num is not None and syscall_name:
        syscall_display = f"{syscall_num} ({syscall_name})"
    elif syscall_num is not None:
        syscall_display = str(syscall_num)
    elif syscall_name:
        syscall_display = syscall_name

    epoch_display = str(epoch) if epoch is not None else "-"

    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│         {AQUA}AUDIT CONTEXT        {GREEN}│
    {GREEN}└──────────────────────────────┘

    {GRAY}Syscall        : {WHITE}{syscall_display}
    {GRAY}Audit Serial   : {WHITE}{serial if serial is not None else "-"}
    {GRAY}Epoch          : {WHITE}{epoch_display}
""")

    # LOG CONTEXT (journald / log-style events)
    if source == "journald" or service_name or message_snippet or log_priority_label:
        print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│         {AQUA}LOG CONTEXT         {GREEN}│
    {GREEN}└──────────────────────────────┘
""")
        if service_name:
            print(f"    {GRAY}Service        : {WHITE}{service_name}")
        if log_unit:
            print(f"    {GRAY}Unit           : {WHITE}{log_unit}")
        if log_priority_label:
            print(f"    {GRAY}Priority       : {WHITE}{log_priority_label}")
        if message_snippet:
            print(f"    {GRAY}Message        : {WHITE}{_truncate(str(message_snippet), 160)}\n")

    print(f"\n    {GRAY}Use {YELLOW}EXPORT ALERT{GRAY} from the main menu to view")
    print(f"    the full raw JSON event for deeper forensics.\n")

    input(ENTER_BUTTON)


def export_alert_by_uid(path: str) -> None:
    # prompt for an alert uid and export that alert as pretty json to a file.

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


# RULES / ALERTS BROWSING

def view_loaded_rules() -> None:
    # load and display all rule names from the rules file.

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
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.1       {GREEN}│
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
    # display all alerts in summary format with optional rule-name filter.

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
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.1       {GREEN}│
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


# STATS VIEW

def view_alert_stats(path: str) -> None:
    # show simple stats about alerts in the file: total, per severity, per rule.

    alerts = read_alerts_from_file(path)

    clear_screen()
    print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.1       {GREEN}│
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

    print(f"{AQUA}    TOTAL {RED}({total})\n")

    print(f"{GREEN}    SEVERITY:")
    for sev, count in sorted(sev_counter.items(), key=lambda x: (-x[1], x[0])):
        print(f"{GRAY}      {sev} {YELLOW}({count})")

    print(f"{GREEN}    RULE TYPE:")
    for name, count in sorted(rule_counter.items(), key=lambda x: (-x[1], x[0])):
        print(f"{GRAY}      {name} {YELLOW}({count})")

    input(ENTER_BUTTON)


# MAIN MENU

def main_menu() -> None:
    # main interactive menu loop.

    while True:
        clear_screen()
        print(f"""
    {GREEN}┌──────────────────────────────┐
    {GREEN}│                              │
    {GREEN}│           {AQUA}^(;,;)^ {D_GRAY}v1.1       {GREEN}│
    {GREEN}│         {AQUA}CTHULHU SIEM         {GREEN}│
    {GREEN}│                              │
    {GREEN}│       {AQUA}Built for Debian       {GREEN}│
    {GREEN}│   {GRAY}https://r2.jts.gg/license  {GREEN}│
    {GREEN}│    {GRAY}https://jts.gg/cthulhu    {GREEN}│
    {GREEN}│                              │
    {GREEN}└──────────────────────────────┘

    {GREEN}1. {YELLOW}LIVE ALERT FEED
    {GREEN}2. {GRAY}FILTERED LIVE ALERT FEED
    {GREEN}3. {YELLOW}ALERT TRIAGE
    {GREEN}4. {GRAY}VIEW/SEARCH ALL ALERTS
    {GREEN}5. {GRAY}EXPORT ALERT
    {GREEN}6. {GRAY}ALERT STATS
    {GREEN}7. {GRAY}LOADED RULES
    {GREEN}q. {GRAY}QUIT
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
