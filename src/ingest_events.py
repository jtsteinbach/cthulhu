#!/usr/bin/env python3
# CTHULHU module    ingest_events.py

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

__all__ = [
    # auditd low-level
    "parse_auditd_record_line",
    "parse_auditd_record_stream",
    # auditd high-level
    "build_auditd_event",
    "build_auditd_events_from_stream",
    # journald
    "parse_journald_event",
    "parse_journald_stream",
]


# SOURCES
#
# auditd   (typically /var/log/audit/audit.log)
# journald (typically via `journalctl -o json`)
#
# for auditd, we expose:
#     - low-level record parsing per log line (parse_auditd_record_line / stream).
#     - high-level event grouping by serial number, syscall-centric
#       (build_auditd_event / build_auditd_events_from_stream).
#
# for journald, we expose:
#     - normalized events from json lines (parse_journald_event / stream),
#       with all original fields preserved in `fields` and `raw`.


# SHARED HELPERS

_AUDITD_HEADER_RE = re.compile(
    r"""
    ^\s*
    type=(?P<type>[A-Z_]+)\s+
    msg=audit\(
        (?P<ts_sec>\d+)
        (?:\.(?P<ts_usec>\d+))?
        :
        (?P<serial>\d+)
    \):
    \s*
    """,
    re.VERBOSE,
)


def _parse_epoch_to_iso(ts_sec: int, ts_usec: int = 0) -> str:
    # convert epoch seconds plus microseconds to an iso 8601 utc string.
    # example: "2025-12-01T18:42:10.123456+00:00"

    dt = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000, tz=timezone.utc)
    return dt.isoformat()


def _safe_int(value: Any) -> Optional[int]:
    # safely convert a value to int, returning none on failure.

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# AUDITD LOW-LEVEL RECORD PARSING (PER LINE, NO DATA LOSS)

def _tokenize_auditd_kv(s: str) -> Iterable[str]:
    # tokenize a string of auditd key=value pairs, handling quoted values.
    # example: key1=val1 key2="value with spaces" key3=val3

    tokens: List[str] = []
    current: List[str] = []
    in_quotes = False
    escape = False

    for ch in s:
        if escape:
            current.append(ch)
            escape = False
            continue

        if ch == "\\":
            current.append(ch)
            escape = True
            continue

        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
            continue

        if ch.isspace() and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)

    if current:
        tokens.append("".join(current))

    return tokens


def _strip_auditd_value(v: str) -> str:
    # strip surrounding quotes and unescape simple \" sequences.

    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    v = v.replace('\\"', '"')
    return v


def parse_auditd_record_line(line: str) -> Optional[Dict[str, Any]]:
    # parse a single auditd record line into a structured dict.
    # returns none if the line does not match the expected header.

    line = line.rstrip("\n")

    m = _AUDITD_HEADER_RE.match(line)
    if not m:
        return None

    rec_type = m.group("type")
    ts_sec = int(m.group("ts_sec"))
    ts_usec = int(m.group("ts_usec") or "0")
    serial = int(m.group("serial"))

    remainder = line[m.end():].strip()

    fields: Dict[str, Any] = {}
    for token in _tokenize_auditd_kv(remainder):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        key = key.strip()
        value = _strip_auditd_value(value.strip())
        if key:
            fields[key] = value

    iso_ts = _parse_epoch_to_iso(ts_sec, ts_usec)
    epoch = ts_sec + ts_usec / 1_000_000

    return {
        "source": "auditd",
        "raw": line,
        "type": rec_type,
        "timestamp": iso_ts,
        "epoch": epoch,
        "serial": serial,
        "fields": fields,
    }


def parse_auditd_record_stream(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    # generator: parse a stream of auditd lines into individual records.
    # each yielded dict corresponds to exactly one matching audit.log line.

    for line in lines:
        line = line.strip()
        if not line:
            continue
        rec = parse_auditd_record_line(line)
        if rec is not None:
            yield rec


# AUDITD HIGH-LEVEL EVENT ASSEMBLY (MULTI-RECORD, SYSCALL-CENTRIC)

def build_auditd_event(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    # build a high-level auditd event from all records sharing the same serial.
    # exposes syscall-centric fields, gathers cwd and file paths, concatenates raw lines,
    # and preserves all record data in the records list.

    if not records:
        raise ValueError("build_auditd_event() called with empty records list")

    base = records[0]
    timestamp = base.get("timestamp")
    epoch = base.get("epoch")
    serial = base.get("serial")

    def first_of_type(t: str) -> Optional[Dict[str, Any]]:
        for r in records:
            if r.get("type") == t:
                return r
        return None

    syscall_rec = first_of_type("SYSCALL") or {}
    cwd_rec = first_of_type("CWD") or {}
    path_recs = [r for r in records if r.get("type") == "PATH"]

    syscall_fields = syscall_rec.get("fields", {})
    cwd_fields = cwd_rec.get("fields", {})

    def to_int_from_syscall(key: str) -> Optional[int]:
        return _safe_int(syscall_fields.get(key))

    # filepaths from PATH records
    filepaths: List[str] = []
    for r in path_recs:
        f = r.get("fields", {})
        candidate = f.get("name") or f.get("obj")
        if candidate:
            filepaths.append(candidate)

    filepath = filepaths[0] if filepaths else None

    raw_lines = [r.get("raw", "") for r in records]

    rich_records: List[Dict[str, Any]] = []
    host: Optional[str] = None

    for r in records:
        r_fields = dict(r.get("fields", {}))
        # host from node/hostname if present anywhere
        if host is None:
            host = r_fields.get("node") or r_fields.get("hostname")

        rich_records.append(
            {
                "type": r.get("type"),
                "timestamp": r.get("timestamp"),
                "epoch": r.get("epoch"),
                "serial": r.get("serial"),
                "fields": r_fields,
                "raw": r.get("raw"),
            }
        )

    event_id = serial

    # best-effort category
    success_flag = syscall_fields.get("success")
    if success_flag == "no":
        category = "process_error"
    else:
        category = "process"

    return {
        "source": "auditd",
        "timestamp": timestamp,
        "epoch": epoch,
        "event_id": event_id,
        "serial": serial,
        "syscall": syscall_fields.get("syscall"),
        "success": success_flag == "yes",
        "exe": syscall_fields.get("exe"),
        "command": syscall_fields.get("comm"),
        "cwd": cwd_fields.get("cwd"),
        "tty": syscall_fields.get("tty"),
        "uid": to_int_from_syscall("uid"),
        "euid": to_int_from_syscall("euid"),
        "auid": to_int_from_syscall("auid"),
        "gid": to_int_from_syscall("gid"),
        "pid": to_int_from_syscall("pid"),
        "ppid": to_int_from_syscall("ppid"),
        "session": to_int_from_syscall("ses"),
        "host": host,
        "filepaths": filepaths,
        "filepath": filepath,
        "raw": "\n".join(raw_lines),
        "records": rich_records,
        "category": category,
    }


def build_auditd_events_from_stream(
    lines: Iterable[str],
) -> Iterable[Dict[str, Any]]:
    # high-level generator: audit.log lines -> rich auditd events.
    # records are grouped by serial; a new event is emitted when the serial changes.

    current_serial: Optional[int] = None
    current_records: List[Dict[str, Any]] = []

    for rec in parse_auditd_record_stream(lines):
        serial = rec.get("serial")

        if current_serial is None:
            current_serial = serial

        if serial != current_serial:
            if current_records:
                yield build_auditd_event(current_records)
            current_records = [rec]
            current_serial = serial
        else:
            current_records.append(rec)

    if current_records:
        yield build_auditd_event(current_records)


# JOURNALD INGEST (KEEPS ALL FIELDS)

def parse_journald_event(event: Any) -> Dict[str, Any]:
    # parse a single journald event (json string or dict) into a normalized dict.
    # keeps all original metadata in the fields and raw dicts (no data loss).

    if isinstance(event, str):
        event_raw = json.loads(event)
    else:
        event_raw = dict(event)  # defensive copy

    ts_us_str = (
        event_raw.get("__REALTIME_TIMESTAMP")
        or event_raw.get("_SOURCE_REALTIME_TIMESTAMP")
    )

    if ts_us_str is not None:
        ts_us = int(ts_us_str)
        ts_sec, ts_usec = divmod(ts_us, 1_000_000)
        iso_ts = _parse_epoch_to_iso(ts_sec, ts_usec)
        epoch = ts_sec + ts_usec / 1_000_000
    else:
        iso_ts = None
        epoch = None

    host = event_raw.get("_HOSTNAME") or event_raw.get("HOSTNAME")

    msg = event_raw.get("MESSAGE") or ""
    priority = _safe_int(event_raw.get("PRIORITY"))
    facility = _safe_int(event_raw.get("FACILITY"))

    unit = (
        event_raw.get("_SYSTEMD_UNIT")
        or event_raw.get("SYSLOG_IDENTIFIER")
    )

    process_id = _safe_int(event_raw.get("_PID") or event_raw.get("PID"))

    process_name = (
        event_raw.get("_COMM")
        or event_raw.get("SYSLOG_IDENTIFIER")
        or event_raw.get("_EXE")
    )

    category = _classify_journald_category(unit, process_name, msg, priority)

    fields = dict(event_raw)

    return {
        "source": "journald",
        "timestamp": iso_ts,
        "epoch": epoch,
        "host": host,
        "message": msg,
        "priority": priority,
        "facility": facility,
        "unit": unit,
        "process_id": process_id,
        "process_name": process_name,
        "category": category,
        "fields": fields,
        "raw": fields,
    }


def _classify_journald_category(
    unit: Optional[str],
    process_name: Optional[str],
    message: str,
    priority: Optional[int],
) -> str:
    # classify a journald event into a coarse category based on unit, process, message, and priority.

    unit_l = (unit or "").lower()
    pname = (process_name or "").lower()
    msg = (message or "").lower()

    if any(x in unit_l for x in ("ssh", "sshd", "sudo", "login")) or \
       any(x in pname for x in ("ssh", "sudo", "login")) or \
       "authentication" in msg or "failed password" in msg:
        return "auth"

    if unit_l.startswith("kernel") or pname == "kernel":
        return "kernel"

    if "systemd" in unit_l or "systemd" in pname:
        return "service"

    if priority is not None and priority <= 3:
        return "error"

    return "other"


def parse_journald_stream(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    # generator: parse a stream of journald json lines into normalized events.
    # typical producer: `journalctl -o json -f`

    for line in lines:
        line = line.strip()
        if not line:
            continue
        yield parse_journald_event(line)
