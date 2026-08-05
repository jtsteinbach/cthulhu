"""Ingest and normalization: raw auditd / journald -> canonical events.

The v1 pipeline lost the two things detections most depend on:

* the **full command line** — it exposed auditd's ``comm``, which the kernel
  truncates to 15 characters and which carries no arguments at all, so
  ``nc -e /bin/bash 10.0.0.5`` was only ever visible as ``nc``;
* the **audit key** and a meaningful **category** — every auditd event was
  labelled ``process``, so file-oriented rules could never match.

This module reconstructs ``cmdline`` from the ``EXECVE`` argv vector (falling
back to the hex-encoded ``PROCTITLE`` record), decodes auditd's hex fields,
resolves syscall numbers to names and names to categories, extracts ``key``,
and parses ``SOCKADDR`` into ``remote_ip`` / ``remote_port``.
"""

from __future__ import annotations

import binascii
import json
import os
import re
import socket
import struct
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

from .schema import ALIASES, SYSCALL_CATEGORY, syscall_name

__all__ = [
    "parse_audit_line",
    "assemble_audit_events",
    "parse_journal_event",
    "iter_journal_events",
    "apply_aliases",
    "ParentResolver",
]

# --------------------------------------------------------------------------
# auditd record parsing
# --------------------------------------------------------------------------

_AUDIT_HEADER_RE = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?"
    r"type=(?P<type>[A-Z0-9_]+)\s+"
    r"msg=audit\((?P<sec>\d+)(?:\.(?P<msec>\d+))?:(?P<serial>\d+)\):\s*"
)

_UNSET_UID = 4294967295  # (uid_t)-1 — auditd's "not set"


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_hex_decode(value: str) -> str:
    """auditd hex-encodes any value containing whitespace or specials.

    Such values arrive unquoted, even-length, and pure hex. Decoding them is
    what makes ``proctitle`` and non-trivial ``name=`` fields readable.
    """
    if len(value) < 2 or len(value) % 2 != 0:
        return value
    if not all(c in "0123456789abcdefABCDEF" for c in value):
        return value
    try:
        raw = binascii.unhexlify(value)
    except (binascii.Error, ValueError):
        return value
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return value
    # auditd separates argv entries with NUL inside proctitle.
    text = text.replace("\x00", " ").strip()
    if not text or any(ord(c) < 9 for c in text):
        return value
    return text


def _tokenize_kv(text: str) -> Iterator[tuple[str, str, bool]]:
    """Split ``k=v k="v with spaces"`` respecting quotes and escapes.

    Yields ``(key, value, quoted)``. The quoting flag matters: auditd only
    hex-encodes values it leaves *unquoted*, so a quoted ``a3="4444"`` is
    the literal string 4444 and must not be read as the hex bytes 0x44 0x44.
    """
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            return
        start = i
        while i < n and text[i] != "=" and not text[i].isspace():
            i += 1
        if i >= n or text[i] != "=":
            while i < n and not text[i].isspace():
                i += 1
            continue
        key = text[start:i]
        i += 1  # skip '='
        if i < n and text[i] == '"':
            i += 1
            buf: List[str] = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                buf.append(text[i])
                i += 1
            i += 1  # closing quote
            yield key, "".join(buf), True
        elif i < n and text[i] == "'":
            i += 1
            buf = []
            while i < n and text[i] != "'":
                buf.append(text[i])
                i += 1
            i += 1
            yield key, "".join(buf), True
        else:
            vstart = i
            while i < n and not text[i].isspace():
                i += 1
            yield key, text[vstart:i], False


# Fields that are hex-encoded when they contain awkward characters.
_HEXABLE = {"proctitle", "cmd", "name", "cwd", "exe", "comm", "data", "path"}


def parse_audit_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one audit.log line into a record dict, or None if unrecognized."""
    line = line.rstrip("\n").rstrip("\r")
    m = _AUDIT_HEADER_RE.match(line)
    if not m:
        return None

    sec = int(m.group("sec"))
    msec = int(m.group("msec") or 0)
    epoch = sec + msec / 1000.0
    fields: Dict[str, str] = {}

    for key, value, quoted in _tokenize_kv(line[m.end():]):
        if not quoted and (key in _HEXABLE or re.fullmatch(r"a\d+(\[\d+\])?", key)):
            value = _maybe_hex_decode(value)
        fields[key] = value

    return {
        "type": m.group("type"),
        "node": m.group("node"),
        "epoch": epoch,
        "serial": int(m.group("serial")),
        "fields": fields,
        "raw": line,
    }


def _execve_cmdline(fields: Dict[str, str]) -> tuple[Optional[str], List[str]]:
    """Rebuild argv from an EXECVE record's a0, a1, ... vector.

    Handles auditd's split-argument form (``a1_len`` / ``a1[0]``, ``a1[1]``)
    that appears when a single argument exceeds the record size limit.
    """
    argv: List[str] = []
    idx = 0
    while True:
        direct = fields.get(f"a{idx}")
        if direct is not None:
            argv.append(direct)
            idx += 1
            continue
        parts: List[str] = []
        part = 0
        while True:
            chunk = fields.get(f"a{idx}[{part}]")
            if chunk is None:
                break
            parts.append(chunk)
            part += 1
        if parts:
            argv.append("".join(parts))
            idx += 1
            continue
        break
    if not argv:
        return None, []
    return " ".join(argv), argv


def _parse_sockaddr(hexstr: str) -> Dict[str, Any]:
    """Decode an auditd SOCKADDR ``saddr=`` blob."""
    out: Dict[str, Any] = {}
    try:
        raw = binascii.unhexlify(hexstr.strip())
    except (binascii.Error, ValueError):
        return out
    if len(raw) < 2:
        return out
    family = struct.unpack("<H", raw[:2])[0]
    try:
        if family == socket.AF_INET and len(raw) >= 8:
            port = struct.unpack("!H", raw[2:4])[0]
            out["remote_ip"] = socket.inet_ntop(socket.AF_INET, raw[4:8])
            out["remote_port"] = port
            out["addr_family"] = "inet"
        elif family == socket.AF_INET6 and len(raw) >= 24:
            port = struct.unpack("!H", raw[2:4])[0]
            out["remote_ip"] = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            out["remote_port"] = port
            out["addr_family"] = "inet6"
        elif family == socket.AF_UNIX:
            path = raw[2:].split(b"\x00")[0].decode("utf-8", "replace")
            if path:
                out["socket_path"] = path
            out["addr_family"] = "unix"
        elif family == 16:
            out["addr_family"] = "netlink"
    except (OSError, ValueError):
        return out
    return out


_MUTATING_SYSCALLS = {
    "write", "pwrite64", "writev", "truncate", "ftruncate",
    "rename", "renameat", "renameat2", "unlink", "unlinkat",
    "link", "linkat", "symlink", "symlinkat", "mkdir", "mkdirat",
    "rmdir", "creat", "mknod", "mknodat", "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "fchownat", "lchown", "utimensat",
    "setxattr", "lsetxattr", "fsetxattr", "removexattr",
}

_INTERPRETERS = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
    "python", "python2", "python3", "perl", "ruby", "php", "lua",
    "node", "nodejs", "awk", "gawk",
}


def build_audit_event(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Fold all records sharing one serial into a single canonical event."""
    base = records[0]
    epoch = base["epoch"]
    serial = base["serial"]

    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records:
        by_type.setdefault(rec["type"], []).append(rec)

    syscall_rec = (by_type.get("SYSCALL") or [{}])[0]
    sf: Dict[str, str] = syscall_rec.get("fields", {}) if syscall_rec else {}

    ev: Dict[str, Any] = {
        "source": "auditd",
        "epoch": epoch,
        "timestamp": _iso(epoch),
        "serial": serial,
        "event_id": serial,
        "record_types": sorted(by_type),
        "host": base.get("node"),
    }

    # ---- process / syscall -------------------------------------------
    sc_num = sf.get("syscall")
    sc_name = syscall_name(sc_num)
    ev["syscall"] = sc_num
    ev["syscall_name"] = sc_name
    ev["arch"] = sf.get("arch")
    ev["exit_code"] = _to_int(sf.get("exit"))

    success = sf.get("success")
    if success is not None:
        ev["success"] = success == "yes"
        ev["outcome"] = "success" if success == "yes" else "failure"
    elif ev["exit_code"] is not None:
        ev["success"] = ev["exit_code"] >= 0
        ev["outcome"] = "success" if ev["success"] else "failure"

    exe = sf.get("exe")
    if exe:
        ev["exe"] = exe
        ev["exe_name"] = exe.rsplit("/", 1)[-1]
        ev["exe_dir"] = exe.rsplit("/", 1)[0] or "/"
    if sf.get("comm"):
        ev["comm"] = sf["comm"]

    for src, dst in (("pid", "pid"), ("ppid", "ppid"), ("ses", "session")):
        val = _to_int(sf.get(src))
        if val is not None:
            ev[dst] = val

    for name in ("uid", "euid", "suid", "fsuid", "gid", "egid", "auid"):
        val = _to_int(sf.get(name))
        if val is None:
            continue
        if name == "auid" and val == _UNSET_UID:
            ev["auid"] = -1
            ev["auid_set"] = False
            continue
        ev[name] = val
    if "auid" in ev and "auid_set" not in ev:
        ev["auid_set"] = ev["auid"] >= 0

    tty = sf.get("tty")
    if tty:
        ev["tty"] = tty
        ev["interactive"] = tty not in ("(none)", "none", "?", "")

    # audit rule key(s): auditd joins multiple keys with 0x01
    key_raw = sf.get("key") or ""
    if key_raw and key_raw not in ("(null)", "(none)"):
        keys = [k for k in re.split(r"[\x01]", _maybe_hex_decode(key_raw)) if k]
        if keys:
            ev["key"] = keys[0]
            ev["keys"] = keys

    # ---- identity flags ----------------------------------------------
    euid = ev.get("euid", ev.get("uid"))
    uid = ev.get("uid")
    if euid is not None:
        ev["is_root"] = euid == 0
    if uid is not None:
        ev["is_system_user"] = uid < 1000
    if euid is not None and uid is not None:
        ev["priv_escalated"] = euid == 0 and uid != 0

    # Human-readable names auditd appends (UID="root", AUID="alice", ...)
    for rec in records:
        rf = rec["fields"]
        for src, dst in (("UID", "user"), ("EUID", "euser"), ("AUID", "auser")):
            if dst not in ev and rf.get(src) and rf[src] != "unset":
                ev[dst] = rf[src]

    # ---- command line -------------------------------------------------
    cmdline: Optional[str] = None
    argv: List[str] = []
    if "EXECVE" in by_type:
        cmdline, argv = _execve_cmdline(by_type["EXECVE"][0]["fields"])
    if not cmdline and "PROCTITLE" in by_type:
        pt = by_type["PROCTITLE"][0]["fields"].get("proctitle")
        if pt:
            ev["proctitle"] = pt
            cmdline = pt
            argv = pt.split(" ")
    if cmdline:
        ev["cmdline"] = cmdline
        ev["argv"] = argv
        ev["argc"] = len(argv)
    elif ev.get("exe"):
        ev["cmdline"] = ev["exe"]

    # interpreter / script detection
    name = ev.get("exe_name")
    if name:
        stem = re.sub(r"[\d.]+$", "", name)
        if name in _INTERPRETERS or stem in _INTERPRETERS:
            ev["interpreter"] = name
            if argv and len(argv) > 1:
                ev["is_script"] = any(
                    a.startswith(("/", "./", "../")) or a.endswith(
                        (".sh", ".py", ".pl", ".rb", ".php"))
                    for a in argv[1:])

    if "CWD" in by_type:
        cwd = by_type["CWD"][0]["fields"].get("cwd")
        if cwd:
            ev["cwd"] = cwd

    # ---- file targets -------------------------------------------------
    paths: List[str] = []
    primary: Optional[Dict[str, str]] = None
    for rec in by_type.get("PATH", []):
        pf = rec["fields"]
        candidate = pf.get("name")
        if not candidate or candidate in (".", ".."):
            continue
        if not candidate.startswith("/") and ev.get("cwd"):
            candidate = f"{ev['cwd'].rstrip('/')}/{candidate}"
        paths.append(candidate)
        nametype = pf.get("nametype")
        if primary is None or nametype in ("CREATE", "DELETE", "NORMAL"):
            if primary is None or primary.get("nametype") == "PARENT":
                primary = {**pf, "_resolved": candidate}

    if paths:
        ev["paths"] = paths
        target = primary.get("_resolved") if primary else paths[0]
        ev["path"] = target
        base_name = target.rsplit("/", 1)[-1]
        ev["file_name"] = base_name
        ev["file_dir"] = target.rsplit("/", 1)[0] or "/"
        if "." in base_name and not base_name.startswith("."):
            ev["file_ext"] = base_name.rsplit(".", 1)[-1].lower()
        if primary:
            if primary.get("nametype"):
                ev["nametype"] = primary["nametype"]
            mode = primary.get("mode")
            if mode:
                ev["mode"] = mode
                mode_int = _to_int(int(mode, 8)) if re.fullmatch(r"[0-7]+", mode) else None
                if mode_int is not None:
                    ev["is_setuid"] = bool(mode_int & 0o4000)
                    ev["is_setgid"] = bool(mode_int & 0o2000)
            for src, dst in (("ouid", "owner_uid"), ("ogid", "owner_gid")):
                val = _to_int(primary.get(src))
                if val is not None:
                    ev[dst] = val

    # ---- network ------------------------------------------------------
    for rec in by_type.get("SOCKADDR", []):
        saddr = rec["fields"].get("saddr")
        if saddr:
            ev.update(_parse_sockaddr(saddr))
            break

    # ---- read vs write -------------------------------------------------
    # auditd labels both a read and a write of /etc/shadow as a file event.
    # Mutating syscalls are unambiguous; for open/openat the intent lives in
    # the flags argument, which auditd logs in hex.
    if sc_name in _MUTATING_SYSCALLS:
        ev["is_write"] = True
    elif sc_name in ("open", "openat", "openat2"):
        flag_arg = {"open": "a1", "openat": "a2", "openat2": "a2"}[sc_name]
        try:
            flags = int(sf.get(flag_arg, "0"), 16)
        except (TypeError, ValueError):
            flags = 0
        ev["open_flags"] = flags
        # O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND
        ev["is_write"] = bool(flags & (0o1 | 0o2 | 0o100 | 0o1000 | 0o2000))
    elif sc_name is not None:
        ev["is_write"] = False

    # ---- category / action --------------------------------------------
    ev["action"] = sc_name or base["type"].lower()
    category = SYSCALL_CATEGORY.get(sc_name or "")
    rtypes = set(by_type)
    if rtypes & {"USER_AUTH", "USER_LOGIN", "USER_ACCT", "USER_START",
                 "CRED_ACQ", "CRED_REFR", "LOGIN", "USER_ERR", "USER_CMD"}:
        category = "auth"
        ev["action"] = base["type"].lower()
    elif rtypes & {"ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP",
                   "USER_CHAUTHTOK", "ROLE_ASSIGN", "ROLE_REMOVE"}:
        category = "auth"
    elif rtypes & {"CONFIG_CHANGE", "DAEMON_START", "DAEMON_END"}:
        category = "audit"
    elif rtypes & {"KERN_MODULE", "MAC_STATUS"}:
        category = "module"
    elif rtypes & {"AVC", "SECCOMP", "ANOM_ABEND", "ANOM_PROMISCUOUS"}:
        category = "kernel"
    if category is None and "PATH" in rtypes:
        category = "file"
    ev["category"] = category or "other"

    # auth-record niceties: acct="user", res=success/failed
    if ev["category"] == "auth":
        for rec in records:
            rf = rec["fields"]
            if "acct" in rf and "auth_user" not in ev:
                ev["auth_user"] = _maybe_hex_decode(rf["acct"])
            if "res" in rf and "auth_result" not in ev:
                ev["auth_result"] = "success" if rf["res"] in ("success", "yes") else "failure"
                ev.setdefault("success", rf["res"] in ("success", "yes"))
                ev.setdefault("outcome", ev["auth_result"])
            if "cmd" in rf and "sudo_command" not in ev:
                ev["sudo_command"] = _maybe_hex_decode(rf["cmd"])
                ev.setdefault("cmdline", ev["sudo_command"])
            if "terminal" in rf and "tty" not in ev:
                ev["tty"] = rf["terminal"]
            if "addr" in rf and rf["addr"] not in ("?", "") and "remote_ip" not in ev:
                ev["remote_ip"] = rf["addr"]

    ev["raw"] = "\n".join(r["raw"] for r in records)
    ev["records"] = [
        {"type": r["type"], "fields": r["fields"], "serial": r["serial"]}
        for r in records
    ]
    return ev


def assemble_audit_events(
    lines: Iterable[str],
    flush_seconds: float = 1.0,
    now: Optional[Any] = None,
) -> Iterator[Dict[str, Any]]:
    """Group audit records into events.

    v1 emitted an event only when the *next* serial appeared, so in a live
    tail the newest event sat buffered indefinitely. Here an event is emitted
    as soon as its ``EOE`` marker arrives, when a different serial shows up,
    or when ``flush_seconds`` elapses with nothing new — so the last event is
    never stranded. Records for interleaved serials are kept separate.
    """
    import time as _time

    clock = now or _time.monotonic
    pending: Dict[int, List[Dict[str, Any]]] = {}
    arrived: Dict[int, float] = {}

    def flush(serial: int) -> Optional[Dict[str, Any]]:
        recs = pending.pop(serial, None)
        arrived.pop(serial, None)
        if not recs:
            return None
        return build_audit_event(recs)

    for line in lines:
        if line is None:  # idle tick from the tailer
            deadline = clock() - flush_seconds
            for serial in [s for s, t in arrived.items() if t <= deadline]:
                ev = flush(serial)
                if ev:
                    yield ev
            continue

        line = line.strip()
        if not line:
            continue
        rec = parse_audit_line(line)
        if rec is None:
            continue

        serial = rec["serial"]
        if rec["type"] == "EOE":
            ev = flush(serial)
            if ev:
                yield ev
            continue

        pending.setdefault(serial, []).append(rec)
        arrived.setdefault(serial, clock())

        # Bound memory if a broken producer never sends EOE.
        if len(pending) > 512:
            oldest = min(arrived, key=arrived.get)
            ev = flush(oldest)
            if ev:
                yield ev

    for serial in list(pending):
        ev = flush(serial)
        if ev:
            yield ev


# --------------------------------------------------------------------------
# journald
# --------------------------------------------------------------------------

_PRIORITY_LABELS = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# sshd / sudo message shapes worth structuring.
_SSH_FAIL_RE = re.compile(
    r"(?P<res>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)")
_SSH_INVALID_RE = re.compile(
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)")
_SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:.*?TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*"
    r"USER=(?P<target>\S*)\s*;\s*COMMAND=(?P<cmd>.+)$")
_SUDO_FAIL_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?P<reason>\d+ incorrect password attempts?"
    r"|authentication failure|user NOT in sudoers)")


def parse_journal_event(entry: Any) -> Optional[Dict[str, Any]]:
    """Normalize one journald JSON entry."""
    if isinstance(entry, (str, bytes)):
        try:
            entry = json.loads(entry)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
    if not isinstance(entry, dict):
        return None

    def text(value: Any) -> Optional[str]:
        # journald renders non-UTF8 payloads as an array of byte values.
        if isinstance(value, list):
            try:
                return bytes(value).decode("utf-8", "replace")
            except (TypeError, ValueError):
                return " ".join(str(v) for v in value)
        return value if value is None or isinstance(value, str) else str(value)

    ts_us = entry.get("__REALTIME_TIMESTAMP") or entry.get("_SOURCE_REALTIME_TIMESTAMP")
    epoch = None
    if ts_us is not None:
        try:
            epoch = int(ts_us) / 1_000_000
        except (TypeError, ValueError):
            epoch = None

    message = text(entry.get("MESSAGE")) or ""
    unit = text(entry.get("_SYSTEMD_UNIT"))
    syslog_id = text(entry.get("SYSLOG_IDENTIFIER"))
    comm = text(entry.get("_COMM"))
    priority = _to_int(entry.get("PRIORITY"))

    ev: Dict[str, Any] = {
        "source": "journald",
        "epoch": epoch,
        "timestamp": _iso(epoch) if epoch is not None else None,
        "host": text(entry.get("_HOSTNAME")),
        "message": message,
        "message_snippet": message[:200],
        "unit": unit,
        "syslog_id": syslog_id,
        "comm": comm or syslog_id,
        "exe_name": comm or syslog_id,
        "boot_id": text(entry.get("_BOOT_ID")),
        "machine_id": text(entry.get("_MACHINE_ID")),
    }

    exe = text(entry.get("_EXE"))
    if exe:
        ev["exe"] = exe
        ev["exe_name"] = exe.rsplit("/", 1)[-1]
    if text(entry.get("_CMDLINE")):
        ev["cmdline"] = text(entry.get("_CMDLINE"))

    if unit and unit.endswith(".service"):
        ev["service"] = unit[: -len(".service")]
    elif unit:
        ev["service"] = unit.rsplit(".", 1)[0]

    for src, dst in (("_PID", "pid"), ("_UID", "uid"), ("_GID", "gid"),
                     ("_AUDIT_LOGINUID", "auid"), ("_AUDIT_SESSION", "session")):
        val = _to_int(entry.get(src))
        if val is not None:
            if dst == "auid" and val == _UNSET_UID:
                ev["auid"] = -1
                ev["auid_set"] = False
                continue
            ev[dst] = val
    if "uid" in ev:
        ev["is_root"] = ev["uid"] == 0
        ev["is_system_user"] = ev["uid"] < 1000

    facility = _to_int(entry.get("SYSLOG_FACILITY"))
    if facility is not None:
        ev["facility"] = facility
    if priority is not None:
        ev["priority"] = priority
        ev["priority_label"] = _PRIORITY_LABELS.get(priority)
        ev["is_error"] = priority <= 3
        ev["is_warning"] = priority == 4

    ident = (comm or syslog_id or "").lower()
    ev["category"] = _journal_category(unit, ident, message, priority)
    ev["action"] = "log"

    # ---- structured auth extraction ----------------------------------
    if ident in ("sshd", "sshd-session"):
        m = _SSH_FAIL_RE.search(message)
        if m:
            failed = m.group("res") == "Failed"
            ev.update({
                "category": "auth",
                "action": "ssh_login",
                "auth_user": m.group("user"),
                "auth_method": m.group("method").lower(),
                "auth_result": "failure" if failed else "success",
                "success": not failed,
                "outcome": "failure" if failed else "success",
                "remote_ip": m.group("ip"),
                "remote_port": _to_int(m.group("port")),
            })
            if "invalid user" in message.lower():
                ev["auth_result"] = "invalid_user"
        else:
            m = _SSH_INVALID_RE.search(message)
            if m:
                ev.update({
                    "category": "auth", "action": "ssh_login",
                    "auth_user": m.group("user"), "auth_result": "invalid_user",
                    "success": False, "outcome": "failure",
                    "remote_ip": m.group("ip"),
                })
    elif ident == "sudo":
        m = _SUDO_RE.match(message)
        if m:
            ev.update({
                "category": "auth", "action": "sudo",
                "auth_user": m.group("user"),
                "sudo_target_user": m.group("target"),
                "sudo_command": m.group("cmd").strip(),
                "cmdline": m.group("cmd").strip(),
                "cwd": m.group("pwd"),
                "tty": m.group("tty") or None,
                "auth_result": "success", "success": True, "outcome": "success",
            })
        else:
            m = _SUDO_FAIL_RE.match(message)
            if m:
                ev.update({
                    "category": "auth", "action": "sudo",
                    "auth_user": m.group("user"),
                    "auth_result": "failure", "success": False,
                    "outcome": "failure",
                })

    return ev


def _journal_category(unit: Optional[str], ident: str,
                      message: str, priority: Optional[int]) -> str:
    u = (unit or "").lower()
    msg = message.lower()

    if ident in ("sshd", "sshd-session", "sudo", "su", "login", "polkitd",
                 "systemd-logind", "gdm-password") or "pam_" in msg:
        return "auth"
    if any(k in msg for k in ("authentication failure", "failed password",
                              "invalid user", "session opened for user")):
        return "auth"
    if ident == "kernel" or u.startswith("kernel"):
        return "kernel"
    if ident == "auditd" or "audit" in u:
        return "audit"
    if u.endswith(".service") or ident == "systemd":
        return "service"
    if priority is not None and priority <= 3:
        return "log"
    return "log"


def iter_journal_events(lines: Iterable[str]) -> Iterator[Dict[str, Any]]:
    for line in lines:
        if not line:
            continue
        line = line.strip()
        if not line:
            continue
        ev = parse_journal_event(line)
        if ev is not None:
            yield ev


# --------------------------------------------------------------------------
# Legacy aliases
# --------------------------------------------------------------------------


class ParentResolver:
    """Best-effort ``ppid`` -> name/path lookup via ``/proc``.

    v1 read ``/proc/<ppid>/comm`` on every single event with no cache and no
    guard against PID reuse, so a recycled PID could attribute an event to
    the wrong parent. Here the cache key includes the process start time from
    ``/proc/<pid>/stat`` field 22, which is unique per process, and results
    (including misses) are cached so a busy host does not re-stat constantly.
    """

    __slots__ = ("_cache", "_order", "_max")

    def __init__(self, max_entries: int = 4096) -> None:
        self._cache: Dict[tuple, Dict[str, Any]] = {}
        self._order: List[tuple] = []
        self._max = max_entries

    @staticmethod
    def _starttime(pid: int) -> Optional[str]:
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                data = fh.read()
        except OSError:
            return None
        # comm may contain spaces/parens; everything after the final ')'.
        close = data.rfind(b")")
        if close < 0:
            return None
        parts = data[close + 2:].split()
        return parts[19].decode() if len(parts) > 19 else None

    def resolve(self, pid: Optional[int]) -> Dict[str, Any]:
        if not isinstance(pid, int) or pid <= 0:
            return {}
        start = self._starttime(pid)
        if start is None:
            return {}
        key = (pid, start)
        hit = self._cache.get(key)
        if hit is not None:
            return hit

        info: Dict[str, Any] = {}
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
                name = fh.read().strip()
            if name:
                info["parent_name"] = name
        except OSError:
            pass
        try:
            info["parent_exe"] = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass

        self._cache[key] = info
        self._order.append(key)
        if len(self._order) > self._max:
            for stale in self._order[: self._max // 2]:
                self._cache.pop(stale, None)
            del self._order[: self._max // 2]
        return info


def apply_aliases(event: Dict[str, Any]) -> Dict[str, Any]:
    """Materialize v1 field names so pre-existing rules keep working."""
    for old, new in ALIASES.items():
        if old not in event and new in event:
            event[old] = event[new]
    return event
