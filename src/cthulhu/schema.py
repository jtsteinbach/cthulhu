"""Canonical event schema for CTHULHU.

Every field a JRL rule may reference is declared here. The ingest layer
promises to produce these names; the JRL loader validates rules against
them at load time so a typo becomes a startup warning instead of a rule
that silently never fires.

Fields absent from an event evaluate to NULL (not an error), so a rule
written for auditd simply does not match a journald event.
"""

from __future__ import annotations

from typing import Dict, Final, Set

# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------

SEVERITIES: Final[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")

SEVERITY_ORDER: Final[Dict[str, int]] = {s: i for i, s in enumerate(SEVERITIES)}


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(str(sev).strip().lower(), -1)


# --------------------------------------------------------------------------
# Categories emitted by the normalizer
# --------------------------------------------------------------------------

CATEGORIES: Final[tuple[str, ...]] = (
    "process",     # execve / process creation
    "file",        # open, write, unlink, rename, chmod, chown, ...
    "network",     # connect, bind, accept, socket
    "auth",        # login, sudo, su, pam, sshd auth
    "privilege",   # setuid/setgid/capset transitions
    "service",     # systemd unit lifecycle
    "kernel",      # kernel ring buffer messages
    "module",      # kernel module load/unload
    "audit",       # auditd self-reported config changes
    "log",         # generic log line
    "other",
)

# --------------------------------------------------------------------------
# Field registry
#
# Grouped for documentation/UI purposes. `ALL_FIELDS` is the flat set used
# for rule validation.
# --------------------------------------------------------------------------

FIELD_GROUPS: Final[Dict[str, tuple[str, ...]]] = {
    "core": (
        "source",          # "auditd" | "journald"
        "timestamp",       # ISO-8601 UTC string
        "epoch",           # float seconds
        "host",
        "category",
        "action",          # normalized verb: execve, open, connect, login, ...
        "outcome",         # "success" | "failure" | null
        "success",         # bool
    ),
    "process": (
        "exe",             # full executable path
        "exe_name",        # basename of exe
        "exe_dir",
        "comm",            # kernel comm (<=16 chars, may be truncated)
        "cmdline",         # FULL reconstructed command line
        "argv",            # list[str]
        "argc",
        "cwd",
        "pid",
        "ppid",
        "parent_exe",
        "parent_name",
        "tty",
        "session",
        "interactive",     # bool: has a real tty
        "is_script",       # bool: interpreter executing a script
        "interpreter",     # bash/python/perl/php/... when applicable
    ),
    "identity": (
        "uid",
        "euid",
        "suid",
        "fsuid",
        "auid",            # login uid (audit user); -1 when unset
        "gid",
        "egid",
        "user",            # resolved name for uid
        "euser",
        "auser",
        "is_root",         # euid == 0
        "is_system_user",  # uid < 1000
        "priv_escalated",  # euid == 0 and uid != 0
        "auid_set",        # auid is a real login uid
    ),
    "file": (
        "path",            # primary target path, cwd-resolved
        "paths",           # list[str] of all PATH records
        "file_name",
        "file_ext",
        "file_dir",
        "mode",            # octal string from PATH record
        "owner_uid",
        "owner_gid",
        "is_setuid",       # setuid bit present on target
        "is_setgid",
        "nametype",        # NORMAL / CREATE / DELETE / PARENT ...
        "is_write",        # True when the syscall actually mutates the target
        "open_flags",
    ),
    "network": (
        "remote_ip",
        "remote_port",
        "local_ip",
        "local_port",
        "addr_family",     # inet / inet6 / unix / netlink
        "socket_path",
    ),
    "audit": (
        "syscall",         # numeric string
        "syscall_name",    # resolved name, e.g. "execve"
        "key",             # auditd -k key
        "keys",            # list when multiple
        "serial",
        "event_id",
        "arch",
        "exit_code",
        "record_types",    # list[str] of audit record types in this event
        "proctitle",
    ),
    "journald": (
        "message",
        "message_snippet",
        "unit",
        "service",
        "syslog_id",
        "priority",
        "priority_label",
        "facility",
        "is_error",
        "is_warning",
        "boot_id",
        "machine_id",
    ),
    "auth": (
        "auth_user",       # username involved in an auth event
        "auth_method",     # password / publickey / keyboard-interactive
        "auth_result",     # success / failure / invalid_user
        "sudo_command",
        "sudo_target_user",
    ),
    "web": (
        "http_method",
        "http_path",
        "http_status",
        "http_query",
        "http_version",
        "user_agent",
        "referer",
        "bytes_sent",
        "request_time",
        "virtual_host",
    ),
}

ALL_FIELDS: Final[Set[str]] = {f for group in FIELD_GROUPS.values() for f in group}

# --------------------------------------------------------------------------
# Backwards-compatible aliases (v1 JRL rule vocabulary).
#
# Old rules keep working; the normalizer materializes these as real keys.
# --------------------------------------------------------------------------

ALIASES: Final[Dict[str, str]] = {
    "command_line": "cmdline",
    "process_name": "exe_name",
    "exe_basename": "exe_name",
    "process_path": "exe",
    "process_id": "pid",
    "parent_pid": "ppid",
    "parent_process_name": "parent_name",
    "parent_process_path": "parent_exe",
    "filepath": "path",
    "filepaths": "paths",
    "target_path": "path",
    "log_message": "message",
    "log_unit": "unit",
    "service_name": "service",
    "log_priority": "priority",
    "log_priority_label": "priority_label",
    "log_facility": "facility",
    "success_bool": "success",
    "ppid_name": "parent_name",
    "ppid_path": "parent_exe",
}

KNOWN_FIELDS: Final[Set[str]] = ALL_FIELDS | set(ALIASES)

#: Fields contributed at runtime by declarative or third-party feeds.
EXTRA_FIELDS: Set[str] = set()


def register_fields(names: Set[str] | tuple[str, ...]) -> None:
    """Let a feed declare fields so rules referencing them validate cleanly."""
    EXTRA_FIELDS.update(n for n in names if n)


def known_fields() -> Set[str]:
    """Every field a rule may legitimately reference right now."""
    return KNOWN_FIELDS | EXTRA_FIELDS


def resolve_alias(name: str) -> str:
    """Map a legacy field name onto its canonical name."""
    return ALIASES.get(name, name)


# --------------------------------------------------------------------------
# Syscall table (x86_64 / aarch64 common subset actually worth auditing)
# --------------------------------------------------------------------------

SYSCALL_NAMES: Final[Dict[str, str]] = {
    "0": "read", "1": "write", "2": "open", "3": "close", "4": "stat",
    "5": "fstat", "6": "lstat", "8": "lseek", "9": "mmap", "10": "mprotect",
    "21": "access", "22": "pipe", "32": "dup", "33": "dup2",
    "41": "socket", "42": "connect", "43": "accept", "44": "sendto",
    "45": "recvfrom", "46": "sendmsg", "47": "recvmsg", "48": "shutdown",
    "49": "bind", "50": "listen", "56": "clone", "57": "fork", "58": "vfork",
    "59": "execve", "62": "kill", "82": "rename", "83": "mkdir", "84": "rmdir",
    "85": "creat", "86": "link", "87": "unlink", "88": "symlink",
    "90": "chmod", "91": "fchmod", "92": "chown", "93": "fchown",
    "94": "lchown", "101": "ptrace", "105": "setuid", "106": "setgid",
    "113": "setreuid", "114": "setregid", "117": "setresuid",
    "119": "setresgid", "133": "mknod", "155": "pivot_root", "161": "chroot",
    "165": "mount", "166": "umount2", "169": "reboot", "175": "init_module",
    "176": "delete_module", "180": "quotactl", "246": "kexec_load",
    "257": "openat", "258": "mkdirat", "259": "mknodat", "260": "fchownat",
    "263": "unlinkat", "264": "renameat", "265": "linkat", "266": "symlinkat",
    "268": "fchmodat", "280": "utimensat", "288": "accept4",
    "313": "finit_module", "316": "renameat2", "317": "seccomp",
    "319": "memfd_create", "321": "bpf", "322": "execveat",
    "424": "pidfd_send_signal", "435": "clone3",
}


def syscall_name(num: object) -> str | None:
    if num is None:
        return None
    return SYSCALL_NAMES.get(str(num))


# Syscalls grouped into the categories the normalizer assigns.
SYSCALL_CATEGORY: Final[Dict[str, str]] = {}
for _n, _c in (
    (("execve", "execveat", "clone", "fork", "vfork", "clone3"), "process"),
    (("open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat",
      "renameat2", "link", "linkat", "symlink", "symlinkat", "mkdir",
      "mkdirat", "rmdir", "chmod", "fchmod", "fchmodat", "chown", "fchown",
      "fchownat", "lchown", "truncate", "ftruncate", "mknod", "mknodat",
      "write", "utimensat"), "file"),
    (("socket", "connect", "bind", "listen", "accept", "accept4", "sendto",
      "recvfrom", "sendmsg", "recvmsg"), "network"),
    (("setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
      "capset", "ptrace"), "privilege"),
    (("init_module", "finit_module", "delete_module"), "module"),
    (("mount", "umount2", "pivot_root", "chroot"), "file"),
):
    for _name in _n:
        SYSCALL_CATEGORY[_name] = _c
