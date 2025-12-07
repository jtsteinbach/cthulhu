# JRL – Jaco Rule Language Reference

---

## 1. SUMMARY

JRL (Jaco Rule Language) is the rule format used to match system events and trigger alerts.  
Rules evaluate against **enriched events**, which include:

- Raw auditd or journald event fields  
- Normalized meta fields  
- Enrichment fields (process_name, command_line, file_ext, etc.)
- Severities: low, medium, high

Rules follow this structure:

```text
name(severity)
    | "Description"
    : condition
    : condition
```

All `:` conditions must be true.

---

## 1.5 JRL SYNTAX GUIDE

This is the minimal syntax needed to write rules.

**Rule structure**
```text
name(severity)
    | "Description"
    : condition
    : condition
```

**Comparisons**
```text
==  !=  <  >  <=  >=
```

**Boolean logic**
```text
and  or  not
```

**Null checks**
```text
field is null
field is not null
```

**String operators**
```text
field contains "text"
field !contains "text"
field startswith "/path"
field !startswith "/path"
field endswith ".sh"
field !endswith ".sh"
```

**Grouping**
```text
(field1 == 1 or field2 == 2) and success_bool == true
```

---

## 2. ALL USABLE FIELDS IN JRL

These are **all fields rules can reference**, including raw, meta, and enriched fields.

### 2.1 Core Fields (all events)

```text
source
timestamp
epoch
host
category
success
success_bool
outcome
```

---

### 2.2 Auditd Raw Fields

Available for audit events:

```text
event_id
serial
syscall
exe
command
cwd
tty
uid
euid
auid
gid
pid
ppid
ppid_name
ppid_path
session
filepath
filepaths
```

---

### 2.3 Auditd Enrichment Fields

```text
command_line
process_path
process_name
exe_basename
process_id
parent_pid
parent_process_name
parent_process_path
target_path
file_name
file_ext
interactive
```

---

### 2.4 Journald Raw Fields

Available for journald events:

```text
message
priority
facility
unit
process_id
process_name
```

---

### 2.5 Journald Enrichment Fields

```text
log_message
message_snippet
log_unit
service_name
log_facility
log_priority
log_priority_label
is_error
is_warning
is_info
```

---

## 3. AUDITD EVENT FORMAT (FULL STRUCTURE)

A complete auditd event provides fields like:

```json
{
  "source": "auditd",
  "timestamp": "...",
  "epoch": 0.0,
  "event_id": 123,
  "serial": 123,
  "syscall": "59",
  "success": true,
  "exe": "/usr/bin/bash",
  "command": "bash",
  "cwd": "/home/user",
  "tty": "/dev/pts/1",
  "uid": 1000,
  "euid": 1000,
  "auid": 1000,
  "gid": 1000,
  "pid": 2000,
  "ppid": 1999,
  "parent_process_name": "bash",
  "parent_process_path": "/usr/bin/bash",
  "session": 12,
  "host": "hostname",
  "filepath": "/tmp/file.txt",
  "filepaths": ["/tmp/file.txt"],
  "category": "process"
}
```

---

## 4. JOURNALD EVENT FORMAT (FULL STRUCTURE)

A complete journald event provides:

```json
{
  "source": "journald",
  "timestamp": "...",
  "epoch": 0.0,
  "host": "hostname",
  "message": "Service started",
  "priority": 5,
  "facility": 3,
  "unit": "sshd.service",
  "process_id": 1234,
  "process_name": "sshd",
  "category": "auth"
}
```

---

## 5. JRL EXAMPLES

### 5.1 Detect Netcat Reverse Shell

```text
reverse_nc(high)
    | "Netcat reverse shell"
    : exe_basename == "nc" or exe_basename == "ncat"
    : command_line contains " -e "
```

### 5.2 Detect Bash /dev/tcp Reverse Shell

```text
reverse_bash(high)
    | "Reverse shell via /dev/tcp"
    : exe_basename == "bash"
    : command_line contains "/dev/tcp"
```

### 5.3 Interactive Root Shell

```text
root_shell(high)
    | "Interactive root shell"
    : uid == 0
    : interactive == true
```

### 5.4 Journald Authentication Failure

```text
auth_fail(medium)
    | "Authentication failure in logs"
    : source == "journald"
    : category == "auth"
    : is_error == true
```
