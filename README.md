![CTHULHU SIEM](https://r2.jts.gg/cth_logo.png)

# CTHULHU SIEM

**CTHULHU SIEM** is a small, Linux-focused SIEM built in **100% Python (standard library only)**.

It watches:

- **auditd** (`/var/log/audit/audit.log`)
- **systemd-journald** (via `journalctl -o json -f`)

and turns them into normalized events, passes them through a simple rule engine (JRL), and writes alerts as JSONL.

---

## 1. What CTHULHU Does

- Collects events from **auditd** and **journald**
- Normalizes them into a common event model
- Enriches events with useful fields (for example `command_line`, `process_name`, `target_path`, `log_priority_label`)
- Applies rules written in **Jaco Ruling Language (JRL)**
- Writes alerts to a file as one-JSON-object-per-line
- Provides a **terminal-based alert console** for triage

No external services, no external Python packages, no agents.

---

## 2. Core Components

All code typically lives under `/cthulhu/src`.

- `engine.py`  
  - Main daemon
  - Tails auditd and journald
  - Evaluates rules
  - Calls the alert handler

- `ingest_events.py`  
  - Parses auditd lines → syscall-centric events  
  - Parses journald JSON → normalized events  
  - Preserves original fields in `fields` / `raw`

- `rule_handler.py`  
  - Loads rules from `alert.rules`
  - Converts JRL conditions into safe Python expressions
  - Evaluates each event against all rules

- `alert_handler.py`  
  - Builds a structured alert:
    - `rule` (name, severity, description)
    - `event_meta` (normalized/enriched)
    - `event_summary` (triage-friendly)
    - `rule_highlights` (“why this fired”)
    - full `event`

- `cli.py`  
  - Interactive terminal console:
    - live alert feed
    - filter by severity
    - triage by UID
    - list/search alerts
    - basic stats
    - export a single alert to JSON

---

## 3. Rules: Jaco Ruling Language (JRL)

CTHULHU uses a small, readable rule language called **JRL**.

Example:

```text
reverse_shell_netcat(high)
    | "Netcat reverse shell execution"
    : source == "auditd"
    : success == true
    : exe endswith "/nc" or exe endswith "/ncat"
    : command contains " -e " or command contains "/bin/bash"
```

- Header: `<rule_name>(<severity>)`
- Description line: `| "Human readable description"`
- Conditions: one or more `:` lines (all ANDed)
- Helpers: `contains`, `startswith`, `endswith`
- Literals like `true`, `false`, `null` are normalized internally

Rules are stored in:

```text
/cthulhu/alert.rules
```

Full syntax, all fields, and helper functions are documented here:

> **JRL Guide:**  
> https://github.com/jtsteinbach/cthulhu/blob/main/JRL_GUIDE.md

---

## 4. Configuration

Defaults (in code):

- Alerts file: `ALERT_LOG_PATH = "/cthulhu/alerts.jsonl"`
- Rules file: `RULES_PATH = "/cthulhu/alert.rules"`
- Audit log: `AUDIT_LOG_PATH = "/var/log/audit/audit.log"`

Environment overrides understood by `engine.py`:

```bash
export SIEM_ALERT_LOG_PATH=/path/to/alerts.jsonl
export SIEM_RULES_PATH=/path/to/alert.rules
export SIEM_AUDIT_LOG_PATH=/path/to/audit.log
```

---

## 5. Requirements

- Linux with:
  - `systemd-journald`
  - `auditd` enabled and logging to a file
- Python **3.10+**
- No external Python dependencies (standard library only)
- Sufficient permissions for the engine to read:
  - `/var/log/audit/audit.log`
  - journald via `journalctl`

---

## 6. License

CTHULHU SIEM is licensed under:

> https://r2.jts.gg/license
