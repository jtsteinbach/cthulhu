# 📘 CTHULHU SIEM — **JRL (Jaco Ruling Language) Complete Specification**

This document defines the **JRL Rule Language**, used to match normalized
auditd/journald events and generate alerts.

---

# 🧩 1. Rule Structure

A rule has **four parts**:

```
rule_name(severity)
    | "Human readable description"
    : condition1
    : condition2
    : condition3
```

### Required elements
- `rule_name` — identifier `[A-Za-z_][A-Za-z0-9_]*`
- `(severity)` — any string (typical: low, medium, high)
- `"description"` — displayed in UI and alerts
- One or more `:` conditions (logical AND)

---

# 🧱 2. Available Event Fields

You reference normalized **event fields only**, not nested dictionaries.

## 2.1 auditd Event Fields

| Field | Type | Meaning |
|-------|------|---------|
| source | "auditd" | Always `"auditd"` |
| timestamp | str | ISO8601 |
| epoch | float | UNIX timestamp |
| event_id | int | Audit serial |
| serial | int | Audit serial |
| syscall | str or None |
| success | bool |
| exe | str or None |
| command | str or None |
| cwd | str or None |
| tty | str or None |
| uid/euid/auid/gid | int or None |
| pid/ppid | int or None |
| session | int or None |
| host | str or None |
| filepath | str or None |
| filepaths | list[str] |
| raw | str |
| records | list |
| category | str |

## 2.2 journald Event Fields

| Field | Type | Meaning |
|-------|------|---------|
| source | "journald" |
| timestamp | str or None |
| epoch | float or None |
| host | str or None |
| message | str |
| priority | int or None |
| facility | int or None |
| unit | str or None |
| process_id | int or None |
| process_name | str or None |
| category | str |
| fields | dict |
| raw | dict |

---

# 🧠 3. Condition Syntax (JRL Operators)

## 3.1 Literals
```
true  → True
false → False
null  → None
```

## 3.2 Comparisons
```
uid == 0
exe != "/usr/bin/bash"
priority < 3
pid >= 1000
```

## 3.3 Logical Operators
```
and
or
not
(...)
```

## 3.4 Null tests
```
exe is null
exe is not null
```

## 3.5 String Operators (infix)
```
message contains "failed password"
unit startswith "ssh"
filepath endswith ".conf"
```

These map to:
```
_contains()
_startswith()
_endswith()
```

---

# 🧮 4. Condition Evaluation Model

Every `:` line is ANDed.

```
: a == 1
: b == 2
```

becomes:

```
(a == 1) and (b == 2)
```

---

# 🔐 5. Grammar (EBNF)

```
rule        = name "(" severity ")" newline
              "|" description newline
              { ":" condition newline }

condition   = expression
expression  = logical_or

logical_or  = logical_and { "or" logical_and }
logical_and = unary { "and" unary }
unary       = ["not"] comparison

comparison  = value ( comp_op value
                    | "is" ["not"] "null"
                    | string_op value )

string_op   = "contains" | "startswith" | "endswith"
```

---

# 📌 6. Identifier Mapping

Any identifier evaluates as:

```
event[identifier]
```

No nested fields allowed.

---

# 🔥 7. Examples

## Root Shell
```
root_shell(high)
    | "Root interactive shell spawned"
    : source == "auditd"
    : uid == 0
    : tty is not null
```

## SSH failure
```
ssh_fail(medium)
    | "SSH authentication failed"
    : source == "journald"
    : message contains "Failed password"
```

## Sensitive file modification
```
mod_sensitive_file(high)
    | "Sensitive file modified"
    : source == "auditd"
    : filepath endswith ".conf"
```

---

# 🛑 8. Rule Error Behavior

- Safe eval
- No builtins
- Exceptions are swallowed
- Rule simply does not match

---

# 📦 9. Quick Reference

```
true false null
== != < > <= >=
and or not
is null / is not null
contains / startswith / endswith
(...)
```
