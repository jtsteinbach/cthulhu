# JRL — Jaco Rule Language, v2

The detection language used by CTHULHU. Designed so that a working rule reads
like a sentence, and so that a mistake is caught at load time instead of
becoming a rule that silently never fires.

Validate any change before deploying:

```bash
cth check                       # parse, validate fields, report problems
systemctl reload cthulhu        # apply without dropping the event stream
```

---

## 1. Anatomy of a rule

```text
reverse_shell_netcat(critical)
    | "Netcat invoked with command execution — classic reverse shell"
    ~ on: auditd
    ~ mitre: T1059.004
    ~ tags: execution, reverse_shell
    : category == "process"
    : exe_name in ["nc", "ncat", "netcat"]
    : cmdline matches "(^|\s)-[a-zA-Z]*e(\s|$)"
```

| Line | Prefix | Meaning |
|------|--------|---------|
| header | — | `name(severity)` |
| description | `\|` | one quoted sentence, shown in the console |
| directive | `~` | metadata and behaviour (`on`, `tags`, `threshold`, …) |
| condition | `:` | a test; **all conditions must be true** |

Severities, lowest to highest: `info`, `low`, `medium`, `high`, `critical`.

Blank lines separate rules. `#` starts a comment anywhere outside a string.

---

## 2. Conditions

### Comparison

```text
: uid == 0
: http_status >= 400
: exe_name != "sudo"
```

Numbers and numeric strings compare correctly, so `priority <= 3` works even
though journald delivers priority as text.

### Membership — prefer this over long `or` chains

```text
: exe_name in ["nc", "ncat", "netcat"]
: remote_port not in [22, 443]
```

### String tests

| Operator | Negated | Case-insensitive |
|----------|---------|------------------|
| `contains` | `not contains` / `!contains` | `icontains` |
| `startswith` | `not startswith` / `!startswith` | `istartswith` |
| `endswith` | `not endswith` / `!endswith` | `iendswith` |
| `matches` (regex) | `not matches` / `!matches` | `imatches` |

Any string operator accepts a **list**, meaning *any of*:

```text
: cmdline contains ["/dev/tcp/", "/dev/udp/"]
: path startswith ["/tmp/", "/var/tmp/", "/dev/shm/"]
```

Regexes are Python syntax, compiled once at load. An invalid regex is a load
error, not a silent failure.

### Presence

```text
: tty is null
: key is not null
```

### Boolean logic

`and`, `or`, `not`, and parentheses. `and` binds tighter than `or`, so
parenthesise anything ambiguous:

```text
: (exe_name == "bash" or exe_name == "sh") and uid == 0
```

### Wrapping long conditions

A condition continues onto the next line while brackets are open, when the
next line starts with `and`/`or`, or when the current line ends on an
operator:

```text
: path startswith ["/etc/cron.d/", "/etc/cron.daily/"]
  or path == "/etc/crontab"
```

---

## 3. Null semantics

A field an event does not carry is **null**. Referencing it is never an
error, so an auditd rule simply does not match a journald event.

* **Positive tests are fail-closed.** `==`, `!=`, `<`, `>`, `contains`,
  `startswith`, `matches`, `in` are all *false* against null. A rule can
  never fire on data that is not there.
* **Negated exclusions are fail-open.** `not contains`, `not in`,
  `not startswith`, `not matches` are *true* against null. This is what makes
  tuning safe: `parent_name not in $trusted_automation` must not discard an
  event merely because the parent could not be resolved.

Use `is null` / `is not null` when you need to test presence explicitly.

---

## 4. Named lists (`@list`)

Declare a list once, reference it as `$name` anywhere below. This is the
intended tuning mechanism — edit the list, retune every rule that uses it.

```text
@list shells = ["bash", "sh", "dash", "zsh"]
@list pkg    = ["apt", "dpkg", "yum", "dnf"]
@list noise  = [$pkg, "ansible-playbook", "puppet"]     # lists splice

my_rule(high)
    | "Shell spawned outside package management"
    : exe_name in $shells
    : parent_name not in $noise
```

Lists may span lines, and work as multi-needle operands:

```text
: cmdline contains $miner_markers
```

---

## 5. Directives

| Directive | Example | Purpose |
|-----------|---------|---------|
| `on` | `~ on: auditd` | which feed(s) this rule applies to |
| `tags` | `~ tags: execution, c2` | free-form labels, filterable in the console |
| `mitre` | `~ mitre: T1059.004` | ATT&CK technique IDs |
| `ref` | `~ ref: https://…` | supporting link |
| `threshold` | `~ threshold: 8 in 120s by remote_ip` | fire only on repetition |
| `throttle` | `~ throttle: 5m` | suppress repeats of the same alert |
| `dedup` | `~ dedup: uid, exe` | which fields define "the same alert" |
| `enabled` | `~ enabled: false` | keep a rule in the file but inactive |

### `on:` — targeting feeds

```text
~ on: auditd
~ on: journald, nginx
```

This replaces writing `: source == "auditd"` as a condition. It also lets the
engine bucket rules per feed, so an event is only tested against rules that
could match it. Omit it and the rule is evaluated against every feed.

### `threshold:` — correlation

```text
~ threshold: <count> in <window> by <field>[, <field>]
~ threshold: 8 in 120s by remote_ip
```

The rule matches individually, but only raises an alert once `count` matches
share the same `by` values inside `window`. The alert carries
`match_count` and the correlated events. Without a `by` clause the count is
global to the rule.

Durations: `30s`, `5m`, `1h`, `1d` (a bare number means seconds).

### `throttle:` and `dedup:` — volume control

```text
~ throttle: 10m
~ dedup: exe, remote_ip
```

After firing, further alerts with the same `dedup` values are suppressed for
the throttle window. Defaults to `host, uid, exe, path, remote_ip`.
Suppressed matches are counted in `cth stats` and never silently lost.

---

## 6. Fields

Full list: `cth rules` shows what each rule uses; the schema lives in
`src/cthulhu/schema.py`. A rule referencing a field outside the schema
produces a **load-time warning**, because such a rule can never match.

### Core — every feed

`source` `timestamp` `epoch` `host` `category` `action` `outcome` `success`

`category` is one of: `process`, `file`, `network`, `auth`, `privilege`,
`service`, `kernel`, `module`, `audit`, `log`, `other`.

### Process

`exe` `exe_name` `exe_dir` `comm` `cmdline` `argv` `argc` `cwd` `pid` `ppid`
`parent_exe` `parent_name` `tty` `session` `interactive` `is_script`
`interpreter`

> `cmdline` is the **full** command line, reconstructed from the auditd
> `EXECVE` argv vector (or a hex-decoded `PROCTITLE`). `comm` is the kernel's
> name for the process and is truncated to 15 characters with no arguments —
> match on `cmdline`, not `comm`.

### Identity

`uid` `euid` `suid` `fsuid` `auid` `gid` `egid` `user` `euser` `auser`
`is_root` `is_system_user` `priv_escalated` `auid_set`

> `auid` is the login uid: it survives `su`/`sudo` and identifies the human
> behind an action. `auid_set` is false for daemons started at boot.

### File

`path` `paths` `file_name` `file_ext` `file_dir` `mode` `owner_uid`
`owner_gid` `is_setuid` `is_setgid` `nametype` `is_write` `open_flags`

> `is_write` distinguishes a read from a modification — auditd labels both as
> file events. Gate modification rules on
> `is_write == true or nametype in ["CREATE", "DELETE"]`.

### Network

`remote_ip` `remote_port` `local_ip` `local_port` `addr_family` `socket_path`

### Audit

`syscall` `syscall_name` `key` `keys` `serial` `event_id` `arch` `exit_code`
`record_types` `proctitle`

### Journald

`message` `message_snippet` `unit` `service` `syslog_id` `priority`
`priority_label` `facility` `is_error` `is_warning` `boot_id` `machine_id`

### Auth (both feeds)

`auth_user` `auth_method` `auth_result` `sudo_command` `sudo_target_user`

### Aliases

Several older field names still resolve, so existing rules keep working:
`command_line`→`cmdline`, `process_name`→`exe_name`, `filepath`→`path`,
`exe_basename`→`exe_name`, `log_message`→`message`, and others. New rules
should use the canonical names on the left of each pair above.

---

## 7. Adding a new feed

Drop a JSON descriptor in `/cthulhu/feeds.d/`. Named regex groups (or JSON
keys) become rule fields automatically.

```json
{
  "name": "nginx",
  "paths": ["/var/log/nginx/access.log"],
  "format": "regex",
  "category": "web",
  "pattern": "^(?P<remote_ip>\\S+) .* \"(?P<http_method>[A-Z]+) (?P<http_path>[^ ]*)[^\"]*\" (?P<http_status>\\d{3})",
  "types": { "http_status": "int" }
}
```

```bash
cth feeds     # confirm registration
cth check     # confirm rules validate against its fields
```

Then write rules against it:

```text
web_path_traversal(high)
    | "Path traversal attempt against the web server"
    ~ on: nginx
    ~ threshold: 3 in 60s by remote_ip
    : http_path contains ["../", "..%2f"]
```

See `feeds.d/README.md` for every descriptor key.

---

## 8. Writing rules that stay quiet

The difference between a SIEM people use and one they mute:

1. **Match on behaviour, not names.** `cmdline matches "-e\s+/bin/sh"` beats
   `exe_name == "nc"`.
2. **Exclude the automation, not the technique.** Add the noisy parent to
   `$trusted_automation` rather than weakening the detection.
3. **Gate file rules on writes.** `is_write == true` removes a whole class of
   false positives from read access.
4. **Use `auid_set == true`** to focus on human-initiated activity.
5. **Threshold anything repetitive** — brute force, scans, recon bursts.
6. **Throttle anything chatty** so one loop cannot bury the console.
7. **Let triage drive tuning.** `cth triage <id> fp` prints the exclusion to
   add; `cth stats` ranks rules by precision so you know which to fix first.

---

## 9. Error reference

| Message | Cause |
|---------|-------|
| `references unknown field(s): X` | typo, or a field that feed does not emit |
| `undefined list $X` | `@list X = [...]` missing or declared after use |
| `expected 'in', got '...'` | `not` used with an unsupported operator |
| `invalid regex` | malformed pattern in `matches` |
| `invalid threshold` | expected `<count> in <window> by <field>` |
| `unknown severity` | not one of the five severity names |
| `rule has no conditions` | header and description with no `:` lines |
| `targets unknown feed` | `~ on:` names a feed that is not registered |

A rule that fails to parse is reported and skipped; the rest of the file
still loads. The engine refuses to start only if *no* rules are usable.
