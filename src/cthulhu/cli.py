#!/usr/bin/env python3
"""CTHULHU console — triage surface for the alert stream.

v1 offered a numbered menu only. This exposes the same work as direct
subcommands (``cth list``, ``cth triage``) so the console is
scriptable, and keeps the menu for interactive use.

The live feed streams appended alerts instead of clearing and repainting the
whole screen on a 30-second timer, which is what made v1 flicker and lag.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from typing import Any, Dict, Iterable, Iterator, List, Optional

from . import config as config_mod
from . import feeds as feeds_mod
from . import ui
from .jrl import load_rules
from .schema import SEVERITIES, register_fields, severity_rank
from .triage import TriageStore, Verdict, signature_of, suggest_tuning

VERSION = "2.0"

#: True while the interactive console is driving. Hints then point at menu
#: options instead of shell commands the user is not in a position to type.
IN_MENU = False


def hint_for(shell: str, menu: str) -> str:
    """Phrase a hint for whichever way the user got here."""
    return ui.hint(menu if IN_MENU else shell)


# ==========================================================================
# Alert access
# ==========================================================================


class AlertLogProblem(Exception):
    """The alert log could not be read — as opposed to being empty."""


def iter_alerts(path: str) -> Iterator[Dict[str, Any]]:
    if not os.path.exists(path):
        return
    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except PermissionError as exc:
        raise AlertLogProblem(
            f"cannot read {path} — the alert log is root-owned; "
            f"try: sudo cth …") from exc
    except OSError as exc:
        raise AlertLogProblem(f"cannot read {path}: {exc}") from exc
    with handle as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def read_alerts(path: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    alerts = list(iter_alerts(path))
    # Include rotated history when the live file is thin.
    idx = 1
    while (limit is None or len(alerts) < limit) and os.path.exists(f"{path}.{idx}") and idx <= 5:
        alerts = list(iter_alerts(f"{path}.{idx}")) + alerts
        idx += 1
    return alerts


def find_alert(path: str, needle: str) -> Optional[Dict[str, Any]]:
    """Locate an alert by full id, prefix, or trailing short form.

    IDs are time-sortable ULIDs, so alerts created close together share a
    leading prefix; the discriminating characters are at the end. The console
    therefore displays the tail, and lookup accepts either end.
    """
    needle = needle.strip().upper()
    if not needle:
        return None
    matches = [a for a in read_alerts(path)
               if (lambda i: i.startswith(needle) or i.endswith(needle))(
                   str(a.get("alert_id", "")).upper())]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(ui.status("warn", f"{len(matches)} alerts match {needle!r}; "
                                f"use more characters"))
        for alert in matches[:8]:
            print(ui.hint(f"  {alert['alert_id']}  {alert['rule']['name']}"))
    return None


# ==========================================================================
# Rendering
# ==========================================================================

_VERDICT_STYLE = {
    Verdict.OPEN: (ui.P.muted, "open"),
    Verdict.IN_PROGRESS: (ui.P.info, "wip"),
    Verdict.TRUE_POSITIVE: (ui.P.danger, "true-pos"),
    Verdict.BENIGN_POSITIVE: (ui.P.ok, "benign"),
    Verdict.FALSE_POSITIVE: (ui.P.violet, "false-pos"),
    Verdict.DUPLICATE: (ui.P.faint, "dup"),
}


def verdict_cell(verdict: str, inherited: bool = False) -> str:
    color, label = _VERDICT_STYLE.get(verdict, (ui.P.muted, verdict))
    if inherited:
        # Resolved by signature rather than reviewed directly.
        return f"{ui.P.faint}{label}~{ui.P.reset}"
    return f"{color}{label}{ui.P.reset}"


def short_time(alert: Dict[str, Any]) -> str:
    stamp = alert.get("event_time") or alert.get("detected_at") or ""
    return stamp[5:19].replace("T", " ") if len(stamp) >= 19 else stamp


def alert_row(alert: Dict[str, Any], store: TriageStore) -> List[str]:
    sev = alert.get("severity", "info")
    verdict, inherited, _ = store.resolve(alert)
    return [
        f"{ui.severity_dot(sev)} {str(alert.get('alert_id',''))[-8:]}",
        short_time(alert),
        f"{ui.severity_color(sev)}{sev}{ui.P.reset}",
        f"{ui.P.accent}{alert.get('rule',{}).get('name','?')}{ui.P.reset}",
        verdict_cell(verdict, inherited),
        alert.get("summary", ""),
    ]


def print_alert_table(alerts: List[Dict[str, Any]], store: TriageStore) -> None:
    if not alerts:
        print(ui.hint("no alerts match"))
        return
    rows = [alert_row(a, store) for a in alerts]
    print(ui.table(
        ["ID", "TIME", "SEVERITY", "RULE", "STATUS", "SUMMARY"],
        rows,
        max_widths=[11, 14, 8, 32, 9, None],
    ))


def print_feed_line(alert: Dict[str, Any]) -> None:
    sev = alert.get("severity", "info")
    width = ui.term_width()
    print(f"  {ui.severity_dot(sev)} {ui.P.faint}{short_time(alert)}{ui.P.reset} "
          f"{ui.severity_tag(sev)} "
          f"{ui.P.faint}{str(alert.get('alert_id',''))[-8:]}{ui.P.reset} "
          f"{ui.P.accent}{ui.truncate(alert.get('rule',{}).get('name','?'), 30)}{ui.P.reset} "
          f"{ui.P.muted}{ui.truncate(alert.get('summary',''), max(20, width - 76))}{ui.P.reset}",
          flush=True)


def show_alert(alert: Dict[str, Any], store: TriageStore,
               prompt_follows: bool = False) -> None:
    rule = alert.get("rule", {})
    event = alert.get("event", {})
    record = store.get(alert.get("alert_id", ""))
    sev = alert.get("severity", "info")

    print(ui.banner("alert detail", VERSION))
    print(ui.panel("OVERVIEW", [
        ("Alert ID", f"{ui.P.warn}{alert.get('alert_id')}{ui.P.reset}"),
        ("Detected", alert.get("detected_at")),
        ("Event time", alert.get("event_time")),
        ("Severity", f"{ui.severity_color(sev)}{sev.upper()}{ui.P.reset}"),
        ("Status", verdict_cell(record.verdict if record else Verdict.OPEN)),
        ("Rule", f"{ui.P.accent}{rule.get('name')}{ui.P.reset}"),
        ("Description", rule.get("description")),
        ("MITRE", ", ".join(rule.get("mitre", []))),
        ("Tags", ", ".join(rule.get("tags", []))),
        ("Matches", alert.get("match_count")),
    ]))

    print(ui.panel("WHAT HAPPENED", [
        ("Summary", alert.get("summary")),
        ("Source", alert.get("source")),
        ("Host", alert.get("host")),
        ("Category", event.get("category")),
        ("Action", event.get("action")),
        ("Outcome", event.get("outcome")),
    ]))

    process_rows = [
        ("Executable", event.get("exe")),
        ("Command", event.get("cmdline")),
        ("Working dir", event.get("cwd")),
        ("PID / PPID", f"{event.get('pid','-')} / {event.get('ppid','-')}"
                       if event.get("pid") or event.get("ppid") else None),
        ("Parent", event.get("parent_name")),
        ("TTY", event.get("tty")),
        ("Interactive", event.get("interactive")),
    ]
    if any(v for _, v in process_rows):
        print(ui.panel("PROCESS", process_rows))

    identity_rows = [
        ("User", f"{event.get('user') or ''} (uid={event.get('uid','-')})"
                 if event.get("uid") is not None or event.get("user") else None),
        ("Effective", event.get("euid")),
        ("Login uid", event.get("auid")),
        ("Root", event.get("is_root")),
        ("Escalated", event.get("priv_escalated")),
    ]
    if any(v is not None and v != "" for _, v in identity_rows):
        print(ui.panel("IDENTITY", identity_rows))

    file_rows = [
        ("Path", event.get("path")),
        ("Name", event.get("file_name")),
        ("Mode", event.get("mode")),
        ("Owner uid", event.get("owner_uid")),
        ("Nametype", event.get("nametype")),
        ("Setuid", event.get("is_setuid")),
    ]
    if event.get("path"):
        print(ui.panel("FILE", file_rows))

    if event.get("remote_ip"):
        print(ui.panel("NETWORK", [
            ("Remote", f"{event.get('remote_ip')}:{event.get('remote_port','-')}"),
            ("Family", event.get("addr_family")),
        ]))

    if alert.get("source") == "journald" or event.get("message"):
        print(ui.panel("LOG", [
            ("Unit", event.get("unit")),
            ("Service", event.get("service")),
            ("Priority", event.get("priority_label")),
            ("Message", event.get("message")),
        ]))

    if event.get("syscall_name") or event.get("key"):
        print(ui.panel("AUDIT", [
            ("Syscall", f"{event.get('syscall_name','')} ({event.get('syscall','')})"),
            ("Audit key", event.get("key")),
            ("Serial", event.get("serial")),
            ("Exit", event.get("exit_code")),
        ]))

    print(ui.heading("WHY THIS FIRED"))
    print()
    for cond in rule.get("conditions", []):
        print(f"    {ui.P.faint}:{ui.P.reset} {ui.P.text}{cond}{ui.P.reset}")
    print()

    if record:
        print(ui.panel("TRIAGE", [
            ("Verdict", verdict_cell(record.verdict)),
            ("Analyst", record.analyst),
            ("Updated", record.updated_at),
            ("Note", record.note or "—"),
            ("Revisions", len(record.history) or None),
        ]))
    elif not prompt_follows:
        print(hint_for(
            f"not yet triaged — cth triage {alert.get('alert_id','')[-8:]}",
            "not yet triaged — choose 2 from the main menu to record a verdict"))
        print()


# ==========================================================================
# Commands
# ==========================================================================


def cmd_live(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    """Stream alerts that still need a decision.

    Anything already dispositioned — directly, or by matching the signature
    of something dispositioned earlier — is skipped, so the feed stays a
    queue of things to act on rather than a transcript of everything the
    engine has ever emitted. ``--all`` restores the full stream.
    """
    store = TriageStore(cfg.triage_log).load()
    path = cfg.alert_log
    min_rank = severity_rank(args.severity) if args.severity else -1
    show_all = getattr(args, "all", False)

    def triage_mtime() -> float:
        try:
            return os.path.getmtime(cfg.triage_log)
        except OSError:
            return 0.0

    seen_mtime = triage_mtime()

    def wanted(alert: Dict[str, Any]) -> bool:
        if severity_rank(alert.get("severity", "info")) < min_rank:
            return False
        if show_all:
            return True
        verdict, _, _ = store.resolve(alert)
        return verdict not in Verdict.CLOSED

    scope = "all alerts" if show_all else "open alerts only"
    print(ui.banner("alert feed", VERSION))
    print(ui.hint(f"{scope}   ·   {path}"
                  + (f"   ·   severity ≥ {args.severity}" if args.severity else "")))
    print(ui.rule_line())

    if args.tail:
        # Filter first, then take the last N, so a queue of five open alerts
        # is not hidden behind fifty already-closed ones.
        recent = [a for a in read_alerts(path) if wanted(a)][-args.tail:]
        for alert in recent:
            print_feed_line(alert)
        if not recent:
            print(ui.hint("nothing open — waiting for new alerts"))

    if not os.path.exists(path):
        print(ui.status("wait", "alert file does not exist yet — waiting"))

    position = os.path.getsize(path) if os.path.exists(path) else 0
    inode = os.stat(path).st_ino if os.path.exists(path) else None
    ui.hide_cursor()
    try:
        while True:
            # Pick up verdicts recorded from another terminal while watching.
            current = triage_mtime()
            if current != seen_mtime:
                seen_mtime = current
                store.load()

            try:
                stat = os.stat(path)
            except FileNotFoundError:
                time.sleep(1.0)
                continue
            if stat.st_ino != inode or stat.st_size < position:
                position, inode = 0, stat.st_ino  # rotated
            if stat.st_size > position:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(position)
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            alert = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if wanted(alert):
                            print_feed_line(alert)
                    position = fh.tell()
            time.sleep(0.4)
    except KeyboardInterrupt:
        print(f"\n{ui.hint('stopped')}")
    finally:
        ui.show_cursor()
    return 0


def _filter_alerts(alerts: List[Dict[str, Any]], store: TriageStore,
                   args: argparse.Namespace) -> List[Dict[str, Any]]:
    out = alerts
    if getattr(args, "severity", None):
        rank = severity_rank(args.severity)
        out = [a for a in out if severity_rank(a.get("severity", "info")) >= rank]
    if getattr(args, "rule", None):
        needle = args.rule.lower()
        out = [a for a in out if needle in a.get("rule", {}).get("name", "").lower()]
    if getattr(args, "tag", None):
        out = [a for a in out if args.tag in a.get("rule", {}).get("tags", [])]
    if getattr(args, "host", None):
        out = [a for a in out if a.get("host") == args.host]
    status = getattr(args, "status", None)
    if status:
        if status == "open":
            # Alerts resolved by signature are already dealt with and do not
            # belong in the review queue.
            out = [a for a in out if store.resolve(a)[0] not in Verdict.CLOSED]
        elif status == "inherited":
            out = [a for a in out if store.resolve(a)[1]]
        else:
            wanted = Verdict.normalize(status)
            out = [a for a in out if store.resolve(a)[0] == wanted]
    if getattr(args, "grep", None):
        needle = args.grep.lower()
        out = [a for a in out if needle in json.dumps(a).lower()]
    return out


def cmd_list(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    store = TriageStore(cfg.triage_log).load()
    alerts = _filter_alerts(read_alerts(cfg.alert_log), store, args)
    alerts = alerts[-args.limit:] if args.limit else alerts
    alerts.reverse()

    print(ui.banner("alerts", VERSION))
    if args.json:
        for alert in alerts:
            print(json.dumps(alert, separators=(",", ":")))
        return 0
    print_alert_table(alerts, store)
    print()
    print(hint_for(
        f"{len(alerts)} shown   ·   cth triage <id>   to review and decide",
        f"{len(alerts)} shown   ·   choose 2 to triage an alert"))
    print()
    return 0


def _prompt_verdict(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Ask for a verdict, note, and scope. None means the user backed out."""
    print(ui.heading("VERDICT"))
    print()
    print(f"    {ui.P.danger}tp{ui.P.reset}   true positive     "
          f"{ui.P.faint}real, unwanted activity{ui.P.reset}")
    print(f"    {ui.P.ok}bp{ui.P.reset}   benign positive   "
          f"{ui.P.faint}detection correct, activity authorized{ui.P.reset}")
    print(f"    {ui.P.violet}fp{ui.P.reset}   false positive    "
          f"{ui.P.faint}rule matched the wrong thing{ui.P.reset}")
    print(f"    {ui.P.info}wip{ui.P.reset}  in progress       "
          f"{ui.P.faint}investigating{ui.P.reset}")
    print(f"    {ui.P.muted}dup{ui.P.reset}  duplicate         "
          f"{ui.P.faint}same activity as another alert{ui.P.reset}")
    print()
    print(ui.hint("leave blank to return without deciding"))
    print()
    try:
        raw = input(f"  {ui.P.accent}verdict ›{ui.P.reset} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not raw:
        return None
    if Verdict.normalize(raw) is None:
        print(ui.status("err", f"unknown verdict {raw!r}"))
        return None
    try:
        note = input(f"  {ui.P.accent}note (optional) ›{ui.P.reset} ").strip()
        scope = input(f"  {ui.P.accent}apply to every alert with this "
                      f"signature? [Y/n] ›{ui.P.reset} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return {"verdict": raw, "message": note, "similar": scope != "n"}


def cmd_triage(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    """Review an alert and record a verdict.

    With no verdict argument this shows the full alert and prompts, which is
    the only way to inspect an alert — looking at one and deciding about it
    are the same activity, so they are the same screen.
    """
    store = TriageStore(cfg.triage_log).load()

    alert = find_alert(cfg.alert_log, args.alert_id)
    if alert is None:
        print(ui.status("err", f"no alert matching {args.alert_id!r}"))
        return 1

    raw_verdict = getattr(args, "verdict", None)
    similar = getattr(args, "similar", False)
    message = getattr(args, "message", "") or ""

    if not raw_verdict:
        show_alert(alert, store, prompt_follows=True)
        answer = _prompt_verdict(alert)
        if answer is None:
            print(ui.hint("no verdict recorded"))
            print()
            return 0
        raw_verdict = answer["verdict"]
        message = answer["message"]
        similar = answer["similar"]
        ui.clear()

    verdict = Verdict.normalize(raw_verdict)
    if verdict is None:
        print(ui.status("err", f"unknown verdict {raw_verdict!r}"))
        print(ui.hint("true-positive (tp) · benign-positive (bp) · "
                      "false-positive (fp) · wip · dup · open"))
        return 1

    rule_name = alert.get("rule", {}).get("name", "")
    signature = signature_of(alert)
    targets = [alert]

    if similar or getattr(args, "rule_wide", False):
        everything = read_alerts(cfg.alert_log)
        if getattr(args, "rule_wide", False):
            scope_desc = f"{rule_name!r}"
            targets = [a for a in everything
                       if a.get("rule", {}).get("name") == rule_name]
        else:
            # Signature scope is the precise one: same rule *and* materially
            # the same event, so the verdict genuinely transfers.
            scope_desc = "matching signature"
            targets = [a for a in everything if signature_of(a) == signature]
        targets = [a for a in targets
                   if a.get("alert_id") == alert.get("alert_id")
                   or store.verdict_of(a.get("alert_id", "")) not in Verdict.CLOSED]
        print(ui.status("info", f"applying to {len(targets)} alert(s) — {scope_desc}"))

    for target in targets:
        store.set_verdict(target["alert_id"], verdict, message,
                          getattr(args, "analyst", None), rule_name,
                          signature_of(target))

    print()
    print(ui.status("ok", f"{len(targets)} alert(s) marked "
                          f"{verdict_cell(verdict)}"
                          + (f"  {ui.P.muted}\u201c{message}\u201d{ui.P.reset}"
                             if message else "")))
    if verdict in Verdict.CLOSED:
        print(ui.hint(f"signature {signature} — later occurrences of this "
                      f"activity will be recognized"))

    if verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_POSITIVE,
                   Verdict.TRUE_POSITIVE) and not getattr(args, "quiet", False):
        print()
        print(ui.heading("SUGGESTED TUNING", f"edit {cfg.rules_path}"))
        print()
        for line in suggest_tuning(alert, verdict):
            style = ui.P.faint if line.startswith("#") else ui.P.text
            print(f"  {style}{line}{ui.P.reset}")
        print()
        print(hint_for(
            "validate with: cth check    ·    apply with: systemctl reload cthulhu",
            "edit the ruleset, then reload with: systemctl reload cthulhu"))
    print()
    return 0


def cmd_stats(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    store = TriageStore(cfg.triage_log).load()
    alerts = read_alerts(cfg.alert_log)

    print(ui.banner("statistics", VERSION))
    if not alerts:
        print(ui.hint("no alerts recorded yet"))
        return 0

    by_sev = Counter(a.get("severity", "info") for a in alerts)
    by_rule = Counter(a.get("rule", {}).get("name", "?") for a in alerts)
    verdicts = store.counts()
    open_count = len(alerts) - sum(verdicts[v] for v in Verdict.CLOSED)

    print(ui.heading("VOLUME", f"{len(alerts)} alerts"))
    print()
    rows = [[f"{ui.severity_color(s)}{s}{ui.P.reset}", by_sev.get(s, 0),
             _bar(by_sev.get(s, 0), max(by_sev.values()), ui.severity_color(s))]
            for s in reversed(SEVERITIES) if by_sev.get(s)]
    print(ui.table(["SEVERITY", "COUNT", ""], rows, aligns=["left", "right", "left"]))
    print()

    print(ui.heading("TRIAGE", f"{open_count} awaiting review"))
    print()
    vrows = [[verdict_cell(v), verdicts.get(v, 0)]
             for v in Verdict.ALL if verdicts.get(v)]
    vrows.append([f"{ui.P.muted}untriaged{ui.P.reset}", open_count])
    print(ui.table(["STATUS", "COUNT"], vrows, aligns=["left", "right"]))
    print()

    # Rule precision: the payoff of triaging consistently.
    per_rule = store.counts_by_rule()
    scored = []
    for name, counts in per_rule.items():
        tp = counts.get(Verdict.TRUE_POSITIVE, 0)
        bp = counts.get(Verdict.BENIGN_POSITIVE, 0)
        fp = counts.get(Verdict.FALSE_POSITIVE, 0)
        judged = tp + bp + fp
        if judged < 1:
            continue
        precision = (tp + bp) / judged
        scored.append((precision, name, tp, bp, fp, by_rule.get(name, 0)))
    if scored:
        scored.sort()
        print(ui.heading("RULE PRECISION", "lowest first — tune these"))
        print()
        print(ui.table(
            ["RULE", "FIRED", "TRUE", "BENIGN", "FALSE", "PRECISION"],
            [[f"{ui.P.accent}{n}{ui.P.reset}", total, tp, bp, fp,
              f"{_precision_color(p)}{p*100:.0f}%{ui.P.reset}"]
             for p, n, tp, bp, fp, total in scored[:12]],
            aligns=["left", "right", "right", "right", "right", "right"]))
        print()

    print(ui.heading("TOP RULES"))
    print()
    top = by_rule.most_common(args.limit)
    peak = top[0][1] if top else 1
    print(ui.table(
        ["RULE", "COUNT", ""],
        [[f"{ui.P.accent}{n}{ui.P.reset}", c, _bar(c, peak, ui.P.accent_dim)]
         for n, c in top],
        aligns=["left", "right", "left"]))
    print()
    return 0


def _precision_color(value: float) -> str:
    if value >= 0.8:
        return ui.P.ok
    if value >= 0.5:
        return ui.P.warn
    return ui.P.danger


def _bar(value: int, peak: int, color: str, width: int = 24) -> str:
    if peak <= 0:
        return ""
    filled = max(1, round(value / peak * width)) if value else 0
    return f"{color}{'█' * filled}{ui.P.reset}"


def cmd_rules(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    _prepare_feeds(cfg)
    try:
        ruleset = load_rules(cfg.rules_path)
    except FileNotFoundError:
        print(ui.status("err", f"rules file not found: {cfg.rules_path}"))
        return 1

    print(ui.banner("ruleset", VERSION))
    rules = ruleset.rules
    if args.tag:
        rules = [r for r in rules if args.tag in r.tags]
    if args.severity:
        rank = severity_rank(args.severity)
        rules = [r for r in rules if severity_rank(r.severity) >= rank]
    if args.search:
        needle = args.search.lower()
        rules = [r for r in rules
                 if needle in r.name.lower() or needle in r.description.lower()
                 or any(needle in t for t in r.tags)]

    rules.sort(key=lambda r: (-severity_rank(r.severity), r.name))
    print(ui.table(
        ["", "RULE", "FEED", "MITRE", "DESCRIPTION"],
        [[ui.severity_dot(r.severity),
          f"{ui.P.accent}{r.name}{ui.P.reset}",
          f"{ui.P.muted}{','.join(r.feeds) or '*'}{ui.P.reset}",
          f"{ui.P.faint}{','.join(r.mitre[:2])}{ui.P.reset}",
          r.description] for r in rules],
        max_widths=[2, 38, 10, 18, None]))
    print()
    counts = ruleset.by_severity()
    print(ui.hint(f"{len(rules)} shown of {len(ruleset)}   ·   " + "  ".join(
        f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts.get(s))))
    for warning in ruleset.warnings:
        print(ui.status("warn", warning))
    for error in ruleset.errors:
        print(ui.status("err", error))
    print()
    return 0


def cmd_feeds(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    _prepare_feeds(cfg)
    print(ui.banner("feeds", VERSION))
    try:
        ruleset = load_rules(cfg.rules_path)
        per_feed = Counter()
        for rule in ruleset.rules:
            for name in (rule.feeds or ("*",)):
                per_feed[name] += 1
    except Exception:
        per_feed = Counter()

    print(ui.table(
        ["FEED", "RULES", "FIELDS", "DESCRIPTION"],
        [[f"{ui.P.accent}{f.name}{ui.P.reset}", per_feed.get(f.name, 0),
          len(f.fields), f.description]
         for f in feeds_mod.all_feeds()],
        aligns=["left", "right", "right", "left"]))
    print()
    print(ui.hint(f"add a feed by dropping a JSON descriptor in {cfg.feeds_dir}"))
    print()
    return 0


def cmd_export(cfg: config_mod.Config, args: argparse.Namespace) -> int:
    store = TriageStore(cfg.triage_log).load()
    alerts = _filter_alerts(read_alerts(cfg.alert_log), store, args)
    for alert in alerts:
        alert["triage"] = (store.get(alert.get("alert_id", "")) or None)
        if alert["triage"]:
            alert["triage"] = alert["triage"].to_json()
    payload = json.dumps(alerts, indent=2, default=str)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(ui.status("ok", f"{len(alerts)} alerts written to {args.output}"))
    else:
        print(payload)
    return 0


def _prepare_feeds(cfg: config_mod.Config) -> None:
    feeds_mod.load_descriptors(cfg.feeds_dir)
    for feed in feeds_mod.all_feeds():
        register_fields(feed.fields)


# ==========================================================================
# Interactive menu
# ==========================================================================

_MENU = [
    ("1", "Alert feed", "stream open alerts as they arrive"),
    ("2", "Triage", "full detail, then record a verdict"),
    ("3", "All alerts", "full history, every verdict"),
    ("4", "Statistics", "volume, verdicts, rule precision"),
    ("5", "Loaded rules", "active detection rules"),
    ("6", "Data feeds", "configured event sources"),
    ("q", "Quit", ""),
]


def menu(cfg: config_mod.Config) -> int:
    # Hints inside the console must point at menu options, not at shell
    # commands the user is not in a position to type.
    global IN_MENU
    IN_MENU = True
    store = TriageStore(cfg.triage_log)
    while True:
        ui.clear()
        print(ui.banner("console", VERSION))
        store.load()
        alerts = read_alerts(cfg.alert_log)
        open_alerts = [a for a in alerts
                       if store.verdict_of(a.get("alert_id", "")) not in Verdict.CLOSED]
        critical = sum(1 for a in open_alerts
                       if a.get("severity") in ("critical", "high"))
        print(ui.hint(f"{len(alerts)} alerts   ·   {len(open_alerts)} open   ·   "
                      f"{critical} high or critical unreviewed"))
        print()
        for key, label, blurb in _MENU:
            print(f"  {ui.P.accent}{key}{ui.P.reset}  {ui.P.text}{ui.pad(label, 16)}"
                  f"{ui.P.reset}{ui.P.faint}{blurb}{ui.P.reset}")
        print()
        try:
            choice = input(f"  {ui.P.accent}›{ui.P.reset} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        ns = argparse.Namespace(
            severity=None, rule=None, tag=None, host=None, status=None,
            grep=None, limit=50, json=False, search=None, output=None)

        if choice == "1":
            cmd_live(cfg, argparse.Namespace(severity=None, tail=20, all=False))
        elif choice == "2":
            _review_alert(cfg)
        elif choice == "3":
            ui.clear()
            cmd_list(cfg, ns)
            _pause()
        elif choice == "4":
            ui.clear()
            cmd_stats(cfg, argparse.Namespace(limit=12))
            _pause()
        elif choice == "5":
            ui.clear()
            cmd_rules(cfg, argparse.Namespace(tag=None, severity=None, search=None))
            _pause()
        elif choice == "6":
            ui.clear()
            cmd_feeds(cfg, ns)
            _pause()
        elif choice in ("q", "quit", "exit"):
            return 0


def _review_alert(cfg: config_mod.Config) -> None:
    """Prompt for an alert id, then hand off to the single review screen."""
    try:
        alert_id = input(f"  {ui.P.accent}alert id ›{ui.P.reset} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not alert_id:
        return
    ui.clear()
    cmd_triage(cfg, argparse.Namespace(
        alert_id=alert_id, verdict=None, message="", analyst=None,
        similar=False, rule_wide=False, quiet=False))
    _pause()


def _pause() -> None:
    try:
        input(ui.hint("press enter to return "))
    except (EOFError, KeyboardInterrupt):
        pass


# ==========================================================================
# Entry point
# ==========================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cth", description="CTHULHU SIEM console",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="run without arguments for the interactive console")
    parser.add_argument("--version", action="version", version=f"cthulhu {VERSION}")
    sub = parser.add_subparsers(dest="command")

    live = sub.add_parser("live", help="stream open alerts as they arrive")
    live.add_argument("-s", "--severity", choices=SEVERITIES)
    live.add_argument("-n", "--tail", type=int, default=15)
    live.add_argument("-a", "--all", action="store_true",
                      help="include alerts that already have a verdict")

    def add_filters(p: argparse.ArgumentParser) -> None:
        p.add_argument("-s", "--severity", choices=SEVERITIES)
        p.add_argument("-r", "--rule")
        p.add_argument("-t", "--tag")
        p.add_argument("-H", "--host")
        p.add_argument("--status", help="open, tp, bp, fp, wip, dup")
        p.add_argument("-g", "--grep")

    listing = sub.add_parser("list", help="browse alerts")
    add_filters(listing)
    listing.add_argument("-n", "--limit", type=int, default=50)
    listing.add_argument("--json", action="store_true")

    triage = sub.add_parser(
        "triage", help="review an alert and record a verdict")
    triage.add_argument("alert_id")
    triage.add_argument("verdict", nargs="?", default=None,
                        help="tp | bp | fp | wip | dup | open; "
                             "omit to review the alert and be prompted")
    triage.add_argument("-m", "--message", default="", help="analyst note")
    triage.add_argument("-a", "--analyst", default=None)
    triage.add_argument("--similar", action="store_true",
                        help="apply to every alert sharing this signature")
    triage.add_argument("--rule-wide", dest="rule_wide", action="store_true",
                        help="apply to all untriaged alerts from the same rule")
    triage.add_argument("-q", "--quiet", action="store_true",
                        help="skip the tuning suggestion")

    stats = sub.add_parser("stats", help="volume, verdicts and rule precision")
    stats.add_argument("-n", "--limit", type=int, default=15)

    rules = sub.add_parser("rules", help="list detection rules")
    rules.add_argument("-t", "--tag")
    rules.add_argument("-s", "--severity", choices=SEVERITIES)
    rules.add_argument("search", nargs="?")

    sub.add_parser("feeds", help="list configured data sources")
    sub.add_parser("check", help="validate the ruleset")

    export = sub.add_parser("export", help="export alerts as JSON")
    add_filters(export)
    export.add_argument("-o", "--output")
    export.add_argument("-n", "--limit", type=int, default=0)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = config_mod.load()

    handlers = {
        "live": cmd_live, "list": cmd_list,
        "triage": cmd_triage, "stats": cmd_stats, "rules": cmd_rules,
        "feeds": cmd_feeds, "export": cmd_export,
    }
    if args.command == "check":
        from .engine import check_rules
        return check_rules(cfg)
    if args.command in handlers:
        try:
            return handlers[args.command](cfg, args)
        except BrokenPipeError:
            return 0
        except KeyboardInterrupt:
            print()
            return 130
    return menu(cfg)


if __name__ == "__main__":
    sys.exit(main())
