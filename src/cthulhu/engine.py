#!/usr/bin/env python3
"""CTHULHU engine — collects, normalizes, evaluates, alerts.

Reliability fixes over v1:

* **Log rotation is handled.** v1 held one file descriptor forever, so the
  first ``logrotate`` run on ``audit.log`` left the engine reading a deleted
  inode — silently blind until restart. The tailer here re-opens on inode or
  truncation change.
* **SIGTERM is handled**, so ``systemctl stop`` shuts down cleanly instead of
  being killed; **SIGHUP reloads rules** without dropping the event stream.
* **Threads are supervised.** v1's main loop exited as soon as every worker
  died, with no message; workers now restart with backoff.
* Rule evaluation is bucketed by ``source`` so an event is only tested against
  rules that could plausibly match it.
"""

from __future__ import annotations

import errno
import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

from . import config as config_mod
from . import feeds
from . import ui
from .alerts import AlertBuilder, AlertWriter, Suppressor
from .jrl import Rule, RuleSet, load_rules
from .normalize import ParentResolver, apply_aliases
from .schema import register_fields
from .triage import TriageStore, Verdict

VERSION = "2.0"


# ==========================================================================
# Rotation-aware file tailer
# ==========================================================================


def follow_file(path: str, stop: threading.Event,
                read_existing: bool = False,
                poll: float = 0.25) -> Iterator[Optional[str]]:
    """Yield lines from a growing file, surviving rotation and truncation.

    Yields ``None`` when idle, which lets the audit assembler flush a
    partially-collected event instead of holding it until the next record.
    """
    handle = None
    inode = None
    partial = ""

    def open_file():
        nonlocal handle, inode, partial
        try:
            new = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return False
        stat = os.fstat(new.fileno())
        if not read_existing and handle is None:
            new.seek(0, os.SEEK_END)
        if handle is not None:
            handle.close()
        handle = new
        inode = (stat.st_ino, stat.st_dev)
        partial = ""
        return True

    while not stop.is_set():
        if handle is None:
            if not open_file():
                yield None
                if stop.wait(2.0):
                    break
                continue

        assert handle is not None
        chunk = handle.readline()
        if chunk:
            if not chunk.endswith("\n"):
                # Partial write; hold it until the rest arrives.
                partial += chunk
                continue
            if partial:
                chunk = partial + chunk
                partial = ""
            yield chunk.rstrip("\n")
            continue

        # Nothing new — check whether the file moved out from under us.
        try:
            disk = os.stat(path)
            rotated = (disk.st_ino, disk.st_dev) != inode
            # Truncation (logrotate's copytruncate) keeps the same inode and
            # resets the size, so compare against our read position rather
            # than against the file's own size — both would read as zero.
            truncated = disk.st_size < handle.tell()
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ESTALE):
                raise
            rotated, truncated = True, False

        if rotated or truncated:
            # Drain whatever remains in the old handle first.
            while True:
                leftover = handle.readline()
                if not leftover:
                    break
                yield leftover.rstrip("\n")
            handle.close()
            handle = None
            # Whether rotated or truncated, the replacement content is new
            # and must be read from its start.
            read_existing = True
            continue

        yield None
        if stop.wait(poll):
            break

    if handle is not None:
        handle.close()


# ==========================================================================
# Engine
# ==========================================================================


class Engine:
    def __init__(self, cfg: config_mod.Config) -> None:
        self.cfg = cfg
        self.stop = threading.Event()
        self.reload_requested = threading.Event()
        self.rules: RuleSet = RuleSet()
        self.by_source: Dict[str, List[Rule]] = {"auditd": [], "journald": [], "any": []}
        self._rules_lock = threading.RLock()
        self.writer = AlertWriter(cfg.alert_log, cfg.max_alert_bytes, cfg.alert_backups)
        self.triage = TriageStore(cfg.triage_log)
        self.builder = AlertBuilder(
            self.writer, Suppressor(cfg.default_throttle), cfg.min_severity,
            known_signatures=self._known_signatures(),
            suppress_known=cfg.suppress_known)
        self.parents = ParentResolver()
        self.started = time.time()
        self.event_count = 0
        self._count_lock = threading.Lock()

    def _known_signatures(self) -> Dict[str, str]:
        """Signatures an analyst has already closed, for recognizing repeats."""
        try:
            return self.triage.load().known_signatures(Verdict.CLOSED)
        except OSError:
            return {}

    # -- rules ----------------------------------------------------------
    def load(self) -> RuleSet:
        ruleset = load_rules(self.cfg.rules_path)
        buckets: Dict[str, List[Rule]] = {"*": []}
        registered = feeds.feed_names()
        for rule in ruleset.rules:
            targets = self._targets_for(rule)
            if not targets:
                buckets["*"].append(rule)
                continue
            for name in targets:
                if name not in registered:
                    ruleset.warnings.append(
                        f"{self.cfg.rules_path}:{rule.line_no}: rule "
                        f"{rule.name!r} targets unknown feed {name!r} "
                        f"(known: {', '.join(sorted(registered))})")
                buckets.setdefault(name, []).append(rule)
        with self._rules_lock:
            self.rules = ruleset
            self.by_source = buckets
        return ruleset

    @staticmethod
    def _targets_for(rule: Rule) -> tuple[str, ...]:
        """Which feeds a rule applies to.

        Prefers the explicit ``~ on:`` directive; falls back to sniffing a
        legacy ``source == "..."`` condition so v1 rules still bucket
        correctly instead of being evaluated against every event.
        """
        if rule.feeds:
            return tuple(f for f in rule.feeds if f not in ("any", "*"))
        found = []
        for cond in rule.conditions:
            for m in re.finditer(r'source\s*==\s*["\']([A-Za-z0-9_.-]+)["\']', cond):
                found.append(m.group(1))
        return tuple(dict.fromkeys(found))

    def rules_for(self, source: str) -> List[Rule]:
        with self._rules_lock:
            return self.by_source.get(source, []) + self.by_source["*"]

    # -- event pipeline -------------------------------------------------
    def handle(self, event: Dict[str, Any]) -> None:
        if "parent_name" not in event and event.get("ppid"):
            event.update(self.parents.resolve(event["ppid"]))
        apply_aliases(event)
        with self._count_lock:
            self.event_count += 1
        source = event.get("source") or "any"
        matched = [r for r in self.rules_for(source) if r.matches(event)]
        if not matched:
            return
        for alert in self.builder.process(event, matched):
            self.emit(alert)

    def emit(self, alert: Dict[str, Any]) -> None:
        if self.cfg.quiet:
            return
        sev = alert.get("severity", "info")
        ts = (alert.get("event_time") or alert.get("detected_at") or "")[11:19]
        name = alert["rule"]["name"]
        prior = alert.get("prior_verdict")
        mark = ""
        if prior:
            mark = f"{ui.P.faint}↺{ui.P.reset} "
        line = (
            f"  {ui.severity_dot(sev)} {ui.P.faint}{ts}{ui.P.reset} "
            f"{ui.severity_tag(sev)} "
            f"{ui.P.accent}{ui.truncate(name, 32)}{ui.P.reset} "
            f"{mark}"
            f"{ui.P.muted}{ui.truncate(alert.get('summary', ''), max(20, ui.term_width() - 70))}{ui.P.reset}"
        )
        print(line, flush=True)

    # -- workers --------------------------------------------------------
    def _feed_worker(self, feed: "feeds.Feed") -> None:
        if feed.stream is None:
            return
        for event in feed.stream(self.cfg, self.stop):
            if self.stop.is_set():
                return
            event.setdefault("source", feed.name)
            self.handle(event)

    def active_feeds(self) -> List["feeds.Feed"]:
        disabled = {
            name.strip() for name in self.cfg.disabled_feeds.split(",") if name.strip()
        }
        if not self.cfg.enable_auditd:
            disabled.add("auditd")
        if not self.cfg.enable_journald:
            disabled.add("journald")
        out = []
        for feed in feeds.all_feeds():
            if feed.name in disabled or not feed.default_enabled:
                continue
            if feed.name == "auditd" and not os.path.exists(self.cfg.audit_log):
                print(ui.status("warn",
                                f"auditd feed: {self.cfg.audit_log} not present yet — "
                                f"will retry"))
            out.append(feed)
        return out

    def _supervise(self, name: str, target) -> None:
        """Restart a crashed collector with capped backoff."""
        delay = 1.0
        while not self.stop.is_set():
            try:
                target()
                if self.stop.is_set():
                    return
                reason = "stream ended"
            except Exception as exc:  # keep the daemon alive
                reason = f"{type(exc).__name__}: {exc}"
            if self.stop.is_set():
                return
            print(ui.status("warn", f"{name} collector stopped ({reason}); "
                                    f"restarting in {delay:.0f}s"), file=sys.stderr)
            if self.stop.wait(delay):
                return
            delay = min(delay * 2, 30.0)

    # -- lifecycle ------------------------------------------------------
    def install_signals(self) -> None:
        def shutdown(signum, _frame):
            if not self.stop.is_set():
                print(f"\n{ui.status('info', 'shutting down…')}", flush=True)
            self.stop.set()

        def reload(signum, _frame):
            self.reload_requested.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, shutdown)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, reload)

    def report_rules(self, ruleset: RuleSet) -> None:
        counts = ruleset.by_severity()
        summary = "  ".join(
            f"{ui.severity_color(s)}{counts[s]} {s}{ui.P.reset}"
            for s in ("critical", "high", "medium", "low", "info") if counts.get(s))
        print(ui.status("ok", f"{len(ruleset)} rules loaded    {summary}"))
        for warning in ruleset.warnings[:12]:
            print(ui.status("warn", warning))
        if len(ruleset.warnings) > 12:
            print(ui.hint(f"  … {len(ruleset.warnings) - 12} more warnings"))
        for error in ruleset.errors[:12]:
            print(ui.status("err", error))
        if len(ruleset.errors) > 12:
            print(ui.hint(f"  … {len(ruleset.errors) - 12} more errors"))

    def run(self) -> int:
        self.install_signals()
        print(ui.banner("engine", VERSION))

        problems = feeds.load_descriptors(self.cfg.feeds_dir)
        for problem in problems:
            print(ui.status("warn", f"feed descriptor: {problem}"))
        for feed in feeds.all_feeds():
            register_fields(feed.fields)

        try:
            ruleset = self.load()
        except FileNotFoundError:
            print(ui.status("err", f"rules file not found: {self.cfg.rules_path}"),
                  file=sys.stderr)
            return 1
        except Exception as exc:
            print(ui.status("err", f"could not load rules: {exc}"), file=sys.stderr)
            return 1

        self.report_rules(ruleset)
        if not ruleset.rules:
            print(ui.status("err", "no usable rules — refusing to start blind"),
                  file=sys.stderr)
            return 1

        print(ui.status("info", f"alerts  {ui.P.muted}{self.cfg.alert_log}{ui.P.reset}"))
        closed = len(self.builder.known_signatures)
        if closed:
            mode = "suppressed" if self.cfg.suppress_known else "flagged as seen"
            print(ui.status("info", f"triage  {ui.P.muted}{closed} closed signature(s) — "
                                    f"repeats {mode}{ui.P.reset}"))
        active = self.active_feeds()
        with self._rules_lock:
            counts = {f.name: len(self.by_source.get(f.name, [])) for f in active}
        print(ui.status("info", "feeds   " + (ui.P.muted + ", ".join(
            f"{f.name}({counts.get(f.name, 0)} rules)" for f in active) + ui.P.reset
            or "none")))
        print(ui.rule_line())
        print()

        workers = [
            threading.Thread(
                target=self._supervise,
                args=(feed.name, lambda f=feed: self._feed_worker(f)),
                name=f"feed-{feed.name}", daemon=True)
            for feed in active
        ]

        if not workers:
            print(ui.status("err", "no feeds enabled"), file=sys.stderr)
            return 1

        for worker in workers:
            worker.start()

        try:
            while not self.stop.is_set():
                if self.reload_requested.is_set():
                    self.reload_requested.clear()
                    try:
                        reloaded = self.load()
                        known = self._known_signatures()
                        self.builder.refresh_known(known)
                        print(ui.status("ok", f"rules reloaded — {len(reloaded)} active"
                                              f", {len(known)} closed signatures"))
                        for warning in reloaded.warnings[:5]:
                            print(ui.status("warn", warning))
                    except Exception as exc:
                        print(ui.status("err", f"reload failed, keeping previous rules: {exc}"),
                              file=sys.stderr)
                if not any(w.is_alive() for w in workers):
                    print(ui.status("err", "all collectors stopped"), file=sys.stderr)
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop.set()

        self.stop.set()
        for worker in workers:
            worker.join(timeout=5.0)
        self.writer.close()

        stats = self.builder.stats
        print()
        print(ui.rule_line())
        print(ui.status("ok", ui.kv_inline([
            ("events", self.event_count),
            ("alerts", stats.get("alerts", 0)),
            ("suppressed", stats.get("suppressed", 0)),
            ("known", stats.get("known", 0)),
            ("uptime", f"{time.time() - self.started:.0f}s"),
        ])))
        return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cfg = config_mod.load()

    if "--check" in argv or "-c" in argv:
        return check_rules(cfg)
    if "--version" in argv:
        print(f"cthulhu {VERSION}")
        return 0
    if "--help" in argv or "-h" in argv:
        print(ui.banner("engine", VERSION))
        print(ui.hint("usage: cthulhu-engine [--check] [--version]"))
        print(ui.hint("  --check   validate the rules file and exit"))
        print()
        return 0

    return Engine(cfg).run()


def check_rules(cfg: config_mod.Config) -> int:
    """Validate the ruleset without starting collectors."""
    print(ui.banner("rule check", VERSION))
    for problem in feeds.load_descriptors(cfg.feeds_dir):
        print(ui.status("warn", f"feed descriptor: {problem}"))
    for feed in feeds.all_feeds():
        register_fields(feed.fields)
    try:
        ruleset = load_rules(cfg.rules_path)
    except FileNotFoundError:
        print(ui.status("err", f"not found: {cfg.rules_path}"))
        return 1

    counts = ruleset.by_severity()
    print(ui.status("info", f"file    {ui.P.muted}{cfg.rules_path}{ui.P.reset}"))
    print(ui.status("ok" if not ruleset.errors else "err",
                    f"{len(ruleset)} rules parsed    " + "  ".join(
                        f"{ui.severity_color(s)}{counts[s]} {s}{ui.P.reset}"
                        for s in ("critical", "high", "medium", "low", "info")
                        if counts.get(s))))
    for warning in ruleset.warnings:
        print(ui.status("warn", warning))
    for error in ruleset.errors:
        print(ui.status("err", error))
    print()
    return 1 if ruleset.errors else 0


if __name__ == "__main__":
    sys.exit(main())
