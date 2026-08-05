"""Feed registry.

A *feed* is one source of events. v1 hard-coded two of them and every rule
carried a ``: source == "auditd"`` line as boilerplate; adding a third source
would have meant editing the engine, the schema and every rule.

Here a feed is a small descriptor: a name, the extra fields it can produce,
and something that yields raw records. Built-in feeds (``auditd``,
``journald``) are registered at import. Additional feeds can be added two
ways, neither of which touches the engine:

1. **Declaratively** — drop a JSON descriptor in ``feeds.d/``. Good for any
   line-oriented log (nginx, HAProxy, an appliance syslog file).
2. **Programmatically** — call :func:`register` with a :class:`Feed`.

Rules then target a feed with ``~ on: nginx`` instead of a condition, so the
engine can bucket rules per feed and skip evaluating the rest.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set

__all__ = [
    "Feed", "register", "get", "all_feeds", "feed_names",
    "load_descriptors", "build_descriptor_feed",
]


@dataclass
class Feed:
    """One event source."""

    name: str
    description: str = ""
    #: Fields this feed can emit beyond the core set (used for rule validation).
    fields: Set[str] = field(default_factory=set)
    #: Called with (config, stop_event) -> iterator of normalized event dicts.
    stream: Optional[Callable[..., Iterator[Dict[str, Any]]]] = None
    #: Feeds off by default must be enabled explicitly.
    default_enabled: bool = True
    #: Free-form descriptor kept for declarative feeds.
    descriptor: Optional[Dict[str, Any]] = None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Feed {self.name}>"


_REGISTRY: Dict[str, Feed] = {}


def register(feed: Feed, replace: bool = False) -> Feed:
    if feed.name in _REGISTRY and not replace:
        raise ValueError(f"feed {feed.name!r} is already registered")
    _REGISTRY[feed.name] = feed
    return feed


def get(name: str) -> Optional[Feed]:
    return _REGISTRY.get(name)


def all_feeds() -> List[Feed]:
    return sorted(_REGISTRY.values(), key=lambda f: f.name)


def feed_names() -> Set[str]:
    return set(_REGISTRY)


def known_fields() -> Set[str]:
    out: Set[str] = set()
    for feed in _REGISTRY.values():
        out |= feed.fields
    return out


# ==========================================================================
# Declarative feeds (JSON descriptors)
# ==========================================================================

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z",
)


def _parse_ts(text: str) -> Optional[float]:
    text = text.strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt.year == 1900:  # syslog format carries no year
                dt = dt.replace(year=datetime.now(timezone.utc).year)
            return dt.timestamp()
        except ValueError:
            continue
    try:
        return float(text)
    except ValueError:
        return None


_COERCE = {
    "int": lambda v: int(str(v).strip()),
    "float": lambda v: float(str(v).strip()),
    "bool": lambda v: str(v).strip().lower() in ("1", "true", "yes", "on"),
    "str": lambda v: str(v),
}


class DescriptorParser:
    """Turns a raw log line into a normalized event from a JSON descriptor."""

    def __init__(self, spec: Dict[str, Any]) -> None:
        self.name: str = spec["name"]
        self.fmt: str = spec.get("format", "regex")
        self.category: str = spec.get("category", "log")
        self.action: Optional[str] = spec.get("action")
        self.field_map: Dict[str, str] = spec.get("field_map", {})
        self.types: Dict[str, str] = spec.get("types", {})
        self.static: Dict[str, Any] = spec.get("static", {})
        self.ts_field: Optional[str] = spec.get("timestamp_field")
        self.message_field: str = spec.get("message_field", "message")
        self.pattern: Optional[re.Pattern[str]] = None
        if self.fmt == "regex":
            try:
                self.pattern = re.compile(spec["pattern"])
            except (KeyError, re.error) as exc:
                raise ValueError(
                    f"feed {self.name!r}: invalid or missing 'pattern' ({exc})") from exc

    def declared_fields(self) -> Set[str]:
        out: Set[str] = set(self.field_map.values()) | set(self.static)
        if self.pattern is not None:
            out |= set(self.pattern.groupindex)
        return {f for f in out if f}

    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None

        if self.fmt == "json":
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                return None
            if not isinstance(raw, dict):
                return None
            values: Dict[str, Any] = dict(raw)
        else:
            if self.pattern is None:
                return None
            m = self.pattern.search(line)
            if not m:
                return None
            values = {k: v for k, v in m.groupdict().items() if v is not None}

        event: Dict[str, Any] = {
            "source": self.name,
            "category": self.category,
            "raw": line,
        }
        if self.action:
            event["action"] = self.action
        event.update(self.static)

        for src, value in values.items():
            dst = self.field_map.get(src, src)
            if not dst:
                continue
            coerce = self.types.get(dst) or self.types.get(src)
            if coerce in _COERCE:
                try:
                    value = _COERCE[coerce](value)
                except (TypeError, ValueError):
                    continue
            event[dst] = value

        epoch = None
        if self.ts_field and self.ts_field in values:
            epoch = _parse_ts(str(values[self.ts_field]))
        if epoch is None:
            import time as _t
            epoch = _t.time()
        event["epoch"] = epoch
        event["timestamp"] = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

        if self.message_field in event:
            msg = str(event[self.message_field])
            event.setdefault("message", msg)
            event["message_snippet"] = msg[:200]
        else:
            event.setdefault("message", line[:400])
            event.setdefault("message_snippet", line[:200])
        return event


def build_descriptor_feed(spec: Dict[str, Any]) -> Feed:
    """Create a :class:`Feed` from a JSON descriptor dict."""
    if "name" not in spec:
        raise ValueError("feed descriptor requires a 'name'")
    parser = DescriptorParser(spec)
    paths: List[str] = spec.get("paths") or ([spec["path"]] if spec.get("path") else [])
    if not paths:
        raise ValueError(f"feed {spec['name']!r} requires 'path' or 'paths'")
    read_existing = bool(spec.get("read_existing", False))

    def stream(cfg: Any, stop: Any) -> Iterator[Dict[str, Any]]:
        from .engine import follow_file  # imported lazily to avoid a cycle
        import threading

        queue: List[Dict[str, Any]] = []
        lock = threading.Lock()
        gate = threading.Event()

        def pump(path: str) -> None:
            for line in follow_file(path, stop, read_existing,
                                    getattr(cfg, "poll_interval", 0.25)):
                if line is None:
                    continue
                event = parser.parse(line)
                if event is None:
                    continue
                with lock:
                    queue.append(event)
                gate.set()

        expanded: List[str] = []
        for pattern in paths:
            expanded.extend(sorted(glob.glob(pattern)) or [pattern])

        workers = [threading.Thread(target=pump, args=(p,), daemon=True,
                                    name=f"feed-{spec['name']}")
                   for p in expanded]
        for worker in workers:
            worker.start()

        while not stop.is_set():
            gate.wait(0.5)
            gate.clear()
            with lock:
                batch, queue[:] = list(queue), []
            for event in batch:
                yield event

    return Feed(
        name=spec["name"],
        description=spec.get("description", f"log feed: {', '.join(paths)}"),
        fields=parser.declared_fields(),
        stream=stream,
        default_enabled=bool(spec.get("enabled", True)),
        descriptor=spec,
    )


def load_descriptors(directory: str) -> List[str]:
    """Register every ``*.json`` feed descriptor in *directory*.

    Returns a list of human-readable problems; a bad descriptor never
    prevents the others from loading.
    """
    problems: List[str] = []
    if not os.path.isdir(directory):
        return problems
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                spec = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"{path}: {exc}")
            continue
        specs = spec if isinstance(spec, list) else [spec]
        for item in specs:
            try:
                register(build_descriptor_feed(item), replace=True)
            except (ValueError, KeyError) as exc:
                problems.append(f"{path}: {exc}")
    return problems


# ==========================================================================
# Built-in feeds
# ==========================================================================


def _auditd_stream(cfg: Any, stop: Any) -> Iterator[Dict[str, Any]]:
    from .engine import follow_file
    from .normalize import assemble_audit_events

    lines = follow_file(cfg.audit_log, stop, cfg.read_existing, cfg.poll_interval)
    yield from assemble_audit_events(lines, cfg.flush_seconds)


def _journald_stream(cfg: Any, stop: Any) -> Iterator[Dict[str, Any]]:
    import subprocess
    from .normalize import iter_journal_events

    proc = subprocess.Popen(
        ["journalctl", "-o", "json", "--no-pager", "-f", "-n", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        assert proc.stdout is not None
        for event in iter_journal_events(proc.stdout):
            if stop.is_set():
                break
            yield event
    finally:
        for finish in (proc.terminate, proc.kill):
            try:
                finish()
                proc.wait(timeout=3)
                break
            except Exception:
                continue


def _register_builtins() -> None:
    from .schema import FIELD_GROUPS

    core = set(FIELD_GROUPS["core"])
    audit_fields = core | set(FIELD_GROUPS["process"]) | set(FIELD_GROUPS["identity"]) \
        | set(FIELD_GROUPS["file"]) | set(FIELD_GROUPS["network"]) \
        | set(FIELD_GROUPS["audit"]) | set(FIELD_GROUPS["auth"])
    journal_fields = core | set(FIELD_GROUPS["journald"]) | set(FIELD_GROUPS["auth"]) \
        | set(FIELD_GROUPS["network"]) | {"pid", "uid", "gid", "auid", "auid_set",
                                          "exe", "exe_name", "comm", "cmdline", "cwd",
                                          "tty", "session", "is_root", "is_system_user"}

    register(Feed("auditd", "Linux kernel audit subsystem (execve, file, network, auth)",
                  audit_fields, _auditd_stream), replace=True)
    register(Feed("journald", "systemd journal (services, ssh, sudo, kernel)",
                  journal_fields, _journald_stream), replace=True)


_register_builtins()
