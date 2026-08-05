"""Alert remediation and triage.

An alert that nobody dispositions is just noise with a timestamp. This module
records what an analyst decided about each alert and — importantly — turns a
*false positive* verdict into a concrete JRL exclusion the operator can paste
into their ruleset, so triage actually reduces future noise instead of only
labelling it.

Verdicts
--------
``true_positive``
    Real, unwanted activity. The rule worked and the event mattered.
``benign_positive``
    The rule correctly identified the behaviour it was written to find, but
    the activity was authorized or expected. The detection is *right*; the
    context made it harmless. Do not "fix" the rule — suppress the actor.
``false_positive``
    The rule fired on something that is not the behaviour it describes. The
    detection logic is wrong or too broad and should be tuned.
``open``
    Not yet reviewed (the default).
``in_progress``
    Someone has picked it up.
``duplicate``
    Same underlying activity as another alert.

Signatures
----------
Every alert carries a ``signature`` — a fingerprint of the activity that
produced it, with instance-specific noise (pids, build numbers, random temp
names) folded out. When a false or benign positive is recorded, the verdict
is indexed against that signature, so the next occurrence of the same
activity is recognized as already dealt with instead of re-entering the
review queue.

Storage is an append-only JSONL journal: last record wins for a given alert.
That keeps a full audit trail of who changed a verdict and when, survives
rotation of the alert log, and needs no schema migrations.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "Verdict", "TriageRecord", "TriageStore", "suggest_tuning",
    "event_signature", "SIGNATURE_FIELDS",
]


# ==========================================================================
# Event signatures
# ==========================================================================

#: Fields that identify *what happened*, in a stable order. Deliberately
#: excludes anything that changes between two occurrences of the same
#: activity — timestamps, PIDs, serials, alert ids.
SIGNATURE_FIELDS: Tuple[str, ...] = (
    "host", "category", "action", "syscall_name",
    "exe", "cmdline", "parent_name",
    "path", "file_dir",
    "uid", "user",
    "remote_ip", "remote_port",
    "unit", "service", "auth_user", "auth_method",
)

#: Identity and address fields are compared verbatim. Folding digits inside
#: them would be actively dangerous: 203.0.113.9 and 198.51.100.7 would
#: collapse to the same signature, so clearing one source as benign would
#: silently clear every other source too. The same applies to uid and port.
_EXACT_FIELDS = frozenset({
    "uid", "user", "remote_ip", "remote_port", "auth_user", "auth_method",
    "host", "category", "action", "syscall_name", "unit", "service",
})

# Applied only to path- and command-like values, where instance-specific
# noise really does appear: a PID in a path, a build number, a container
# hash, a mkstemp suffix.
#
# Digit runs are folded only where they are *embedded in an identifier*
# (``build-4482``, ``job_991``, ``tmp7734``) — that is, immediately preceded
# by a letter, underscore or hyphen. A run preceded by a dot, a slash, or
# whitespace is left alone, which is what keeps ``203.0.113.9`` and a bare
# port like ``4444`` intact. Standalone runs are folded only when they are
# long enough to be an epoch or serial rather than a port or small id.
_PROC_PID = re.compile(r"/proc/\d+/")
_EMBEDDED_NUM = re.compile(r"(?<=[A-Za-z_-])\d{3,}")
_LONG_NUM = re.compile(r"(?<![\d.])\d{6,}(?![\d.])")
_HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{12,}\b")
_TMP_RAND = re.compile(r"(/tmp/|/var/tmp/|/dev/shm/)[A-Za-z0-9._-]*tmp[A-Za-z0-9._-]*")
_WS = re.compile(r"\s+")


def _normalize(value: Any, exact: bool = False) -> str:
    text = (" ".join(str(v) for v in value)
            if isinstance(value, (list, tuple)) else str(value))
    if exact:
        return _WS.sub(" ", text).strip()
    text = _PROC_PID.sub("/proc/<pid>/", text)
    text = _HEX_BLOB.sub("<hex>", text)
    text = _TMP_RAND.sub(r"\1<tmp>", text)
    text = _EMBEDDED_NUM.sub("<n>", text)
    text = _LONG_NUM.sub("<n>", text)
    return _WS.sub(" ", text).strip()


def event_signature(alert: Dict[str, Any]) -> str:
    """A stable fingerprint of the activity behind an alert.

    Two alerts share a signature when they describe the same rule firing on
    materially the same event, so a verdict recorded once can be recognized
    the next time that activity appears. Instance-specific noise (pids,
    build numbers, random temp names) is folded out of path and command
    values before hashing; identities and addresses are compared exactly.
    """
    rule = (alert.get("rule") or {}).get("name", "")
    event = alert.get("event") or {}

    parts: List[str] = [f"rule={rule}"]
    for name in SIGNATURE_FIELDS:
        value = event.get(name)
        if value in (None, "", [], {}):
            continue
        parts.append(f"{name}={_normalize(value, name in _EXACT_FIELDS)}")

    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace"))
    return digest.hexdigest()[:16]


def signature_of(alert: Dict[str, Any]) -> str:
    """Signature stored on the alert, recomputed if it predates the field."""
    stored = alert.get("signature")
    if isinstance(stored, str) and stored:
        return stored
    return event_signature(alert)


class Verdict:
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    TRUE_POSITIVE = "true_positive"
    BENIGN_POSITIVE = "benign_positive"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"

    ALL: Tuple[str, ...] = (
        OPEN, IN_PROGRESS, TRUE_POSITIVE, BENIGN_POSITIVE,
        FALSE_POSITIVE, DUPLICATE,
    )

    #: Short forms accepted on the command line / in the console.
    ALIASES: Dict[str, str] = {
        "o": OPEN, "open": OPEN, "new": OPEN, "unreviewed": OPEN,
        "w": IN_PROGRESS, "wip": IN_PROGRESS, "progress": IN_PROGRESS,
        "t": TRUE_POSITIVE, "tp": TRUE_POSITIVE, "true": TRUE_POSITIVE,
        "b": BENIGN_POSITIVE, "bp": BENIGN_POSITIVE, "benign": BENIGN_POSITIVE,
        "f": FALSE_POSITIVE, "fp": FALSE_POSITIVE, "false": FALSE_POSITIVE,
        "d": DUPLICATE, "dup": DUPLICATE,
    }

    LABEL: Dict[str, str] = {
        OPEN: "OPEN",
        IN_PROGRESS: "WIP",
        TRUE_POSITIVE: "TRUE POSITIVE",
        BENIGN_POSITIVE: "BENIGN POSITIVE",
        FALSE_POSITIVE: "FALSE POSITIVE",
        DUPLICATE: "DUPLICATE",
    }

    #: Verdicts that mean "stop showing me this by default".
    CLOSED: Tuple[str, ...] = (TRUE_POSITIVE, BENIGN_POSITIVE,
                               FALSE_POSITIVE, DUPLICATE)

    @classmethod
    def normalize(cls, value: str) -> Optional[str]:
        key = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        if key in cls.ALL:
            return key
        return cls.ALIASES.get(key)


@dataclass
class TriageRecord:
    alert_id: str
    verdict: str
    note: str = ""
    analyst: str = ""
    rule: str = ""
    signature: str = ""
    updated_at: str = ""
    history: List[Dict[str, str]] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _whoami() -> str:
    for var in ("SUDO_USER", "USER", "LOGNAME"):
        value = os.getenv(var)
        if value:
            return value
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return "unknown"


class TriageStore:
    """Append-only verdict journal with an in-memory index."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._records: Dict[str, TriageRecord] = {}
        #: signature -> the most recent resolved record carrying it
        self._signatures: Dict[str, TriageRecord] = {}
        self._lock = threading.Lock()
        self._loaded = False

    # -- persistence ----------------------------------------------------
    def load(self) -> "TriageStore":
        with self._lock:
            self._records.clear()
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        alert_id = raw.get("alert_id")
                        if not alert_id:
                            continue
                        previous = self._records.get(alert_id)
                        history = list(previous.history) if previous else []
                        if previous:
                            history.append({
                                "verdict": previous.verdict,
                                "analyst": previous.analyst,
                                "at": previous.updated_at,
                                "note": previous.note,
                            })
                        self._records[alert_id] = TriageRecord(
                            alert_id=alert_id,
                            verdict=raw.get("verdict", Verdict.OPEN),
                            note=raw.get("note", ""),
                            analyst=raw.get("analyst", ""),
                            rule=raw.get("rule", ""),
                            signature=raw.get("signature", ""),
                            updated_at=raw.get("updated_at", ""),
                            history=history,
                        )
            self._reindex_signatures()
            self._loaded = True
        return self

    def _reindex_signatures(self) -> None:
        self._signatures.clear()
        for record in sorted(self._records.values(),
                             key=lambda r: r.updated_at or ""):
            if not record.signature:
                continue
            if record.verdict in Verdict.CLOSED:
                self._signatures[record.signature] = record
            else:
                # Reopening an alert withdraws the signature's resolution.
                self._signatures.pop(record.signature, None)

    def _ensure(self) -> None:
        if not self._loaded:
            self.load()

    def _append(self, record: TriageRecord) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = {
            "alert_id": record.alert_id,
            "verdict": record.verdict,
            "note": record.note,
            "analyst": record.analyst,
            "rule": record.rule,
            "signature": record.signature,
            "updated_at": record.updated_at,
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
            fh.flush()

    # -- API ------------------------------------------------------------
    def set_verdict(self, alert_id: str, verdict: str, note: str = "",
                    analyst: Optional[str] = None,
                    rule: str = "", signature: str = "") -> TriageRecord:
        normalized = Verdict.normalize(verdict)
        if normalized is None:
            raise ValueError(
                f"unknown verdict {verdict!r}; expected one of "
                f"{', '.join(Verdict.ALL)}")
        self._ensure()
        with self._lock:
            previous = self._records.get(alert_id)
            history = list(previous.history) if previous else []
            if previous:
                history.append({
                    "verdict": previous.verdict,
                    "analyst": previous.analyst,
                    "at": previous.updated_at,
                    "note": previous.note,
                })
            record = TriageRecord(
                alert_id=alert_id,
                verdict=normalized,
                note=note.strip(),
                analyst=analyst or _whoami(),
                rule=rule or (previous.rule if previous else ""),
                signature=signature or (previous.signature if previous else ""),
                updated_at=_now(),
                history=history,
            )
            self._records[alert_id] = record
            self._append(record)
            if record.signature:
                if record.verdict in Verdict.CLOSED:
                    self._signatures[record.signature] = record
                else:
                    self._signatures.pop(record.signature, None)
        return record

    # -- signature lookups ----------------------------------------------
    def record_for_signature(self, signature: str) -> Optional[TriageRecord]:
        """The verdict previously reached for this activity, if any."""
        if not signature:
            return None
        self._ensure()
        return self._signatures.get(signature)

    def resolve(self, alert: Dict[str, Any]) -> Tuple[str, bool, Optional[TriageRecord]]:
        """Effective verdict for an alert.

        Returns ``(verdict, inherited, record)``. An explicit verdict on this
        alert always wins. Otherwise, if the alert's signature matches
        activity already dispositioned, that verdict is inherited — the alert
        has effectively been dealt with before and does not need reviewing
        again.
        """
        self._ensure()
        alert_id = alert.get("alert_id", "")
        own = self._records.get(alert_id)
        if own is not None:
            return own.verdict, False, own
        prior = self._signatures.get(signature_of(alert))
        if prior is not None:
            return prior.verdict, True, prior
        return Verdict.OPEN, False, None

    def known_signatures(self, verdicts: Iterable[str] = ()) -> Dict[str, str]:
        """Map of signature -> verdict for activity already dealt with."""
        self._ensure()
        wanted = set(verdicts) or set(Verdict.CLOSED)
        return {sig: rec.verdict for sig, rec in self._signatures.items()
                if rec.verdict in wanted}

    def bulk_set(self, alerts: Iterable[Dict[str, Any]], verdict: str,
                 note: str = "", analyst: Optional[str] = None) -> int:
        count = 0
        for alert in alerts:
            self.set_verdict(alert.get("alert_id", ""), verdict, note, analyst,
                             (alert.get("rule") or {}).get("name", ""),
                             signature_of(alert))
            count += 1
        return count

    def get(self, alert_id: str) -> Optional[TriageRecord]:
        self._ensure()
        return self._records.get(alert_id)

    def verdict_of(self, alert_id: str) -> str:
        record = self.get(alert_id)
        return record.verdict if record else Verdict.OPEN

    def counts(self) -> Dict[str, int]:
        self._ensure()
        out = {v: 0 for v in Verdict.ALL}
        for record in self._records.values():
            out[record.verdict] = out.get(record.verdict, 0) + 1
        return out

    def counts_by_rule(self) -> Dict[str, Dict[str, int]]:
        """Per-rule verdict tallies — the input to precision reporting."""
        self._ensure()
        out: Dict[str, Dict[str, int]] = {}
        for record in self._records.values():
            if not record.rule:
                continue
            bucket = out.setdefault(record.rule, {v: 0 for v in Verdict.ALL})
            bucket[record.verdict] = bucket.get(record.verdict, 0) + 1
        return out

    def all_records(self) -> List[TriageRecord]:
        self._ensure()
        return sorted(self._records.values(),
                      key=lambda r: r.updated_at, reverse=True)


# ==========================================================================
# Tuning suggestions
# ==========================================================================

#: Fields worth proposing as an exclusion, most specific first.
_TUNING_CANDIDATES: Tuple[Tuple[str, str], ...] = (
    ("exe", "exe"),
    ("parent_name", "parent_name"),
    ("path", "path"),
    ("file_dir", "file_dir"),
    ("unit", "unit"),
    ("service", "service"),
    ("remote_ip", "remote_ip"),
    ("auth_user", "auth_user"),
    ("user", "user"),
    ("uid", "uid"),
    ("cwd", "cwd"),
)


def suggest_tuning(alert: Dict[str, Any], verdict: str) -> List[str]:
    """Propose JRL edits that would stop this alert recurring.

    A false positive suggests narrowing the *rule*; a benign positive
    suggests suppressing the specific *actor* while leaving detection intact.
    """
    event = alert.get("event") or {}
    rule = (alert.get("rule") or {}).get("name", "the rule")
    lines: List[str] = []

    available = [(field_name, event[field_name])
                 for field_name, _ in _TUNING_CANDIDATES
                 if event.get(field_name) not in (None, "")]

    if not available:
        return [f"# Not enough context on this alert to propose an exclusion."]

    if verdict == Verdict.FALSE_POSITIVE:
        lines.append(f"# {rule} matched activity it was not meant to describe.")
        lines.append("# Narrow it by adding one of these conditions:")
        for field_name, value in available[:4]:
            if isinstance(value, int):
                lines.append(f"    : {field_name} != {value}")
            else:
                lines.append(f'    : {field_name} not in ["{value}"]')
        lines.append("")
        lines.append("# Better still, promote the exclusion to a shared list so")
        lines.append("# every rule benefits:")
        top_field, top_value = available[0]
        lines.append(f'    @list known_good = ["{top_value}"]')
        lines.append(f"    : {top_field} not in $known_good")
    elif verdict == Verdict.BENIGN_POSITIVE:
        lines.append(f"# {rule} is working correctly — this actor is authorized.")
        lines.append("# Keep the detection and suppress just this source:")
        top_field, top_value = available[0]
        if isinstance(top_value, int):
            lines.append(f"    : {top_field} != {top_value}")
        else:
            lines.append(f'    : {top_field} not in ["{top_value}"]')
        lines.append("")
        lines.append("# Or damp the volume without losing visibility:")
        lines.append(f"    ~ throttle: 1h")
        lines.append(f"    ~ dedup: {top_field}")
    elif verdict == Verdict.TRUE_POSITIVE:
        lines.append("# Confirmed true positive — no tuning suggested.")
        lines.append("# Consider raising severity or adding a threshold to catch")
        lines.append("# repetition of this activity:")
        top_field, _ = available[0]
        lines.append(f"    ~ threshold: 3 in 10m by {top_field}")
    else:
        lines.append("# No tuning suggested for this verdict.")

    return lines
