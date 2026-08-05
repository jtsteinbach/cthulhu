"""JRL — Jaco Rule Language, version 2.

A small, readable detection language with a real parser.

v1 rewrote rule text into Python source with regular expressions and handed
the result to ``eval()``. That corrupted any string literal containing
``and``/``or``/``true``/``null``, raised ``NameError`` for fields an event did
not carry (silently swallowed, so the rule never fired), and executed
attacker-controlled text if the rules file was ever writable.

v2 tokenizes, parses to an AST, and compiles the AST to closures. String
literals are opaque, unknown fields evaluate to NULL rather than raising, and
nothing is ever executed as Python.

Grammar
-------

    rule        := header desc? directive* condition+
    header      := NAME '(' SEVERITY ')'
    desc        := '|' STRING
    directive   := '~' NAME ':' VALUE
    condition   := ':' expr

    expr        := or_expr
    or_expr     := and_expr ('or' and_expr)*
    and_expr    := not_expr ('and' not_expr)*
    not_expr    := 'not' not_expr | primary
    primary     := '(' expr ')' | comparison
    comparison  := operand (compare_op operand
                            | 'is' 'not'? 'null'
                            | 'not'? 'in' list)
    operand     := FIELD | STRING | NUMBER | BOOL | NULL | list
    list        := '[' operand (',' operand)* ']'

All ``:`` conditions of a rule are ANDed together.

Null semantics
--------------
A field missing from an event is NULL — referencing it is never an error, so
an auditd rule simply does not match a journald event.

Positive tests are **fail-closed**: ``==``, ``!=``, ``<``, ``>``, ``contains``,
``startswith``, ``endswith``, ``matches`` and ``in`` are all False when the
field is NULL. A rule can never fire on data that is not there.

Negated *exclusion* filters are **fail-open**: ``!contains``, ``!startswith``,
``!endswith``, ``!matches`` and ``not in`` are True when the field is NULL.
This is what makes tuning safe — ``parent_name not in $package_managers``
must not silently discard an event just because the parent could not be
resolved. Use ``is null`` / ``is not null`` when you need to test presence
explicitly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .schema import SEVERITIES, known_fields, resolve_alias

__all__ = [
    "Rule",
    "RuleSet",
    "JRLError",
    "JRLSyntaxError",
    "parse_rules",
    "load_rules",
]


class JRLError(Exception):
    """Base class for rule-language failures."""


class JRLSyntaxError(JRLError):
    def __init__(self, message: str, line: int, text: str = "") -> None:
        self.line = line
        self.text = text
        super().__init__(f"line {line}: {message}" + (f"  |  {text.strip()!r}" if text else ""))


# ==========================================================================
# NULL sentinel
# ==========================================================================


class _Null:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "NULL"

    def __bool__(self) -> bool:
        return False


NULL = _Null()

Predicate = Callable[[Dict[str, Any]], Any]


# ==========================================================================
# Tokenizer
# ==========================================================================

_TOKEN_SPEC: Sequence[Tuple[str, str]] = (
    ("WS", r"[ \t]+"),
    ("STRING", r'"(?:\\.|[^"\\])*"' r"|'(?:\\.|[^'\\])*'"),
    ("NUMBER", r"-?\d+\.\d+|-?\d+"),
    ("OP", r"==|!=|<=|>=|<|>"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("LBRACK", r"\["),
    ("RBRACK", r"\]"),
    ("COMMA", r","),
    ("BANGWORD", r"!(?:contains|icontains|startswith|istartswith|"
                 r"endswith|iendswith|matches|imatches|in)\b"),
    ("VAR", r"\$[A-Za-z_][A-Za-z0-9_]*"),
    ("NAME", r"[A-Za-z_][A-Za-z0-9_]*"),
)

_TOKEN_RE = re.compile("|".join(f"(?P<{n}>{p})" for n, p in _TOKEN_SPEC))

_KEYWORDS = {"and", "or", "not", "is", "in", "true", "false", "null"}

_STRING_OPS = {
    "contains", "icontains", "startswith", "istartswith",
    "endswith", "iendswith", "matches", "imatches",
}


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    col: int


def _unescape(raw: str) -> str:
    body = raw[1:-1]
    out: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                        '"': '"', "'": "'", "0": "\0"}.get(nxt, "\\" + nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def tokenize(text: str, line_no: int) -> List[Token]:
    tokens: List[Token] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise JRLSyntaxError(f"unexpected character {text[pos]!r}", line_no, text)
        kind = m.lastgroup or ""
        value = m.group()
        pos = m.end()
        if kind == "WS":
            continue
        if kind == "NAME":
            low = value.lower()
            if low in _KEYWORDS:
                kind, value = "KEYWORD", low
            elif low in _STRING_OPS:
                kind, value = "STROP", low
        elif kind == "BANGWORD":
            kind, value = "NEGOP", value[1:].lower()
        tokens.append(Token(kind, value, m.start()))
    return tokens


# ==========================================================================
# Comparison primitives (null-safe)
# ==========================================================================


def _as_text(value: Any) -> Optional[str]:
    if value is NULL or value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


def _cmp_eq(a: Any, b: Any) -> bool:
    if a is NULL or b is NULL:
        return False
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) is bool(b)
    if isinstance(a, (int, float)) and isinstance(b, str):
        try:
            return float(a) == float(b)
        except ValueError:
            return False
    if isinstance(b, (int, float)) and isinstance(a, str):
        try:
            return float(a) == float(b)
        except ValueError:
            return False
    if isinstance(a, (list, tuple)):
        return b in a
    return a == b


def _numeric_pair(a: Any, b: Any) -> Optional[Tuple[float, float]]:
    if a is NULL or b is NULL or isinstance(a, bool) or isinstance(b, bool):
        return None
    try:
        return float(a), float(b)
    except (TypeError, ValueError):
        return None


def _make_ordering(op: str) -> Callable[[Any, Any], bool]:
    import operator

    fn = {"<": operator.lt, ">": operator.gt,
          "<=": operator.le, ">=": operator.ge}[op]

    def run(a: Any, b: Any) -> bool:
        pair = _numeric_pair(a, b)
        if pair is None:
            return False
        return fn(pair[0], pair[1])

    return run


def _str_op(name: str, needle: Any) -> Callable[[Any], bool]:
    """Build a string test. Regexes and casings are resolved once, at load."""
    if name in ("matches", "imatches"):
        flags = re.IGNORECASE if name == "imatches" else 0
        try:
            rx = re.compile(str(needle), flags)
        except re.error as exc:
            raise JRLError(f"invalid regex {needle!r}: {exc}") from exc

        def run_rx(value: Any) -> bool:
            text = _as_text(value)
            return False if text is None else rx.search(text) is not None

        return run_rx

    fold = name.startswith("i")
    base = name[1:] if fold else name
    target = str(needle).lower() if fold else str(needle)

    if base == "contains":
        def run(value: Any) -> bool:
            text = _as_text(value)
            if text is None:
                return False
            return target in (text.lower() if fold else text)
    elif base == "startswith":
        def run(value: Any) -> bool:
            text = _as_text(value)
            if text is None:
                return False
            return (text.lower() if fold else text).startswith(target)
    else:  # endswith
        def run(value: Any) -> bool:
            text = _as_text(value)
            if text is None:
                return False
            return (text.lower() if fold else text).endswith(target)

    return run


def _membership(value: Any, items: Sequence[Any]) -> bool:
    if value is NULL:
        return False
    if isinstance(value, (list, tuple)):
        return any(_cmp_eq(v, item) for v in value for item in items)
    return any(_cmp_eq(value, item) for item in items)


# ==========================================================================
# Parser -> compiled closures
# ==========================================================================


class _Parser:
    def __init__(self, tokens: List[Token], line_no: int, raw: str,
                 fields_seen: set[str],
                 macros: Optional[Dict[str, List[Any]]] = None) -> None:
        self.tokens = tokens
        self.pos = 0
        self.line_no = line_no
        self.raw = raw
        self.fields_seen = fields_seen
        self.macros = macros or {}

    def _macro(self, token: Token) -> List[Any]:
        name = token.value[1:]
        if name not in self.macros:
            raise JRLSyntaxError(
                f"undefined list ${name} — declare it with "
                f"`@list {name} = [...]` before use", self.line_no, self.raw)
        return list(self.macros[name])

    # -- token helpers ----------------------------------------------------
    def peek(self) -> Optional[Token]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Token:
        tok = self.peek()
        if tok is None:
            raise JRLSyntaxError("unexpected end of condition", self.line_no, self.raw)
        self.pos += 1
        return tok

    def accept(self, kind: str, value: Optional[str] = None) -> Optional[Token]:
        tok = self.peek()
        if tok and tok.kind == kind and (value is None or tok.value == value):
            self.pos += 1
            return tok
        return None

    def expect(self, kind: str, value: Optional[str] = None) -> Token:
        tok = self.accept(kind, value)
        if tok is None:
            got = self.peek()
            want = value or kind
            raise JRLSyntaxError(
                f"expected {want!r}, got {got.value!r}" if got else f"expected {want!r}",
                self.line_no, self.raw)
        return tok

    # -- grammar ----------------------------------------------------------
    def parse(self) -> Predicate:
        pred = self.parse_or()
        if self.peek() is not None:
            raise JRLSyntaxError(f"trailing input {self.peek().value!r}",
                                 self.line_no, self.raw)
        return pred

    def parse_or(self) -> Predicate:
        left = self.parse_and()
        terms = [left]
        while self.accept("KEYWORD", "or"):
            terms.append(self.parse_and())
        if len(terms) == 1:
            return left

        def run(ev: Dict[str, Any]) -> bool:
            return any(t(ev) for t in terms)

        return run

    def parse_and(self) -> Predicate:
        left = self.parse_not()
        terms = [left]
        while self.accept("KEYWORD", "and"):
            terms.append(self.parse_not())
        if len(terms) == 1:
            return left

        def run(ev: Dict[str, Any]) -> bool:
            return all(t(ev) for t in terms)

        return run

    def parse_not(self) -> Predicate:
        if self.accept("KEYWORD", "not"):
            inner = self.parse_not()

            def run(ev: Dict[str, Any]) -> bool:
                return not inner(ev)

            return run
        return self.parse_primary()

    def parse_primary(self) -> Predicate:
        if self.accept("LPAREN"):
            inner = self.parse_or()
            self.expect("RPAREN")
            return inner
        return self.parse_comparison()

    def parse_comparison(self) -> Predicate:
        left = self.parse_operand()
        tok = self.peek()

        if tok is None:
            # Bare field / literal: truthiness test.
            def run_bare(ev: Dict[str, Any]) -> bool:
                return bool(left(ev)) and left(ev) is not NULL

            return run_bare

        # field is [not] null
        if tok.kind == "KEYWORD" and tok.value == "is":
            self.next()
            negate = bool(self.accept("KEYWORD", "not"))
            self.expect("KEYWORD", "null")

            def run_null(ev: Dict[str, Any]) -> bool:
                val = left(ev)
                is_null = val is NULL or val is None
                return (not is_null) if negate else is_null

            return run_null

        # field [not] in [ ... ]   /   field not contains "x"
        if tok.kind == "KEYWORD" and tok.value in ("in", "not"):
            negate = False
            if tok.value == "not":
                self.next()
                # `not contains` / `not startswith` / ... read naturally and
                # are accepted as synonyms for the `!op` spelling.
                following = self.peek()
                if following is not None and following.kind == "STROP":
                    self.next()
                    return self._string_test(left, following.value, negate=True)
                self.expect("KEYWORD", "in")
                negate = True
            else:
                self.next()
            items = self.parse_list_literal()

            def run_in(ev: Dict[str, Any]) -> bool:
                hit = _membership(left(ev), items)
                return (not hit) if negate else hit

            return run_in

        if tok.kind == "NEGOP" and tok.value == "in":
            self.next()
            items = self.parse_list_literal()

            def run_notin(ev: Dict[str, Any]) -> bool:
                return not _membership(left(ev), items)

            return run_notin

        # string operators (positive and negated)
        if tok.kind in ("STROP", "NEGOP"):
            self.next()
            return self._string_test(left, tok.value, negate=tok.kind == "NEGOP")

        # comparison operators
        if tok.kind == "OP":
            self.next()
            right = self.parse_operand()
            op = tok.value
            if op == "==":
                def run_eq(ev: Dict[str, Any]) -> bool:
                    return _cmp_eq(left(ev), right(ev))
                return run_eq
            if op == "!=":
                def run_ne(ev: Dict[str, Any]) -> bool:
                    a, b = left(ev), right(ev)
                    if a is NULL or b is NULL:
                        return False
                    return not _cmp_eq(a, b)
                return run_ne
            order = _make_ordering(op)

            def run_ord(ev: Dict[str, Any]) -> bool:
                return order(left(ev), right(ev))

            return run_ord

        raise JRLSyntaxError(f"unexpected token {tok.value!r}", self.line_no, self.raw)

    def _string_test(self, left: Predicate, op: str, negate: bool) -> Predicate:
        """Compile `field <op> needle` where needle may be a value or a list."""
        needle_tok = self.peek()
        if needle_tok is None:
            raise JRLSyntaxError(f"{op!r} needs an operand", self.line_no, self.raw)

        # A list on the right means "any of": exe_name contains ["a", "b"]
        if needle_tok.kind in ("LBRACK", "VAR"):
            items = self.parse_list_literal()
            try:
                tests = [_str_op(op, item) for item in items]
            except JRLError as exc:
                raise JRLSyntaxError(str(exc), self.line_no, self.raw) from exc

            def run_multi(ev: Dict[str, Any]) -> bool:
                value = left(ev)
                hit = any(test(value) for test in tests)
                return (not hit) if negate else hit

            return run_multi

        needle = self.parse_literal_value()
        try:
            test = _str_op(op, needle)
        except JRLError as exc:
            raise JRLSyntaxError(str(exc), self.line_no, self.raw) from exc

        def run_single(ev: Dict[str, Any]) -> bool:
            hit = test(left(ev))
            return (not hit) if negate else hit

        return run_single

    def parse_list_literal(self) -> List[Any]:
        # A bare $var is itself a list.
        tok = self.peek()
        if tok is not None and tok.kind == "VAR":
            self.next()
            return self._macro(tok)

        self.expect("LBRACK")
        items: List[Any] = []
        if self.accept("RBRACK"):
            return items
        while True:
            nxt = self.peek()
            if nxt is not None and nxt.kind == "VAR":
                self.next()
                items.extend(self._macro(nxt))  # splice
            else:
                items.append(self.parse_literal_value())
            if self.accept("COMMA"):
                if self.peek() and self.peek().kind == "RBRACK":
                    self.next()
                    break
                continue
            self.expect("RBRACK")
            break
        return items

    def parse_literal_value(self) -> Any:
        tok = self.next()
        if tok.kind == "STRING":
            return _unescape(tok.value)
        if tok.kind == "NUMBER":
            return float(tok.value) if "." in tok.value else int(tok.value)
        if tok.kind == "KEYWORD":
            if tok.value == "true":
                return True
            if tok.value == "false":
                return False
            if tok.value == "null":
                return NULL
        raise JRLSyntaxError(f"expected a literal, got {tok.value!r}",
                             self.line_no, self.raw)

    def parse_operand(self) -> Predicate:
        tok = self.peek()
        if tok is None:
            raise JRLSyntaxError("expected a value", self.line_no, self.raw)

        if tok.kind == "NAME":
            self.next()
            name = resolve_alias(tok.value)
            self.fields_seen.add(tok.value)

            def read(ev: Dict[str, Any]) -> Any:
                val = ev.get(name, NULL)
                return NULL if val is None else val

            return read

        if tok.kind in ("LBRACK", "VAR"):
            items = self.parse_list_literal()
            return lambda ev: items

        value = self.parse_literal_value()
        return lambda ev: value


# ==========================================================================
# Rule model
# ==========================================================================


@dataclass
class Threshold:
    """Correlation window: fire only after `count` matches within `window`s."""
    count: int
    window: float
    group_by: Tuple[str, ...] = ()


@dataclass
class Rule:
    name: str
    severity: str
    description: str = ""
    conditions: List[str] = dc_field(default_factory=list)
    predicate: Optional[Predicate] = None
    feeds: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    mitre: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    threshold: Optional[Threshold] = None
    throttle: float = 0.0
    dedup_by: Tuple[str, ...] = ()
    fields_used: Tuple[str, ...] = ()
    line_no: int = 0
    enabled: bool = True

    def matches(self, event: Dict[str, Any]) -> bool:
        if not self.enabled or self.predicate is None:
            return False
        try:
            return bool(self.predicate(event))
        except Exception:
            return False


@dataclass
class RuleSet:
    rules: List[Rule] = dc_field(default_factory=list)
    errors: List[str] = dc_field(default_factory=list)
    warnings: List[str] = dc_field(default_factory=list)
    path: str = ""

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterable[Rule]:
        return iter(self.rules)

    def by_severity(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in self.rules:
            out[r.severity] = out.get(r.severity, 0) + 1
        return out


# ==========================================================================
# Directive parsing
# ==========================================================================

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*$", re.IGNORECASE)
_MULT = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def _parse_duration(text: str, line_no: int, raw: str) -> float:
    m = _DURATION_RE.match(text)
    if not m:
        raise JRLSyntaxError(f"invalid duration {text!r} (try 30s, 5m, 1h)", line_no, raw)
    return float(m.group(1)) * _MULT[m.group(2).lower()]


_THRESHOLD_RE = re.compile(
    r"^\s*(\d+)\s+in\s+([\w.]+)\s*(?:by\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*))?\s*$",
    re.IGNORECASE,
)


def _split_list(text: str) -> Tuple[str, ...]:
    return tuple(p.strip() for p in re.split(r"[,\s]+", text.strip()) if p.strip())


def _apply_directive(rule: Rule, key: str, value: str, line_no: int, raw: str) -> None:
    key = key.lower()
    if key in ("on", "feed", "feeds", "source", "sources"):
        rule.feeds = rule.feeds + _split_list(value)
    elif key in ("tag", "tags"):
        rule.tags = rule.tags + _split_list(value)
    elif key in ("mitre", "attack"):
        rule.mitre = rule.mitre + _split_list(value)
    elif key in ("ref", "refs", "reference", "references"):
        rule.references = rule.references + (value.strip(),)
    elif key == "throttle":
        rule.throttle = _parse_duration(value, line_no, raw)
    elif key in ("dedup", "dedup_by"):
        rule.dedup_by = _split_list(value)
    elif key == "threshold":
        m = _THRESHOLD_RE.match(value)
        if not m:
            raise JRLSyntaxError(
                f"invalid threshold {value!r} (try: 5 in 60s by auid)", line_no, raw)
        group = _split_list(m.group(3)) if m.group(3) else ()
        rule.threshold = Threshold(
            count=int(m.group(1)),
            window=_parse_duration(m.group(2), line_no, raw),
            group_by=tuple(resolve_alias(g) for g in group),
        )
    elif key in ("enabled", "disabled"):
        flag = value.strip().lower() in ("true", "yes", "1", "on")
        rule.enabled = flag if key == "enabled" else (not flag)
    else:
        raise JRLSyntaxError(f"unknown directive {key!r}", line_no, raw)


# ==========================================================================
# Rules file parsing
# ==========================================================================

_HEADER_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_]+)\s*\)\s*$")
_DESC_RE = re.compile(r'^\|\s*"((?:\\.|[^"\\])*)"\s*$')
_DIRECTIVE_RE = re.compile(r"^~\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")
_LIST_RE = re.compile(r"^@list\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
#: A wrapped condition line that continues the previous boolean clause.
_CONTINUATION_RE = re.compile(r"^(and|or)\b", re.IGNORECASE)
#: A condition line left hanging on an operator, e.g. `... == "a" or`.
_TRAILING_OP_RE = re.compile(r"\b(and|or|not|in|contains|startswith|endswith|"
                             r"matches|icontains|istartswith|iendswith|imatches)\s*$",
                             re.IGNORECASE)


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment that is not inside a string literal."""
    out: List[str] = []
    quote: Optional[str] = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and i + 1 < len(line):
                out.append(ch)
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
        else:
            if ch in ('"', "'"):
                quote = ch
                out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _depth(text: str) -> int:
    """Net open brackets/parens, ignoring anything inside string literals."""
    depth = 0
    quote: Optional[str] = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        i += 1
    return depth


def parse_rules(text: str, path: str = "<string>",
                validate_fields: bool = True) -> RuleSet:
    """Parse a JRL document. Bad rules are collected, not fatal."""
    ruleset = RuleSet(path=path)
    lines = text.splitlines()
    total = len(lines)
    i = 0
    seen_names: Dict[str, int] = {}
    macros: Dict[str, List[Any]] = {}

    while i < total:
        raw = lines[i]
        stripped = _strip_comment(raw).strip()
        if not stripped:
            i += 1
            continue

        # ---- @list NAME = [ ... ]  (may span multiple lines) ----------
        if stripped.startswith("@list"):
            decl = _LIST_RE.match(stripped)
            if not decl:
                ruleset.errors.append(
                    f"{path}:{i+1}: expected `@list name = [...]`, got {stripped[:60]!r}")
                i += 1
                continue
            body = decl.group(2)
            start = i
            # Accumulate until brackets balance, so lists can wrap.
            while body.count("[") > body.count("]") and i + 1 < total:
                i += 1
                body += " " + _strip_comment(lines[i]).strip()
            try:
                tokens = tokenize(body, start + 1)
                parser = _Parser(tokens, start + 1, body, set(), macros)
                macros[decl.group(1)] = parser.parse_list_literal()
            except JRLSyntaxError as exc:
                ruleset.errors.append(f"{path}:{exc}")
            i += 1
            continue

        header = _HEADER_RE.match(stripped)
        if not header:
            ruleset.errors.append(
                f"{path}:{i+1}: expected a rule header like `name(severity)`, "
                f"got {stripped[:60]!r}")
            i += 1
            continue

        start_line = i + 1
        name, severity = header.group(1), header.group(2).lower()
        i += 1

        rule = Rule(name=name, severity=severity, line_no=start_line)
        fields_seen: set[str] = set()
        failed = False

        if severity not in SEVERITIES:
            ruleset.errors.append(
                f"{path}:{start_line}: rule {name!r} has unknown severity "
                f"{severity!r} (expected one of {', '.join(SEVERITIES)})")
            failed = True

        if name in seen_names:
            ruleset.warnings.append(
                f"{path}:{start_line}: duplicate rule name {name!r} "
                f"(first defined at line {seen_names[name]})")
        else:
            seen_names[name] = start_line

        # Body: description, directives, conditions — until a blank line or
        # the next header.
        while i < total:
            body_raw = lines[i]
            body = _strip_comment(body_raw).strip()
            if not body:
                i += 1
                break
            if _HEADER_RE.match(body):
                break

            try:
                if body.startswith("|"):
                    m = _DESC_RE.match(body)
                    if not m:
                        raise JRLSyntaxError(
                            'description must be | "quoted text"', i + 1, body)
                    rule.description = _unescape('"' + m.group(1) + '"')
                elif body.startswith("~"):
                    m = _DIRECTIVE_RE.match(body)
                    if not m:
                        raise JRLSyntaxError(
                            "directive must be ~ key: value", i + 1, body)
                    _apply_directive(rule, m.group(1), m.group(2), i + 1, body)
                elif body.startswith(":"):
                    cond = body[1:].strip()
                    # A condition wraps while brackets stay open, and also
                    # when the next line simply continues the boolean clause
                    # (`or ...` / `and ...`) or trails an operator.
                    while i + 1 < total:
                        nxt = _strip_comment(lines[i + 1]).strip()
                        if _depth(cond) > 0:
                            pass
                        elif _CONTINUATION_RE.match(nxt):
                            pass
                        elif _TRAILING_OP_RE.search(cond):
                            pass
                        else:
                            break
                        if not nxt:
                            break
                        i += 1
                        cond += " " + nxt
                    if not cond:
                        raise JRLSyntaxError("empty condition", i + 1, body)
                    rule.conditions.append(cond)
                else:
                    raise JRLSyntaxError(
                        "expected `| description`, `~ directive`, or `: condition`",
                        i + 1, body)
            except JRLSyntaxError as exc:
                ruleset.errors.append(f"{path}:{exc}  (rule {name!r})")
                failed = True
            i += 1

        if not rule.conditions:
            ruleset.errors.append(
                f"{path}:{start_line}: rule {name!r} has no conditions")
            failed = True

        if failed:
            continue

        # Compile every condition and AND them together.
        compiled: List[Predicate] = []
        for offset, cond in enumerate(rule.conditions):
            try:
                tokens = tokenize(cond, start_line)
                if not tokens:
                    raise JRLSyntaxError("empty condition", start_line, cond)
                compiled.append(_Parser(tokens, start_line, cond, fields_seen, macros).parse())
            except JRLSyntaxError as exc:
                ruleset.errors.append(f"{path}:{exc}  (rule {name!r})")
                failed = True
            except JRLError as exc:
                ruleset.errors.append(
                    f"{path}:{start_line}: {exc}  (rule {name!r})")
                failed = True

        if failed:
            continue

        if len(compiled) == 1:
            rule.predicate = compiled[0]
        else:
            def _all(ev: Dict[str, Any], _c=tuple(compiled)) -> bool:
                for p in _c:
                    if not p(ev):
                        return False
                return True

            rule.predicate = _all

        rule.fields_used = tuple(sorted(fields_seen))

        if validate_fields:
            allowed = known_fields()
            unknown = sorted(f for f in fields_seen if f not in allowed)
            if unknown:
                ruleset.warnings.append(
                    f"{path}:{start_line}: rule {name!r} references unknown "
                    f"field(s): {', '.join(unknown)} — it can never match. "
                    f"Check spelling against the schema.")

        if rule.threshold:
            bad = [g for g in rule.threshold.group_by if g not in known_fields()]
            if bad and validate_fields:
                ruleset.warnings.append(
                    f"{path}:{start_line}: rule {name!r} groups by unknown "
                    f"field(s): {', '.join(bad)}")

        ruleset.rules.append(rule)

    return ruleset


def load_rules(path: str, validate_fields: bool = True) -> RuleSet:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_rules(fh.read(), path=path, validate_fields=validate_fields)
