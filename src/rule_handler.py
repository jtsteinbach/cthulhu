# CTHULHU module    rule_handler.py

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List


# string helper functions used inside expressions

def _contains(value: Any, needle: Any) -> bool:
    if value is None:
        return False
    return str(needle) in str(value)


def _startswith(value: Any, prefix: Any) -> bool:
    if value is None:
        return False
    return str(value).startswith(str(prefix))


def _endswith(value: Any, suffix: Any) -> bool:
    if value is None:
        return False
    return str(value).endswith(str(suffix))


# CONDITION NORMALIZATION

def _normalize_condition_line(line: str) -> str:
    # normalize a single condition line into safe python. this version uses a
    # tokenization approach to prevent merging `or` with `_contains` or `_endswith`.

    expr = line.strip()

    # normalize literals
    expr = re.sub(r"\btrue\b", "True", expr)
    expr = re.sub(r"\bfalse\b", "False", expr)
    expr = re.sub(r"\bnull\b", "None", expr)
    expr = re.sub(r"\bis\s+not\s+null\b", "is not None", expr)
    expr = re.sub(r"\bis\s+null\b", "is None", expr)

    # tokenize by boolean operators
    parts = re.split(r'\b(and|or)\b', expr)

    normalized_parts = []

    # LHS pattern allowing parentheses
    LHS = r"(\(*\s*[A-Za-z_][A-Za-z0-9_\.]*\s*\)*)"

    for part in parts:
        stripped = part.strip()

        # boolean operators pass through unchanged
        if stripped in ("and", "or"):
            normalized_parts.append(stripped)
            continue

        # NEGATED operators
        part = re.sub(rf"{LHS}\s+!contains\s+(.*)", r"not _contains(\1, \2)", part)
        part = re.sub(rf"{LHS}\s+!startswith\s+(.*)", r"not _startswith(\1, \2)", part)
        part = re.sub(rf"{LHS}\s+!endswith\s+(.*)", r"not _endswith(\1, \2)", part)

        # POSITIVE operators
        part = re.sub(rf"{LHS}\s+contains\s+(.*)", r"_contains(\1, \2)", part)
        part = re.sub(rf"{LHS}\s+startswith\s+(.*)", r"_startswith(\1, \2)", part)
        part = re.sub(rf"{LHS}\s+endswith\s+(.*)", r"_endswith(\1, \2)", part)

        normalized_parts.append(part)

    # reassemble with proper spacing
    final_expr = " ".join(normalized_parts).strip()
    return final_expr


def _compile_rule_expression(cond_lines: List[str]) -> Callable[[Dict[str, Any]], bool]:
    # compile a list of condition lines into a predicate.
    # cond_lines are raw condition strings *without* leading ":".
    
    if not cond_lines:
        expr_src = "True"  # rule always matches if no conditions
    else:
        normalized = [_normalize_condition_line(c) for c in cond_lines]
        expr_src = " and ".join(f"({c})" for c in normalized)

    code = compile(expr_src, "<rule>", "eval")

    def predicate(event: Dict[str, Any]) -> bool:
        # evaluate the compiled rule expression against an event dict.
        # event keys are injected as variables in the eval context.

        local_env: Dict[str, Any] = dict(event)
        local_env.update(
            {
                "_contains": _contains,
                "_startswith": _startswith,
                "_endswith": _endswith,
            }
        )
        # no builtins to reduce risk surface; rules only use provided names.
        return bool(eval(code, {"__builtins__": {}}, local_env))

    # optional: store source expression for debugging
    predicate._expr_src = expr_src  # type: ignore[attr-defined]
    return predicate


# RULE LOADING

def load_rules_from_file(path: str) -> List[Dict[str, Any]]:
    # load rules from JRL rules file.

    with open(path, "r", encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f]

    rules: List[Dict[str, Any]] = []
    i = 0
    total = len(lines)

    while i < total:
        line = lines[i].strip()

        if not line:
            i += 1
            continue

        # rule header: name(severity)
        m = re.match(r"^([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]+)\s*\)\s*$", line)
        if not m:
            raise ValueError(f"Invalid rule header at line {i+1}: {line!r}")

        name = m.group(1)
        severity = m.group(2)
        i += 1

        # description line: | "text"
        if i >= total:
            raise ValueError(f"Missing description line for rule {name!r}")

        desc_line = lines[i].lstrip()
        m_desc = re.match(r'^\|\s*"(.*)"\s*$', desc_line)
        if not m_desc:
            raise ValueError(
                f"Invalid description line at {i+1} for rule {name!r}: {desc_line!r}"
            )

        description = m_desc.group(1)
        i += 1

        # condition lines
        cond_lines: List[str] = []
        while i < total:
            raw = lines[i]
            stripped = raw.lstrip()

            if not stripped:
                # blank line separates rules
                i += 1
                break

            if stripped.startswith(":"):
                # remove leading ":" and surrounding whitespace
                cond = stripped[1:].strip()
                cond_lines.append(cond)
                i += 1
            else:
                # next rule header (or other content)
                break

        predicate = _compile_rule_expression(cond_lines)

        rules.append(
            {
                "name": name,
                "severity": severity,
                "description": description,
                "predicate": predicate,
            }
        )

    return rules


# RULE EVALUATION

def evaluate_rules(event: Dict[str, Any], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # evaluate all rules against a single event.

    matches: List[Dict[str, Any]] = []
    for rule in rules:
        try:
            pred = rule["predicate"]
            if pred(event):
                matches.append(
                    {
                        "rule": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                    }
                )
        except Exception:
            # in production you might log the error with rule["name"]
            continue

    return matches
