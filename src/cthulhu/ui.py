"""Terminal presentation primitives.

Design goals, borrowed from the modern CLI tools people actually enjoy using:
a small palette (one accent, one warn, one danger, three greys), lots of
breathing room, thin rules instead of heavy boxes, and alignment that holds
at any terminal width.

The important correctness detail is that width is measured on *visible*
characters. v1 padded its boxes by hand-counting characters including the
escape sequences, so any colour change silently broke the alignment.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata
from typing import Any, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Colour handling
# --------------------------------------------------------------------------


def _is_terminal(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _supports_color(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    if os.getenv("NO_COLOR") is not None:
        return False
    if os.getenv("CTHULHU_COLOR", "").lower() in ("1", "true", "always"):
        return True
    if os.getenv("TERM", "") == "dumb":
        return False
    return _is_terminal(stream)


COLOR = _supports_color()

#: Whether we can address the screen (clear it, move the cursor).
#:
#: Deliberately independent of COLOR. NO_COLOR asks for plain text, not for a
#: broken full-screen interface, and a terminal that cannot render truecolour
#: can still clear itself. Tying the two together made every menu screen
#: append to the last one instead of replacing it.
INTERACTIVE = _is_terminal() and os.getenv("TERM", "") != "dumb"


class _Palette:
    """256/truecolor SGR codes, blanked out when colour is unavailable."""

    def __init__(self, enabled: bool) -> None:
        def c(code: str) -> str:
            return code if enabled else ""

        self.reset = c("\033[0m")
        self.bold = c("\033[1m")
        self.dim = c("\033[2m")
        self.italic = c("\033[3m")
        self.under = c("\033[4m")

        self.accent = c("\033[38;2;94;234;212m")    # teal
        self.accent_dim = c("\033[38;2;45;150;140m")
        self.text = c("\033[38;2;229;231;235m")     # near-white
        self.muted = c("\033[38;2;148;163;184m")    # slate
        self.faint = c("\033[38;2;85;95;110m")      # rule / chrome
        self.danger = c("\033[38;2;248;113;113m")   # red
        self.warn = c("\033[38;2;251;191;36m")      # amber
        self.ok = c("\033[38;2;74;222;128m")        # green
        self.info = c("\033[38;2;125;211;252m")     # sky
        self.violet = c("\033[38;2;167;139;250m")


P = _Palette(COLOR)

_ANSI_RE = re.compile(r"\033\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    """Display width, ignoring escapes and counting wide glyphs as two."""
    plain = strip_ansi(text)
    width = 0
    for ch in plain:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def term_width(default: int = 100) -> int:
    try:
        return max(60, min(shutil.get_terminal_size((default, 24)).columns, 200))
    except OSError:
        return default


def pad(text: str, width: int, align: str = "left") -> str:
    gap = width - visible_len(text)
    if gap <= 0:
        return text
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def truncate(text: Any, width: int, ellipsis: str = "…") -> str:
    text = "" if text is None else str(text)
    text = text.replace("\n", " ").replace("\t", " ")
    if visible_len(text) <= width:
        return text
    if width <= 1:
        return ellipsis[:width]
    out: List[str] = []
    used = 0
    for ch in strip_ansi(text):
        step = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + step > width - 1:
            break
        out.append(ch)
        used += step
    return "".join(out) + ellipsis


# --------------------------------------------------------------------------
# Severity styling
# --------------------------------------------------------------------------

_SEV_STYLE = {
    "critical": (P.danger, "●", "CRIT"),
    "high":     (P.danger, "●", "HIGH"),
    "medium":   (P.warn,   "●", "MED "),
    "low":      (P.info,   "●", "LOW "),
    "info":     (P.muted,  "○", "INFO"),
}


def severity_color(sev: str) -> str:
    return _SEV_STYLE.get(str(sev).lower(), (P.muted, "·", "?"))[0]


def severity_dot(sev: str) -> str:
    color, glyph, _ = _SEV_STYLE.get(str(sev).lower(), (P.muted, "·", "?"))
    return f"{color}{glyph}{P.reset}"


def severity_tag(sev: str) -> str:
    color, _, label = _SEV_STYLE.get(str(sev).lower(), (P.muted, "·", "????"))
    return f"{color}{label}{P.reset}"


# --------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------

GLYPH = {
    "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯",
    "h": "─", "v": "│", "dot": "·", "arrow": "→", "bullet": "▸",
}


def rule_line(width: Optional[int] = None, char: str = "─") -> str:
    width = width or term_width()
    return f"{P.faint}{char * width}{P.reset}"


def heading(title: str, subtitle: str = "", width: Optional[int] = None) -> str:
    """A thin titled rule:  ── TITLE ─────────────────  subtitle"""
    width = width or term_width()
    left = f"{P.faint}──{P.reset} {P.accent}{P.bold}{title}{P.reset} "
    used = visible_len(left)
    tail = ""
    if subtitle:
        tail = f" {P.muted}{subtitle}{P.reset}"
    fill = max(0, width - used - visible_len(tail))
    return f"{left}{P.faint}{'─' * fill}{P.reset}{tail}"


def panel(title: str, rows: Sequence[Tuple[str, Any]],
          width: Optional[int] = None, key_width: int = 16) -> str:
    """A labelled block of key/value pairs with a soft left border."""
    width = width or term_width()
    lines = [heading(title, width=width), ""]
    for key, value in rows:
        if value is None or value == "":
            continue
        label = f"{P.muted}{pad(str(key), key_width)}{P.reset}"
        text = str(value)
        avail = width - key_width - 4
        if visible_len(text) <= avail:
            lines.append(f"  {label}{P.text}{text}{P.reset}")
        else:
            # wrap continuation lines under the value column
            words = text.split(" ")
            current = ""
            chunks: List[str] = []
            for word in words:
                if visible_len(current) + visible_len(word) + 1 > avail:
                    if current:
                        chunks.append(current)
                    current = word
                else:
                    current = f"{current} {word}".strip()
            if current:
                chunks.append(current)
            lines.append(f"  {label}{P.text}{chunks[0]}{P.reset}")
            for chunk in chunks[1:]:
                lines.append(f"  {' ' * key_width}{P.text}{chunk}{P.reset}")
    lines.append("")
    return "\n".join(lines)


def table(headers: Sequence[str], rows: Sequence[Sequence[Any]],
          aligns: Optional[Sequence[str]] = None,
          width: Optional[int] = None, max_widths: Optional[Sequence[int]] = None) -> str:
    """Column-aligned table that shrinks the widest column to fit."""
    width = width or term_width()
    aligns = aligns or ["left"] * len(headers)
    cells = [[("" if c is None else str(c)) for c in row] for row in rows]

    widths = [visible_len(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row[:len(widths)]):
            widths[i] = max(widths[i], visible_len(cell))
    if max_widths:
        widths = [min(w, m) if m else w for w, m in zip(widths, max_widths)]

    gap = 2
    total = sum(widths) + gap * (len(widths) - 1)
    if total > width and widths:
        # shave the widest column until it fits
        overflow = total - width
        order = sorted(range(len(widths)), key=lambda i: widths[i], reverse=True)
        for idx in order:
            if overflow <= 0:
                break
            shave = min(overflow, max(0, widths[idx] - 8))
            widths[idx] -= shave
            overflow -= shave

    out = [
        (" " * gap).join(
            f"{P.faint}{pad(truncate(h, w), w, a)}{P.reset}"
            for h, w, a in zip(headers, widths, aligns))
    ]
    for row in cells:
        out.append((" " * gap).join(
            f"{pad(truncate(c, w), w, a)}"
            for c, w, a in zip(row, widths, aligns)))
    return "\n".join(out)


def banner(subtitle: str = "", version: str = "2.0") -> str:
    """Compact wordmark. Deliberately small — it appears on every screen."""
    return (
        f"\n  {P.accent}{P.bold}^(;,;)^{P.reset}  "
        f"{P.text}{P.bold}CTHULHU{P.reset} {P.faint}SIEM v{version}{P.reset}"
        + (f"   {P.faint}{GLYPH['dot']}{P.reset}  {P.muted}{subtitle}{P.reset}"
           if subtitle else "")
        + "\n"
    )


def kv_inline(pairs: Iterable[Tuple[str, Any]], sep: str = "   ") -> str:
    parts = [f"{P.muted}{k}{P.reset} {P.text}{v}{P.reset}"
             for k, v in pairs if v not in (None, "")]
    return sep.join(parts)


def hint(text: str) -> str:
    return f"  {P.faint}{text}{P.reset}"


def status(kind: str, message: str) -> str:
    marks = {
        "ok": (P.ok, "✓"), "warn": (P.warn, "!"), "err": (P.danger, "✗"),
        "info": (P.accent, "›"), "wait": (P.muted, "·"),
    }
    color, glyph = marks.get(kind, (P.muted, "·"))
    return f"  {color}{glyph}{P.reset} {P.text}{message}{P.reset}"


def clear() -> None:
    """Clear the screen, the scrollback, and home the cursor.

    ``2J`` alone clears only the visible screen, which leaves the previous
    page sitting in scrollback and makes consecutive views look like they
    are stacking. ``3J`` drops the saved lines too.
    """
    if not INTERACTIVE:
        return
    try:
        sys.stdout.write("\033[H\033[2J\033[3J")
        sys.stdout.flush()
    except OSError:
        # Terminal that rejects the escape sequence: fall back to terminfo.
        os.system("clear" if os.name != "nt" else "cls")


def hide_cursor() -> None:
    if INTERACTIVE:
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()


def show_cursor() -> None:
    if INTERACTIVE:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
