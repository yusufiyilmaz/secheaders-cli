"""Turn scan results into terminal text or JSON."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict

from .scanner import Result

ICONS = {"pass": "✔", "warn": "!", "fail": "✘", "info": "i"}
COLORS = {"pass": "32", "warn": "33", "fail": "31", "info": "36"}
GRADE_COLORS = {"A+": "32", "A": "32", "B": "33", "C": "33", "D": "31", "F": "31"}


def _enable_windows_ansi() -> bool:
    """Classic Windows consoles need ANSI color codes switched on explicitly."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        return False


def use_color(stream=sys.stdout) -> bool:
    if not stream.isatty() or "NO_COLOR" in os.environ:
        return False
    return _enable_windows_ansi() if os.name == "nt" else True


def _c(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def to_text(r: Result, color: bool = False) -> str:
    lines = [
        _c(f"secheaders · {r.url}", "1", color),
        f"  final URL : {r.final_url}  (HTTP {r.status}, {r.elapsed:.2f}s)",
        f"  grade     : {_c(r.grade, '1;' + GRADE_COLORS[r.grade], color)}  ({r.score}/100)",
        "",
    ]
    width = max(len(f.check) for f in r.findings)
    for f in r.findings:
        icon = _c(ICONS[f.status], COLORS[f.status], color)
        sev = f" [{f.severity}]" if f.status in ("warn", "fail") else ""
        lines.append(f"  {icon} {f.check.ljust(width)}  {f.message}{_c(sev, '2', color)}")
        if f.fix and f.status != "pass":
            lines.append(f"    {' ' * width}  {_c('→ ' + f.fix, '2', color)}")
    counts = {s: sum(f.status == s for f in r.findings) for s in ("pass", "warn", "fail")}
    lines += ["", f"  {counts['pass']} passed · {counts['warn']} warnings · {counts['fail']} failed"]
    return "\n".join(lines)


def to_json(results: list[Result]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False)
