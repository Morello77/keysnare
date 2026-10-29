"""Human-readable terminal report."""

import sys
import textwrap
import time
from collections.abc import Callable, Mapping
from typing import TextIO

from keysnare import __version__
from keysnare.guidance import fix_for
from keysnare.report import FindingGroup, ReportContext, display_masked
from keysnare.risk import Severity

WIDTH = 100
PROGRESS_INTERVAL_SECONDS = 0.1
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
SEVERITY_COLORS = {
    Severity.CRITICAL: "\x1b[1;31m",
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
}


def use_color(stream: TextIO, env: Mapping[str, str]) -> bool:
    """Use color only in a real terminal, and never when NO_COLOR is set (no-color.org)."""
    return stream.isatty() and not env.get("NO_COLOR")


def enable_windows_colors() -> bool:
    """Turn on ANSI color support in a Windows console. Returns False if that is not possible."""
    if sys.platform != "win32":
        return True
    import ctypes

    kernel32 = ctypes.windll.kernel32
    std_output_handle = -11
    enable_virtual_terminal_processing = 0x0004
    handle = kernel32.GetStdHandle(std_output_handle)
    mode = ctypes.c_uint32()
    if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        return False
    return bool(kernel32.SetConsoleMode(handle, mode.value | enable_virtual_terminal_processing))


class ProgressLine:
    """A one-line folder count on stderr, redrawn in place at most ten times a second."""

    def __init__(self, stream: TextIO, clock: Callable[[], float] = time.monotonic) -> None:
        self.stream = stream
        self.clock = clock
        self.last_drawn: float | None = None
        self.width = 0

    def __call__(self, folders: int) -> None:
        now = self.clock()
        if self.last_drawn is not None and now - self.last_drawn < PROGRESS_INTERVAL_SECONDS:
            return
        text = f"Scanning... {folders:,} folders"
        self.stream.write("\r" + text)
        self.stream.flush()
        self.last_drawn = now
        self.width = max(self.width, len(text))

    def clear(self) -> None:
        """Erase the line so the report starts on a clean line."""
        if self.width:
            self.stream.write("\r" + " " * self.width + "\r")
            self.stream.flush()


def render_summary(context: ReportContext) -> str:
    """Return one line: counts per severity, files checked, scan time and skipped paths."""
    result = context.result
    scanned = (
        f"in {len(result.files_checked)} files checked, "
        f"scanned in {context.duration_seconds:.1f}s"
    )
    if result.findings:
        counts = ", ".join(f"{n} {severity.value}" for severity, n in context.counts.items())
        noun = "finding" if len(result.findings) == 1 else "findings"
        line = f"{len(result.findings)} {noun} ({counts}) {scanned}"
    else:
        line = f"No plain-text credentials found {scanned}"
    if result.skipped:
        noun = "path" if len(result.skipped) == 1 else "paths"
        line += f"; {len(result.skipped)} {noun} skipped"
    return line


def render_text(context: ReportContext, color: bool) -> str:
    """Return the full report: summary, findings grouped by severity, skipped paths."""
    style = _Style(color)
    lines = [style.bold(f"KeySnare {__version__}"), render_summary(context)]
    current: Severity | None = None
    for group in context.groups:
        if group.severity is not current:
            current = group.severity
            lines += ["", style.severity(current, current.value.upper())]
        lines += _render_group(group, context, style)
    if context.result.skipped:
        lines += ["", style.bold(f"Skipped ({len(context.result.skipped)})")]
        lines += [f"  {context.path(s.path)}  {s.reason}" for s in context.result.skipped]
    return "\n".join(lines) + "\n"


def _render_group(group: FindingGroup, context: ReportContext, style: "_Style") -> list[str]:
    count = len(group.findings)
    lines = ["", f"  {style.bold(group.risk.title)} [{group.rule_id}] - {count} found"]
    for finding in group.findings:
        location = context.path(finding.path)
        if finding.line is not None:
            location += f":{finding.line}"
        masked = display_masked(finding)
        lines.append(f"    {location}  {masked}" if masked else f"    {location}")
    lines += _wrap(f"Why: {group.risk.why}", "    ", "         ")
    lines.append("    How to fix:")
    for number, step in enumerate(fix_for(group.rule_id, context.result.platform), start=1):
        lines += _wrap(f"{number}. {step}", "      ", "         ")
    return [style.dim(line) if line.lstrip().startswith("Why:") else line for line in lines]


def _wrap(text: str, first_indent: str, next_indent: str) -> list[str]:
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=first_indent,
        subsequent_indent=next_indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _apply(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._apply(BOLD, text)

    def dim(self, text: str) -> str:
        return self._apply(DIM, text)

    def severity(self, severity: Severity, text: str) -> str:
        return self._apply(SEVERITY_COLORS[severity], text)
