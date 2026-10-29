import io
from pathlib import Path

import pytest

from keysnare.locations import Category
from keysnare.report import ReportContext
from keysnare.scanner import Finding, ScanResult, SkippedPath
from keysnare.terminal import ProgressLine, render_summary, render_text, use_color

HOME = Path.home()
SECRET = "fake" + "Secret" + "Value123"
ANSI = "\x1b["


def context(findings: list[Finding], skipped: list[SkippedPath] | None = None) -> ReportContext:
    result = ScanResult(findings, [HOME / ".npmrc"] * 12, skipped or [], "windows")
    return ReportContext(result, 8.04, HOME, show_full_paths=False)


FINDINGS = [
    Finding("K-SECRET-NAME", Category.ENV_FILE, HOME / "app" / ".env", 3, SECRET),
    Finding("S-SSH-KEY", Category.SSH_KEY, HOME / ".ssh" / "id_rsa", 1),
    Finding("S-CLAUDE-OAUTH", Category.CLAUDE_CODE, HOME / ".claude" / "c.json", 1, SECRET),
    Finding("S-CLAUDE-OAUTH", Category.CLAUDE_CODE, HOME / ".claude" / "c.json", 2, SECRET),
]


def test_summary_comes_first_with_counts_time_and_files() -> None:
    lines = render_text(context(FINDINGS), color=False).splitlines()

    assert lines[0].startswith("KeySnare ")
    assert lines[1] == (
        "4 findings (1 critical, 2 high, 0 medium, 1 low) in 12 files checked, scanned in 8.0s"
    )


def test_findings_are_grouped_most_severe_first() -> None:
    text = render_text(context(FINDINGS), color=False)

    assert text.index("CRITICAL") < text.index("HIGH") < text.index("LOW")
    assert text.count("Claude Code login") == 1


def test_each_finding_shows_home_relative_path_line_and_masked_value() -> None:
    text = render_text(context(FINDINGS), color=False)

    assert f"{Path('~') / 'app' / '.env'}:3  fake****e123" in text
    assert str(HOME) not in text


def test_explanation_and_platform_fix_are_shown() -> None:
    unwrapped = " ".join(render_text(context(FINDINGS), color=False).split())

    assert "Why: Anyone who copies this file" in unwrapped
    assert "Start-Service ssh-agent" in unwrapped


def test_no_findings_message() -> None:
    text = render_text(context([]), color=False)

    assert "No plain-text credentials found in 12 files checked, scanned in 8.0s" in text


def test_skipped_paths_are_counted_and_listed() -> None:
    skipped = [SkippedPath(HOME / "locked", "could not read: Permission denied")]

    text = render_text(context([], skipped), color=False)

    assert "1 path skipped" in text
    assert f"{Path('~') / 'locked'}  could not read: Permission denied" in text


def test_quiet_summary_is_one_line() -> None:
    summary = render_summary(context(FINDINGS))

    assert "\n" not in summary
    assert summary.startswith("4 findings")


def test_colors_only_when_requested() -> None:
    assert ANSI not in render_text(context(FINDINGS), color=False)
    assert ANSI in render_text(context(FINDINGS), color=True)


def test_progress_line_updates_at_most_ten_times_a_second() -> None:
    stream = io.StringIO()
    times = iter([0.0, 0.05, 0.2, 0.25, 0.4])
    progress = ProgressLine(stream, clock=lambda: next(times))

    for folders in (1, 2, 3, 4, 5):
        progress(folders)

    assert stream.getvalue() == (
        "\rScanning... 1 folders" "\rScanning... 3 folders" "\rScanning... 5 folders"
    )


def test_progress_line_is_cleared_when_done() -> None:
    stream = io.StringIO()
    progress = ProgressLine(stream, clock=lambda: 1.0)
    progress(12345)

    progress.clear()

    assert stream.getvalue().endswith("\r" + " " * len("Scanning... 12,345 folders") + "\r")


def test_clearing_an_unused_progress_line_writes_nothing() -> None:
    stream = io.StringIO()

    ProgressLine(stream).clear()

    assert stream.getvalue() == ""


class FakeStream(io.StringIO):
    def __init__(self, is_terminal: bool) -> None:
        super().__init__()
        self.is_terminal = is_terminal

    def isatty(self) -> bool:
        return self.is_terminal


@pytest.mark.parametrize(
    ("is_terminal", "env", "expected"),
    [
        (True, {}, True),
        (False, {}, False),
        (True, {"NO_COLOR": "1"}, False),
        (True, {"NO_COLOR": ""}, True),
    ],
)
def test_use_color(is_terminal: bool, env: dict[str, str], expected: bool) -> None:
    assert use_color(FakeStream(is_terminal), env) is expected
