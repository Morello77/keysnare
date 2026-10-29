"""Command-line interface: `keysnare scan` and `keysnare trap`."""

import argparse
import io
import os
import sys
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from keysnare import __version__
from keysnare.json_report import render_json
from keysnare.report import ReportContext
from keysnare.risk import Severity
from keysnare.sarif_report import render_sarif
from keysnare.scanner import scan
from keysnare.terminal import (
    ProgressLine,
    enable_windows_colors,
    render_summary,
    render_text,
    use_color,
)
from keysnare.trap.commands import (
    TrapDeps,
    run_alert,
    run_install,
    run_remove,
    run_status,
    run_test,
)
from keysnare.trap.manager import TrapPaths
from keysnare.trap.placement import gather_machine
from keysnare.trap.state import STATE_FILE_NAME, data_dir, load_state
from keysnare.trap.windows import is_elevated, is_windows

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

EXIT_CODES_HELP = """\
exit codes:
  0  no findings at or above the --fail-on level
  1  findings at or above the --fail-on level
  2  error (invalid arguments, missing path, or the scan failed)
"""


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for the keysnare command."""
    parser = argparse.ArgumentParser(
        prog="keysnare",
        description="Find plain-text credentials that credential-stealing malware would grab.",
    )
    parser.add_argument("--version", action="version", version=f"keysnare {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser(
        "scan",
        help="scan for plain-text credentials",
        description="Scan your home folder, or PATH, for plain-text credentials. "
        "Runs fully offline. Secrets are always masked.",
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument(
        "path", nargs="?", type=Path, help="folder or file to scan (default: your home folder)"
    )
    output = scan_parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print a JSON report")
    output.add_argument("--sarif", action="store_true", help="print a SARIF 2.1.0 report")
    output.add_argument("--quiet", action="store_true", help="print only the summary line")
    scan_parser.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        default=Severity.HIGH.value,
        help="lowest severity that makes the exit code 1 (default: high)",
    )
    scan_parser.add_argument(
        "--show-full-paths",
        action="store_true",
        help="show full paths instead of ~ for your home folder",
    )
    scan_parser.add_argument(
        "--output",
        metavar="FILE",
        type=Path,
        help="write the report to FILE (UTF-8 without BOM) instead of the screen",
    )
    _add_trap_parser(commands)
    return parser


def _add_trap_parser(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    trap_parser = commands.add_parser(
        "trap",
        help="decoy credentials that alert when read (Windows)",
        description="Plant fake, clearly marked credentials and get a Windows notification "
        "when a program reads one. See docs/design-traps.md.",
    )
    actions = trap_parser.add_subparsers(dest="action", required=True)
    install = actions.add_parser("install", help="plant decoys and register the alert task")
    install.add_argument("--yes", action="store_true", help="do not ask questions (for CI)")
    actions.add_parser("status", help="show decoys, the alert task and recent alerts")
    actions.add_parser("test", help="simulate a theft to check that alerts work")
    remove = actions.add_parser("remove", help="undo everything trap install did")
    remove.add_argument("--purge", action="store_true", help="also delete the alert history")
    actions.add_parser("alert", help=argparse.SUPPRESS)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the exit code."""
    args = build_parser().parse_args(argv)
    _use_utf8_output()
    if is_elevated():
        print(
            "keysnare: error: KeySnare refuses to run as administrator, so that its own code "
            "never runs elevated. Run it from a normal terminal.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    try:
        if args.command == "trap":
            return _trap_command(args)
        return _scan_command(args)
    except Exception as error:
        # CI relies on exit code 2 for any failure, so no exception may escape as a traceback.
        print(f"keysnare: error: {error}", file=sys.stderr)
        return EXIT_ERROR


def _trap_command(args: argparse.Namespace) -> int:
    if not is_windows():
        print("keysnare: error: traps are Windows-only in this version.", file=sys.stderr)
        return EXIT_ERROR
    deps = _windows_trap_deps()
    if args.action == "install":
        return run_install(deps, yes=args.yes)
    if args.action == "status":
        return run_status(deps)
    if args.action == "test":
        return run_test(deps)
    if args.action == "remove":
        return run_remove(deps, purge=args.purge)
    return run_alert(deps)


def _windows_trap_deps() -> TrapDeps:
    from keysnare.trap import windows

    home = Path.home()
    folder = data_dir(os.environ)
    return TrapDeps(
        system=windows.WindowsSystem(),
        paths=TrapPaths(
            home=home, data_dir=folder, store_data_dir=windows.store_python_data_dir(folder)
        ),
        machine=lambda: gather_machine(home, os.environ),
        handler=windows.handler_path(),
        protected_dirs=windows.protected_dirs,
        path_forms=windows.path_forms,
        notify=windows.notify,
        now=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ask=input,
        out=sys.stdout,
        read_export=windows.read_export,
        start_reader=windows.start_reader,
        sleep=time.sleep,
        monotonic=time.monotonic,
    )


def shows_progress(args: argparse.Namespace, stream: TextIO) -> bool:
    """Show the progress line only to a person at a terminal, never in machine output."""
    return stream.isatty() and not (args.quiet or args.json or args.sarif)


def _installed_decoys() -> list[Path]:
    if not is_windows():
        return []
    try:
        state = load_state(data_dir(os.environ) / STATE_FILE_NAME)
    except ValueError:
        return []
    return [record.path for record in state.decoys] if state else []


def _scan_command(args: argparse.Namespace) -> int:
    root: Path | None = args.path.absolute() if args.path else None
    if root is not None and not root.exists():
        print(f"keysnare: error: {args.path} does not exist", file=sys.stderr)
        return EXIT_ERROR
    started = time.perf_counter()
    progress = ProgressLine(sys.stderr) if shows_progress(args, sys.stderr) else None
    try:
        result = scan(root, decoys=_installed_decoys(), progress=progress)
    finally:
        if progress:
            progress.clear()
    context = ReportContext(
        result, time.perf_counter() - started, Path.home(), args.show_full_paths
    )
    report = _render(args, context)
    if args.output:
        try:
            args.output.write_text(report, encoding="utf-8", newline="\n")
        except OSError as error:
            print(
                f"keysnare: error: could not write {args.output}: {error.strerror}", file=sys.stderr
            )
            return EXIT_ERROR
    else:
        sys.stdout.write(report)
    highest = context.highest_severity
    fails = highest is not None and highest <= Severity(args.fail_on)
    return EXIT_FINDINGS if fails else EXIT_OK


def _render(args: argparse.Namespace, context: ReportContext) -> str:
    if args.json:
        return render_json(context)
    if args.sarif:
        return render_sarif(context)
    if args.quiet:
        return render_summary(context) + "\n"
    color = not args.output and use_color(sys.stdout, os.environ) and enable_windows_colors()
    return render_text(context, color)


def _use_utf8_output() -> None:
    # Redirected output on Windows defaults to a legacy code page that cannot encode every
    # character in the report, such as the arrows in fix steps.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")
