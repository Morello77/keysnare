"""The `keysnare trap` commands: what they print and ask. The work happens in manager.py."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from keysnare.report import display_path
from keysnare.trap.admin import AUDIT_RESTORE_COMMANDS, REMOVAL_COMMANDS, render_setup_commands
from keysnare.trap.alert import TEST_PID_FILE, Notifier, ProtectedDirs, handle_export
from keysnare.trap.manager import (
    RemoveResult,
    TrapError,
    TrapPaths,
    TrapSystem,
    install,
    prepare_install,
    read_alerts,
    record_audit_before,
    remove,
    status,
)
from keysnare.trap.placement import Machine
from keysnare.trap.state import AuditBefore, load_state
from keysnare.trap.task import TASK_NAME
from keysnare.winpath import PathForms

EXIT_OK = 0
EXIT_DECLINED = 1
EXIT_ERROR = 2
# Two scheduled tasks run in sequence (the SYSTEM relay, then the user's handler).
TEST_TIMEOUT_SECONDS = 60
TEST_POLL_SECONDS = 1.0

AUDIT_CHOICES = {
    "1": AuditBefore.NO_AUDITING,
    "2": AuditBefore.SUCCESS,
    "3": AuditBefore.FAILURE,
    "4": AuditBefore.SUCCESS_AND_FAILURE,
    "5": AuditBefore.UNKNOWN,
}
AUDIT_QUESTION = """
After running the commands: what did the first command show next to "File System"?
  1  No Auditing
  2  Success
  3  Failure
  4  Success and Failure
  5  Not sure
Answer [5]: """
STORE_PYTHON_WARNING = """
Note: this Python is the Microsoft Store version. Windows keeps the files it writes under
AppData in a private folder, so KeySnare's trap records and alert history will be in:
  {folder}
Uninstalling or resetting that Python deletes this folder. `keysnare trap remove` could then
only list the decoys for you to delete by hand. The python.org installer avoids this."""
OPEN_ADMIN_POWERSHELL = """\
  1. Press Win+R and type: powershell -NoProfile
  2. Press Ctrl+Shift+Enter to open it as administrator.
  3. Check the commands match the template in docs/usage.md, then paste them."""
CHECK_AUDIT_COMMAND = (
    "& ([Environment]::SystemDirectory + '\\auditpol.exe') /get "
    "/subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}'"
)


@dataclass
class TrapDeps:
    """Everything the trap commands use from the outside world, so tests can replace it."""

    system: TrapSystem
    paths: TrapPaths
    machine: Callable[[], Machine]
    handler: Path
    protected_dirs: Callable[[], ProtectedDirs]
    path_forms: Callable[[], PathForms]
    notify: Notifier
    now: Callable[[], str]
    ask: Callable[[str], str]
    out: TextIO
    read_export: Callable[[], str]
    start_reader: Callable[[Path], int]
    sleep: Callable[[float], None]
    monotonic: Callable[[], float]


def run_install(deps: TrapDeps, yes: bool) -> int:
    """`keysnare trap install`."""
    try:
        plan = prepare_install(deps.system, deps.machine(), deps.paths)
    except TrapError as error:
        return _fail(deps, error)
    _say(deps, "KeySnare will create these decoys (fake, clearly marked credentials):")
    for decoy in plan.decoys:
        _say(deps, f"  {_show(deps, decoy.path)}  ({decoy.reason})")
    if plan.skipped:
        _say(deps, "Not used:")
        for skipped in plan.skipped:
            _say(deps, f"  {_show(deps, skipped.path)}  ({skipped.reason})")
    _say(deps, "It will also:")
    _say(deps, '  - mark each decoy "not content indexed", so Windows Search skips it')
    _say(deps, f"  - register the scheduled task {TASK_NAME} (runs as you, without admin rights)")
    _say(deps, f"  - keep its records in {_records_folder(deps)}")
    _say(deps, "Nothing else is changed. `keysnare trap remove` undoes all of it.")
    if deps.paths.store_data_dir is not None:
        _say(deps, STORE_PYTHON_WARNING.format(folder=_records_folder(deps)))
    if not yes and deps.ask("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
        _say(deps, "Nothing was changed.")
        return EXIT_DECLINED
    try:
        state = install(deps.system, plan, deps.paths, deps.handler, deps.now())
    except TrapError as error:
        return _fail(deps, error)
    _say(deps, f"\nCreated {len(state.decoys)} decoys and the alert task.")
    _say(deps, "\nOne step needs administrator rights, and you run it yourself:")
    _say(deps, OPEN_ADMIN_POWERSHELL + "\n")
    deps.out.write(render_setup_commands([record.path for record in state.decoys]))
    answer = AuditBefore.UNKNOWN if yes else _ask_audit_before(deps)
    record_audit_before(deps.paths, answer)
    _say(deps, "\nThen prove it works: run `keysnare trap test`.")
    return EXIT_OK


def run_status(deps: TrapDeps) -> int:
    """`keysnare trap status`. Read-only."""
    report = status(deps.system, deps.paths)
    if not report.installed:
        _say(deps, "Traps are not installed. Run `keysnare trap install`.")
        return EXIT_OK
    _say(deps, f"Records: {_records_folder(deps)}")
    _say(deps, "Decoys:")
    for path, decoy_status in report.decoys.items():
        _say(deps, f"  {_show(deps, path)}: {decoy_status}")
    _say(deps, f"Alert task: {report.task_status or 'missing'}")
    before = report.audit_before.value if report.audit_before else "unknown"
    _say(deps, f'"File System" auditing before install: {before}')
    _say(deps, "Audit settings need admin rights to read; `keysnare trap test` checks them.")
    if report.recent_alerts:
        _say(deps, "Recent alerts:")
        for alert in report.recent_alerts:
            test = " (test)" if alert.get("test") else ""
            _say(deps, f"  {alert.get('time')}  {alert.get('process')}{test}")
    return EXIT_OK


def run_remove(deps: TrapDeps, purge: bool) -> int:
    """`keysnare trap remove`."""
    if deps.system.is_elevated():
        return _fail(deps, TrapError("KeySnare refuses to run as administrator."))
    result = remove(deps.system, deps.paths, purge)
    _report_removal(deps, result)
    return EXIT_OK


def run_test(deps: TrapDeps) -> int:
    """`keysnare trap test`: another program reads a decoy; KeySnare waits for the alert."""
    state = load_state(deps.paths.state_file)
    if state is None:
        return _fail(deps, TrapError("Traps are not installed. Run `keysnare trap install`."))
    decoy = state.decoys[0].path
    alerts_before = len(read_alerts(deps.paths))
    _say(deps, f"Simulating a theft: a separate program reads {_show(deps, decoy)} ...")
    pid_file = deps.paths.data_dir / TEST_PID_FILE
    pid_file.write_text(str(deps.start_reader(decoy)), encoding="ascii")
    deadline = deps.monotonic() + TEST_TIMEOUT_SECONDS
    try:
        while deps.monotonic() < deadline:
            if any(alert.get("test") for alert in read_alerts(deps.paths)[alerts_before:]):
                _say(deps, "Test alert received. You should also have seen a notification.")
                return EXIT_OK
            deps.sleep(TEST_POLL_SECONDS)
    finally:
        pid_file.unlink(missing_ok=True)
    _say(deps, f"No alert within {TEST_TIMEOUT_SECONDS} seconds. Most likely causes:")
    _say(deps, "  - the admin commands printed by `keysnare trap install` were not run yet;")
    _say(deps, "  - a company policy overrides the local audit setting;")
    _say(deps, "  - the alert task is missing or disabled (see `keysnare trap status`).")
    return EXIT_DECLINED


def run_alert(deps: TrapDeps) -> int:
    """`keysnare trap alert`, started by the alert task after the SYSTEM relay exported events."""
    handle_export(
        deps.read_export(),
        deps.paths,
        deps.protected_dirs(),
        deps.notify,
        deps.now(),
        deps.path_forms(),
    )
    return EXIT_OK


def _ask_audit_before(deps: TrapDeps) -> AuditBefore:
    return AUDIT_CHOICES.get(deps.ask(AUDIT_QUESTION).strip(), AuditBefore.UNKNOWN)


def _report_removal(deps: TrapDeps, result: RemoveResult) -> None:
    _say(deps, f"Deleted {len(result.deleted)} decoys.")
    for path in result.kept_changed:
        _say(deps, f"  Kept {_show(deps, path)}: it was changed after install.")
    for folder in result.kept_folders:
        _say(deps, f"  Kept folder {_show(deps, folder)}: it is not empty.")
    if result.unverified:
        _say(deps, "No trap records were found. These files may be KeySnare decoys, but KeySnare")
        _say(deps, "cannot confirm it without reading them, so they were left in place.")
        _say(deps, "Delete them yourself if you do not use them:")
        for path in result.unverified:
            _say(deps, f"  {_show(deps, path)}")
    _say(deps, "Alert task deleted." if result.task_deleted else "No alert task was registered.")
    if result.kept_alerts:
        _say(deps, f"Your alert history was kept: {deps.paths.real_location(result.kept_alerts)}")
    _say(deps, "\nTo finish, remove the admin parts (the SYSTEM relay task, the event source and")
    _say(deps, "C:\\ProgramData\\KeySnare) with these commands:")
    _say(deps, OPEN_ADMIN_POWERSHELL + "\n")
    deps.out.write(REMOVAL_COMMANDS)
    if result.audit_restore_needed:
        _say(deps, '\n"File System" auditing was off before. To turn it off again:\n')
        deps.out.write(AUDIT_RESTORE_COMMANDS)
    elif result.audit_restore_needed is None:
        _say(deps, '\nKeySnare does not know whether "File System" auditing was on before.')
        _say(deps, f"To see the current setting, run as administrator: {CHECK_AUDIT_COMMAND}")
        _say(deps, "If it was off before you installed traps, turn it off again with:\n")
        deps.out.write(AUDIT_RESTORE_COMMANDS)
    else:
        _say(deps, '"File System" auditing was already on before install, so it stays on.')


def _records_folder(deps: TrapDeps) -> str:
    return _show(deps, deps.paths.real_location(deps.paths.data_dir))


def _show(deps: TrapDeps, path: Path) -> str:
    return display_path(path, deps.paths.home, show_full_paths=False)


def _say(deps: TrapDeps, text: str) -> None:
    deps.out.write(text + "\n")


def _fail(deps: TrapDeps, error: TrapError) -> int:
    _say(deps, f"keysnare: {error}")
    return EXIT_ERROR
