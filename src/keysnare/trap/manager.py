"""Install, inspect and remove traps. Never elevated; every change is recorded and reversible."""

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from keysnare.report import display_path
from keysnare.trap.decoys import make_decoy
from keysnare.trap.identity import file_identity
from keysnare.trap.placement import (
    GCLOUD_ADC,
    GH_HOSTS,
    GIT_CREDENTIALS,
    SIBLINGS,
    STANDARD,
    DecoyPlan,
    Machine,
    plan_decoys,
)
from keysnare.trap.state import (
    STATE_FILE_NAME,
    AuditBefore,
    DecoyRecord,
    TrapState,
    load_state,
    save_state,
)
from keysnare.trap.task import build_task_xml

RECENT_ALERTS = 5


class TrapError(Exception):
    """A problem the user can act on, explained in plain English."""


class TrapSystem(Protocol):
    """The Windows operations traps need, kept apart so the logic can be tested anywhere."""

    def is_elevated(self) -> bool: ...
    def user_sid(self) -> str: ...
    def mark_not_indexed(self, path: Path) -> None: ...
    def register_task(self, xml: str) -> None: ...
    def delete_task(self) -> bool: ...
    def task_status(self) -> str | None: ...


@dataclass(frozen=True)
class TrapPaths:
    """Where traps live: the user's home folder and KeySnare's data folder."""

    home: Path
    data_dir: Path
    # Set when Microsoft Store Python keeps data_dir in its private per-package folder instead.
    store_data_dir: Path | None = None

    @property
    def state_file(self) -> Path:
        return self.data_dir / STATE_FILE_NAME

    @property
    def alerts_file(self) -> Path:
        return self.data_dir / "alerts.jsonl"

    def real_location(self, path: Path) -> Path:
        """Return where a file in the data folder really is on disk, for messages to the user."""
        if self.store_data_dir is None:
            return path
        try:
            return self.store_data_dir / path.relative_to(self.data_dir)
        except ValueError:
            return path


@dataclass
class RemoveResult:
    """What `trap remove` did."""

    deleted: list[Path] = field(default_factory=list)
    kept_changed: list[Path] = field(default_factory=list)
    kept_folders: list[Path] = field(default_factory=list)
    task_deleted: bool = False
    kept_alerts: Path | None = None
    audit_restore_needed: bool | None = None
    # Without a state file, nothing proves these are KeySnare's decoys, so they are only reported.
    unverified: list[Path] = field(default_factory=list)


@dataclass(frozen=True)
class StatusReport:
    """What `trap status` found."""

    installed: bool
    decoys: dict[Path, str]
    task_status: str | None
    audit_before: AuditBefore | None
    recent_alerts: list[dict[str, Any]]


def prepare_install(system: TrapSystem, machine: Machine, paths: TrapPaths) -> DecoyPlan:
    """Check that install may run, and return the decoy plan to show the user."""
    if system.is_elevated():
        raise TrapError(
            "KeySnare refuses to run as administrator, so that its own code never runs elevated. "
            "Run `keysnare trap install` from a normal terminal; it prints the few admin "
            "commands for you to run yourself."
        )
    if paths.state_file.exists():
        raise TrapError("Traps are already installed. Run `keysnare trap remove` first.")
    plan = plan_decoys(machine)
    if not plan.decoys:
        raise TrapError("No safe place for a decoy was found on this machine.")
    return plan


def install(
    system: TrapSystem, plan: DecoyPlan, paths: TrapPaths, handler: Path, now: str
) -> TrapState:
    """Create the decoys, the state file and the alert task. Rolls back fully on any failure."""
    records: list[DecoyRecord] = []
    created_files: list[Path] = []
    created_folders: list[Path] = []
    step = "starting"
    try:
        for planned in plan.decoys:
            shown = display_path(planned.path, paths.home, show_full_paths=False)
            step = f"creating the folder for {shown}"
            created_folders += _make_folders(planned.path.parent)
            step = f"creating the decoy {shown}"
            data = make_decoy(planned.kind, planned.path).content.encode("utf-8")
            try:
                with open(planned.path, "xb") as decoy_file:
                    decoy_file.write(data)
            except FileExistsError as error:
                raise TrapError(
                    f"{shown} appeared while installing; it was left untouched."
                ) from error
            created_files.append(planned.path)
            step = f"marking {shown} as not content indexed"
            system.mark_not_indexed(planned.path)
            step = f"recording the file identity of {shown}"
            # Recorded last, so later checks compare against the finished file.
            identity = file_identity(planned.path)
            if identity is None:
                raise TrapError(f"{shown} disappeared while installing.")
            records.append(DecoyRecord(planned.kind, planned.path, identity))
        state = TrapState(tuple(records), tuple(created_folders), AuditBefore.UNKNOWN, now)
        step = "saving the trap records"
        save_state(state, paths.state_file)
        step = "registering the alert task with Task Scheduler"
        system.register_task(build_task_xml(handler, system.user_sid()))
    except (OSError, TrapError) as error:
        _undo(created_files, created_folders, paths)
        if isinstance(error, TrapError):
            raise
        raise TrapError(f"Install failed while {step}, and was rolled back: {error}") from error
    return state


def record_audit_before(paths: TrapPaths, answer: AuditBefore) -> None:
    """Save the user's answer about the audit setting before install."""
    state = load_state(paths.state_file)
    if state is None:
        raise TrapError("Traps are not installed.")
    save_state(replace(state, audit_before=answer), paths.state_file)


def remove(system: TrapSystem, paths: TrapPaths, purge: bool) -> RemoveResult:
    """Undo everything install did. Safe to run more than once."""
    try:
        state = load_state(paths.state_file)
    except ValueError:
        state = None
    result = RemoveResult()
    if state is not None:
        for record in state.decoys:
            _remove_decoy(record, result)
        for folder in reversed(state.created_folders):
            _remove_folder(folder, result)
        result.audit_restore_needed = state.audit_before.restore_needed
    else:
        result.unverified = [p for p in _candidate_paths(paths.home) if os.path.lexists(p)]
    result.task_deleted = system.delete_task()
    result.kept_alerts = _settle_alerts(paths, purge)
    paths.state_file.unlink(missing_ok=True)
    _remove_folder(paths.data_dir, RemoveResult())
    return result


def status(system: TrapSystem, paths: TrapPaths) -> StatusReport:
    """Read-only overview of the installed traps."""
    state = load_state(paths.state_file)
    decoys = {record.path: _decoy_status(record) for record in state.decoys} if state else {}
    return StatusReport(
        installed=state is not None,
        decoys=decoys,
        task_status=system.task_status(),
        audit_before=state.audit_before if state else None,
        recent_alerts=read_alerts(paths)[-RECENT_ALERTS:],
    )


def read_alerts(paths: TrapPaths) -> list[dict[str, Any]]:
    """Return the real alerts in the alert log, skipping other events and damaged lines."""
    try:
        lines = paths.alerts_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    alerts = []
    for line in lines:
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        if isinstance(alert, dict) and alert.get("kind") == "alert":
            alerts.append(alert)
    return alerts


def _make_folders(folder: Path) -> list[Path]:
    missing = []
    while not folder.exists():
        missing.append(folder)
        folder = folder.parent
    for path in reversed(missing):
        path.mkdir()
    return list(reversed(missing))


def _undo(files: list[Path], folders: list[Path], paths: TrapPaths) -> None:
    for path in files:
        path.unlink(missing_ok=True)
    for folder in reversed(folders):
        _remove_folder(folder, RemoveResult())
    paths.state_file.unlink(missing_ok=True)
    _remove_folder(paths.data_dir, RemoveResult())


def _decoy_status(record: DecoyRecord) -> str:
    # Compared by file identity: reading a decoy's content would itself raise an alert.
    identity = file_identity(record.path)
    if identity is None:
        return "missing"
    return "ok" if identity == record.identity else "changed"


def _remove_decoy(record: DecoyRecord, result: RemoveResult) -> None:
    current = _decoy_status(record)
    if current == "ok":
        record.path.unlink()
        result.deleted.append(record.path)
    elif current == "changed":
        result.kept_changed.append(record.path)


def _remove_folder(folder: Path, result: RemoveResult) -> None:
    try:
        folder.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        result.kept_folders.append(folder)


def _settle_alerts(paths: TrapPaths, purge: bool) -> Path | None:
    if paths.alerts_file.exists() and read_alerts(paths) and not purge:
        return paths.alerts_file
    paths.alerts_file.unlink(missing_ok=True)
    return None


def _candidate_paths(home: Path) -> list[Path]:
    relative = [path for path, *_ in (*SIBLINGS, *STANDARD)]
    return [home / path for path in (*relative, GH_HOSTS, GCLOUD_ADC, GIT_CREDENTIALS)]
