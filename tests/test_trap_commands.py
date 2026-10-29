import io
import json
from pathlib import Path

import pytest
from fakes import FakeSystem, exported_event

from keysnare.trap.admin import AUDIT_RESTORE_COMMANDS, REMOVAL_COMMANDS
from keysnare.trap.alert import ProtectedDirs
from keysnare.trap.commands import (
    TrapDeps,
    run_alert,
    run_install,
    run_remove,
    run_status,
    run_test,
)
from keysnare.trap.manager import TrapPaths, read_alerts
from keysnare.trap.placement import Machine
from keysnare.trap.state import AuditBefore, load_state
from keysnare.winpath import PathForms


def deps(tmp_path: Path, answers: list[str] | None = None) -> tuple[TrapDeps, io.StringIO]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    out = io.StringIO()
    replies = iter(answers or [])
    machine = Machine(
        home=home,
        env={},
        installed_tools=frozenset({"aws", "docker", "npm", "kubectl"}),
        git_credential_helpers=("manager",),
        ssh_identity_files=frozenset(),
        existing_paths=frozenset(),
    )
    return (
        TrapDeps(
            system=FakeSystem(),
            paths=TrapPaths(home=home, data_dir=tmp_path / "KeySnare"),
            machine=lambda: machine,
            handler=Path("C:/venv/pythonw.exe"),
            protected_dirs=lambda: ProtectedDirs(
                Path("C:/ProgramData"), Path("C:/Program Files"), Path("C:/Windows/System32")
            ),
            path_forms=PathForms,
            notify=lambda text: True,
            now=lambda: "2026-10-27T12:00:00+00:00",
            ask=lambda prompt: (out.write(prompt), next(replies))[1],
            out=out,
            read_export=lambda: "",
            start_reader=lambda decoy: 4242,
            sleep=lambda seconds: None,
            monotonic=iter(range(1000)).__next__,
        ),
        out,
    )


def test_install_shows_plan_asks_then_prints_admin_commands(tmp_path: Path) -> None:
    d, out = deps(tmp_path, answers=["y", "1"])

    code = run_install(d, yes=False)

    text = out.getvalue()
    assert code == 0
    assert "~" in text and "id_rsa_backup" in text
    assert "npm is installed and reads this file" in text
    assert "Continue? [y/N]" in text
    assert "powershell -NoProfile" in text and "Ctrl+Shift+Enter" in text
    assert 'auditpol.exe" /set /subcategory:' in text
    assert "KeySnare Decoy Read Relay" in text
    assert "keysnare trap test" in text
    state = load_state(d.paths.state_file)
    assert state is not None and state.audit_before is AuditBefore.NO_AUDITING


def test_install_does_nothing_if_the_user_says_no(tmp_path: Path) -> None:
    d, out = deps(tmp_path, answers=["n"])

    assert run_install(d, yes=False) == 1
    assert not d.paths.state_file.exists()
    assert list(d.paths.home.iterdir()) == []


def test_install_with_yes_asks_nothing_and_records_unknown(tmp_path: Path) -> None:
    d, _ = deps(tmp_path)

    assert run_install(d, yes=True) == 0
    state = load_state(d.paths.state_file)
    assert state is not None and state.audit_before is AuditBefore.UNKNOWN


def test_install_errors_are_explained_with_exit_code_2(tmp_path: Path) -> None:
    d, out = deps(tmp_path)
    d.system.elevated = True  # type: ignore[attr-defined]

    assert run_install(d, yes=True) == 2
    assert "refuses to run as administrator" in out.getvalue()


def test_status_lists_decoys_task_and_audit_note(tmp_path: Path) -> None:
    d, out = deps(tmp_path)
    run_install(d, yes=True)
    out.seek(0)
    out.truncate(0)

    assert run_status(d) == 0
    text = out.getvalue()
    assert "Alert task: Ready" in text
    assert text.count(": ok") == 7
    assert "keysnare trap test" in text


def test_status_when_not_installed(tmp_path: Path) -> None:
    d, out = deps(tmp_path)

    assert run_status(d) == 0
    assert "not installed" in out.getvalue()


@pytest.mark.parametrize(("answer", "expect_restore"), [("1", True), ("2", False), ("5", None)])
def test_remove_prints_restore_commands_only_when_needed(
    tmp_path: Path, answer: str, expect_restore: bool | None
) -> None:
    d, out = deps(tmp_path, answers=["y", answer])
    run_install(d, yes=False)
    out.seek(0)
    out.truncate(0)

    assert run_remove(d, purge=False) == 0
    text = out.getvalue()
    assert REMOVAL_COMMANDS in text
    assert ("success:disable" in text) is (expect_restore is not False)
    if expect_restore is None:
        assert "auditpol.exe') /get /subcategory:" in text
    if expect_restore:
        assert AUDIT_RESTORE_COMMANDS in text


def test_remove_tells_where_alert_history_was_kept(tmp_path: Path) -> None:
    d, out = deps(tmp_path)
    run_install(d, yes=True)
    d.paths.alerts_file.write_text(json.dumps({"kind": "alert"}) + "\n")

    run_remove(d, purge=False)

    assert str(d.paths.alerts_file) in out.getvalue()


def test_trap_test_succeeds_when_the_simulated_theft_raises_a_test_alert(tmp_path: Path) -> None:
    d, out = deps(tmp_path)
    run_install(d, yes=True)
    reads: list[Path] = []

    def reader(decoy: Path) -> int:
        reads.append(decoy)
        return 4242

    def task_fires(seconds: float) -> None:
        # Stands in for Windows: the reader's read raises event 4663, the task runs the handler.
        process = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        d.read_export = lambda: exported_event("1", process, pid="4242", decoy=str(reads[0]))
        run_alert(d)

    d.start_reader, d.sleep = reader, task_fires

    assert run_test(d) == 0
    assert "Test alert received" in out.getvalue()
    assert read_alerts(d.paths)[-1]["test"] is True
    assert not (d.paths.data_dir / "test-pid.txt").exists()


def test_trap_test_explains_likely_causes_when_no_alert_arrives(tmp_path: Path) -> None:
    d, out = deps(tmp_path)
    run_install(d, yes=True)

    assert run_test(d) == 1
    assert "admin commands" in out.getvalue()


def test_alert_command_logs_the_event(tmp_path: Path) -> None:
    d, _ = deps(tmp_path)
    run_install(d, yes=True)
    decoy = d.paths.home / ".aws" / "credentials.old"

    d.read_export = lambda: exported_event("5", "C:/Temp/stealer.exe", decoy=str(decoy))

    assert run_alert(d) == 0
    assert read_alerts(d.paths)[0]["process"] == "C:/Temp/stealer.exe"
