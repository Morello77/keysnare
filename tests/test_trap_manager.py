import json
from pathlib import Path

import pytest
from fakes import FakeSystem

from keysnare.trap.decoys import NOTICE
from keysnare.trap.manager import (
    TrapError,
    TrapPaths,
    install,
    prepare_install,
    record_audit_before,
    remove,
    status,
)
from keysnare.trap.placement import Machine
from keysnare.trap.state import AuditBefore, load_state

HANDLER = Path("C:/venv/Scripts/pythonw.exe")


def setup(tmp_path: Path) -> tuple[TrapPaths, Machine]:
    home = tmp_path / "home"
    home.mkdir(parents=True)
    paths = TrapPaths(home=home, data_dir=tmp_path / "data" / "KeySnare")
    machine = Machine(
        home=home,
        env={},
        installed_tools=frozenset({"aws", "docker", "npm", "kubectl"}),
        git_credential_helpers=("manager",),
        ssh_identity_files=frozenset(),
        existing_paths=frozenset(),
    )
    return paths, machine


def installed(tmp_path: Path, system: FakeSystem) -> TrapPaths:
    paths, machine = setup(tmp_path)
    install(system, prepare_install(system, machine, paths), paths, HANDLER, "2026-10-27T12:00Z")
    return paths


def snapshot(root: Path) -> set[Path]:
    return set(root.rglob("*"))


def test_install_creates_marked_decoys_task_and_state(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)

    state = load_state(paths.state_file)
    assert state is not None and len(state.decoys) == 7
    for record in state.decoys:
        assert record.path.is_file()
        assert record.path in system.not_indexed
    assert (paths.home / ".config" / "gh" / "hosts.yml").read_text().startswith(f"# {NOTICE}")
    assert system.task_xml is not None and "LeastPrivilege" in system.task_xml
    assert state.audit_before is AuditBefore.UNKNOWN


def test_install_refuses_to_run_elevated(tmp_path: Path) -> None:
    paths, machine = setup(tmp_path)

    with pytest.raises(TrapError, match="administrator"):
        prepare_install(FakeSystem(elevated=True), machine, paths)


def test_install_refuses_when_already_installed(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)
    _, machine = setup(tmp_path / "again")

    with pytest.raises(TrapError, match="already installed"):
        prepare_install(system, machine, paths)


def test_install_never_overwrites_a_file_that_appears_late(tmp_path: Path) -> None:
    system = FakeSystem()
    paths, machine = setup(tmp_path)
    plan = prepare_install(system, machine, paths)
    late = plan.decoys[-1].path
    late.parent.mkdir(parents=True, exist_ok=True)
    late.write_text("user's real file")
    before = snapshot(paths.home)

    with pytest.raises(TrapError, match="appeared"):
        install(system, plan, paths, HANDLER, "now")

    assert late.read_text() == "user's real file"
    assert snapshot(paths.home) == before
    assert not paths.state_file.exists()


def test_failed_install_rolls_everything_back(tmp_path: Path) -> None:
    system = FakeSystem(fail_register=True)
    paths, machine = setup(tmp_path)

    with pytest.raises(TrapError, match="Access is denied"):
        install(system, prepare_install(system, machine, paths), paths, HANDLER, "now")

    assert snapshot(paths.home) == set()
    assert not paths.state_file.exists()


def test_remove_restores_the_home_folder_exactly(tmp_path: Path) -> None:
    system = FakeSystem()
    paths, machine = setup(tmp_path)
    (paths.home / ".ssh").mkdir()
    (paths.home / ".ssh" / "known_hosts").write_text("github.com ssh-ed25519 AAAA")
    before = snapshot(paths.home)
    install(system, prepare_install(system, machine, paths), paths, HANDLER, "now")

    result = remove(system, paths, purge=False)

    assert snapshot(paths.home) == before
    assert system.task_xml is None
    assert result.task_deleted
    assert not paths.data_dir.exists()


def test_remove_keeps_decoys_the_user_changed(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)
    changed = paths.home / ".aws" / "credentials.old"
    changed.write_text("the user's own content now")

    result = remove(system, paths, purge=False)

    assert changed.read_text() == "the user's own content now"
    assert result.kept_changed == [changed]


def test_remove_keeps_alert_history_unless_purged(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)
    paths.alerts_file.write_text(json.dumps({"kind": "alert", "process": "C:/evil.exe"}) + "\n")

    kept = remove(system, paths, purge=False)

    assert kept.kept_alerts == paths.alerts_file
    assert paths.alerts_file.exists()


def test_remove_with_purge_deletes_alert_history(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)
    paths.alerts_file.write_text(json.dumps({"kind": "alert", "process": "C:/evil.exe"}) + "\n")

    result = remove(system, paths, purge=True)

    assert result.kept_alerts is None
    assert not paths.data_dir.exists()


def test_remove_reports_whether_audit_restore_is_needed(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)
    record_audit_before(paths, AuditBefore.NO_AUDITING)

    assert remove(system, paths, purge=False).audit_restore_needed is True


def test_remove_twice_is_safe(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)
    remove(system, paths, purge=False)

    second = remove(system, paths, purge=False)

    assert second.deleted == [] and not second.task_deleted


def test_remove_without_state_reports_possible_decoys_and_leaves_them(tmp_path: Path) -> None:
    system = FakeSystem()
    paths, machine = setup(tmp_path)
    install(system, prepare_install(system, machine, paths), paths, HANDLER, "now")
    paths.state_file.unlink()
    files_before = {p for p in snapshot(paths.home) if p.is_file()}

    result = remove(system, paths, purge=False)

    assert result.deleted == []
    assert set(result.unverified) == files_before
    assert result.audit_restore_needed is None
    assert {p for p in snapshot(paths.home) if p.is_file()} == files_before


def test_status_reports_decoys_task_and_alerts(tmp_path: Path) -> None:
    system = FakeSystem()
    paths = installed(tmp_path, system)
    (paths.home / ".kube" / "config.bak").write_text("changed")
    paths.alerts_file.write_text(
        json.dumps({"kind": "alert", "process": "C:/evil.exe", "decoy": "x"}) + "\nnot json\n"
    )

    report = status(system, paths)

    assert report.installed and report.task_status == "Ready"
    assert report.decoys[paths.home / ".kube" / "config.bak"] == "changed"
    assert list(report.decoys.values()).count("ok") == 6
    assert report.recent_alerts == [{"kind": "alert", "process": "C:/evil.exe", "decoy": "x"}]


def test_status_when_not_installed(tmp_path: Path) -> None:
    paths, _ = setup(tmp_path)

    assert not status(FakeSystem(), paths).installed
