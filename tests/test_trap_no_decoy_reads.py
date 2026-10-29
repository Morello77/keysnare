"""KeySnare's own status, remove and scan code paths must never read a decoy's data.

Reading a decoy is exactly what its audit rule watches, so it would raise a false alarm. Only
`trap test` (through a separate program) is meant to read one.
"""

import builtins
import io
import os
import pathlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fakes import FakeSystem

from keysnare.scanner import scan
from keysnare.trap.manager import TrapPaths, install, prepare_install, remove, status
from keysnare.trap.placement import Machine
from keysnare.trap.state import load_state


def installed(tmp_path: Path) -> tuple[FakeSystem, TrapPaths, list[Path]]:
    home = tmp_path / "home"
    home.mkdir()
    paths = TrapPaths(home=home, data_dir=tmp_path / "KeySnare")
    machine = Machine(home, {}, frozenset(), ("manager",), frozenset(), frozenset())
    system = FakeSystem()
    install(system, prepare_install(system, machine, paths), paths, Path("pythonw.exe"), "now")
    state = load_state(paths.state_file)
    assert state is not None
    return system, paths, [record.path for record in state.decoys]


@pytest.fixture
def forbid_decoy_reads(monkeypatch: pytest.MonkeyPatch) -> Callable[[list[Path]], None]:
    def arm(decoys: list[Path]) -> None:
        protected = {os.path.normcase(os.path.abspath(path)) for path in decoys}

        def is_decoy(target: Any) -> bool:
            if not isinstance(target, (str, bytes, os.PathLike)):
                return False
            return os.path.normcase(os.path.abspath(os.fsdecode(target))) in protected

        real_open = io.open
        real_os_open = os.open

        def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if is_decoy(file) and ("r" in mode or "+" in mode):
                raise AssertionError(f"KeySnare read a decoy's data: {file}")
            return real_open(file, mode, *args, **kwargs)

        def guarded_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if is_decoy(path) and not flags & os.O_WRONLY:
                raise AssertionError(f"KeySnare opened a decoy for reading: {path}")
            return real_os_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guarded_open)
        monkeypatch.setattr(io, "open", guarded_open)
        monkeypatch.setattr(os, "open", guarded_os_open)
        # Python 3.10's pathlib keeps its own copy of io.open, taken when it was imported.
        accessor = getattr(pathlib, "_NormalAccessor", None)
        if accessor is not None:
            monkeypatch.setattr(accessor, "open", staticmethod(guarded_open))

    return arm


def test_status_never_reads_a_decoy(
    tmp_path: Path, forbid_decoy_reads: Callable[[list[Path]], None]
) -> None:
    system, paths, decoys = installed(tmp_path)
    forbid_decoy_reads(decoys)

    report = status(system, paths)

    assert set(report.decoys.values()) == {"ok"}


def test_remove_never_reads_a_decoy(
    tmp_path: Path, forbid_decoy_reads: Callable[[list[Path]], None]
) -> None:
    system, paths, decoys = installed(tmp_path)
    forbid_decoy_reads(decoys)

    result = remove(system, paths, purge=False)

    assert sorted(result.deleted) == sorted(decoys)


def test_scan_never_reads_a_decoy(
    tmp_path: Path, forbid_decoy_reads: Callable[[list[Path]], None]
) -> None:
    _, paths, decoys = installed(tmp_path)
    forbid_decoy_reads(decoys)

    result = scan(home=paths.home, env={}, platform="linux", decoys=decoys)

    assert result.findings == []


def test_the_guard_itself_catches_a_read(
    tmp_path: Path, forbid_decoy_reads: Callable[[list[Path]], None]
) -> None:
    _, _, decoys = installed(tmp_path)
    forbid_decoy_reads(decoys)

    with pytest.raises(AssertionError):
        decoys[0].read_bytes()
