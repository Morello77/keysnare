import base64
import builtins
import io
import subprocess
from pathlib import Path
from typing import Any

import pytest

from keysnare.trap import windows
from keysnare.trap.windows import REGISTER_TASK_SCRIPT, WindowsSystem, store_python_data_dir

SYSTEM32 = Path("C:/Windows/System32")
XML = '<?xml version="1.0"?><Task><Command>C:\\Users\\Élodie\\pythonw.exe</Command></Task>'


@pytest.fixture
def powershell_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[list[str], dict[str, Any]]]:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(windows, "system_directory", lambda: SYSTEM32)
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


@pytest.fixture
def no_file_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = io.open

    def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if any(flag in mode for flag in "wax+"):
            raise AssertionError(f"register_task wrote a file: {file}")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)


def test_register_task_hands_the_xml_to_powershell_on_stdin_and_writes_no_files(
    powershell_calls: list[tuple[list[str], dict[str, Any]]], no_file_writes: None
) -> None:
    WindowsSystem().register_task(XML)

    [(args, kwargs)] = powershell_calls
    assert args == [
        str(SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        args[4],
    ]
    assert base64.b64decode(args[4]).decode("utf-16-le") == REGISTER_TASK_SCRIPT
    assert base64.b64decode(kwargs["input"]).decode("utf-8") == XML


def test_registration_script_is_fixed_and_never_replaces_a_task() -> None:
    assert "Register-ScheduledTask -TaskPath '\\KeySnare\\' -TaskName 'DecoyRead'" in (
        REGISTER_TASK_SCRIPT
    )
    assert "[Console]::In.ReadToEnd()" in REGISTER_TASK_SCRIPT
    assert "-Force" not in REGISTER_TASK_SCRIPT
    assert "RunLevel" not in REGISTER_TASK_SCRIPT


def test_registration_failure_reports_powershells_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 1, "", "Access is denied.")

    monkeypatch.setattr(windows, "system_directory", lambda: SYSTEM32)
    monkeypatch.setattr(subprocess, "run", failing_run)

    with pytest.raises(OSError, match="Access is denied"):
        WindowsSystem().register_task(XML)


def test_store_python_keeps_the_data_folder_in_its_package_folder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    family = "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
    monkeypatch.setattr(windows, "_package_family_name", lambda: family)
    data_dir = Path("C:/Users/dev/AppData/Local/KeySnare")

    assert store_python_data_dir(data_dir) == Path(
        f"C:/Users/dev/AppData/Local/Packages/{family}/LocalCache/Local/KeySnare"
    )


def test_other_pythons_keep_the_data_folder_where_it_is(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(windows, "_package_family_name", lambda: None)

    assert store_python_data_dir(Path("C:/Users/dev/AppData/Local/KeySnare")) is None
