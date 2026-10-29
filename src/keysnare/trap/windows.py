"""Real Windows operations for traps: standard library only (ctypes, winreg, built-in tools).

Nothing here runs elevated. Each function refuses to run on other operating systems.
"""

import base64
import csv
import io
import os
import subprocess  # noqa: S404 - only built-in Windows tools, fixed arguments, never a shell
import sys
from pathlib import Path

from keysnare.trap.admin import EXPORT_FILE_NAME
from keysnare.trap.alert import NOTIFY_SCRIPT, ProtectedDirs
from keysnare.trap.task import TASK_NAME
from keysnare.winpath import PathForms

FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
MAX_PATH_BUFFER = 32768
TOOL_TIMEOUT_SECONDS = 30
READER_SCRIPT = (
    "Start-Sleep -Milliseconds 1500; $null = [IO.File]::ReadAllBytes($env:KEYSNARE_DECOY)"
)
# Registers the user's own task, non-elevated. No -Force: an existing task is never replaced.
REGISTER_TASK_SCRIPT = (
    "$xml = [Text.Encoding]::UTF8.GetString("
    "[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()));"
    "$null = Register-ScheduledTask -TaskPath '\\KeySnare\\' -TaskName 'DecoyRead' "
    "-Xml $xml -ErrorAction Stop"
)
APPMODEL_ERROR_NO_PACKAGE = 15700


def is_windows() -> bool:
    """Traps are Windows-only in v1."""
    return sys.platform == "win32"


def is_elevated() -> bool:
    """True when this process runs with administrator rights."""
    if sys.platform != "win32":
        return False
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def system_directory() -> Path:
    """Return C:\\Windows\\System32, from the Windows API rather than an environment variable."""
    return Path(_windows_api_path("GetSystemDirectoryW"))


class WindowsSystem:
    """The TrapSystem operations, done with built-in Windows tools."""

    def is_elevated(self) -> bool:
        return is_elevated()

    def user_sid(self) -> str:
        output = _run_tool("whoami.exe", "/user", "/fo", "csv", "/nh")
        return next(csv.reader(io.StringIO(output)))[1]

    def mark_not_indexed(self, path: Path) -> None:
        if sys.platform != "win32":
            raise OSError("traps are Windows-only")
        import ctypes

        kernel32 = ctypes.windll.kernel32
        attributes = kernel32.GetFileAttributesW(str(path))
        if attributes == INVALID_FILE_ATTRIBUTES:
            raise ctypes.WinError()
        if not kernel32.SetFileAttributesW(
            str(path), attributes | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        ):
            raise ctypes.WinError()

    def register_task(self, xml: str) -> None:
        # No file is handed to another program: Microsoft Store Python redirects files it writes
        # under AppData to a private folder, where schtasks.exe would not find them. The XML
        # travels on stdin as base64, so no code page can garble non-English letters in paths.
        completed = subprocess.run(  # noqa: S603 - built-in PowerShell, constant script
            [
                str(powershell_path()),
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                _encoded(REGISTER_TASK_SCRIPT),
            ],
            input=base64.b64encode(xml.encode("utf-8")).decode("ascii"),
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
        )
        if completed.returncode != 0:
            raise OSError(completed.stderr.strip() or "Register-ScheduledTask failed")

    def delete_task(self) -> bool:
        if self.task_status() is None:
            return False
        _run_tool("schtasks.exe", "/Delete", "/TN", TASK_NAME, "/F")
        return True

    def task_status(self) -> str | None:
        try:
            output = _run_tool("schtasks.exe", "/Query", "/TN", TASK_NAME, "/FO", "CSV", "/NH")
        except OSError:
            return None
        rows = list(csv.reader(io.StringIO(output)))
        return rows[0][2] if rows and len(rows[0]) > 2 else "unknown"


def protected_dirs() -> ProtectedDirs:
    """Return the folders only administrators can write to, from HKLM and the Windows API."""
    if sys.platform != "win32":
        raise OSError("traps are Windows-only")
    import winreg

    system32 = system_directory()
    system_drive = system32.drive
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    ) as key:
        program_files = winreg.QueryValueEx(key, "ProgramFilesDir")[0]
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    ) as key:
        program_data = winreg.QueryValueEx(key, "ProgramData")[0]
    # Expanded by hand from the API's drive: environment variables could be changed by malware.
    program_data = program_data.replace("%SystemDrive%", system_drive)
    return ProtectedDirs(Path(program_data), Path(program_files), system32)


def path_forms() -> PathForms:
    """Return this machine's volume device names and 8.3 name expansion, for event paths."""
    if sys.platform != "win32":
        return PathForms()
    import ctypes

    kernel32 = ctypes.windll.kernel32
    devices = {"\\SystemRoot": _windows_api_path("GetWindowsDirectoryW")}
    buffer = ctypes.create_unicode_buffer(MAX_PATH_BUFFER)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if kernel32.QueryDosDeviceW(f"{letter}:", buffer, MAX_PATH_BUFFER):
            devices[buffer.value] = f"{letter}:"

    def expand_short_names(text: str) -> str:
        long_name = ctypes.create_unicode_buffer(MAX_PATH_BUFFER)
        if kernel32.GetLongPathNameW(text, long_name, MAX_PATH_BUFFER):
            return long_name.value
        return text

    return PathForms(devices=devices, expand_short_names=expand_short_names)


def notify(text: str) -> bool:
    """Show a Windows notification. The text travels in an environment variable, never as code."""
    environment = {**os.environ, "KEYSNARE_ALERT_TEXT": text}
    try:
        completed = subprocess.run(  # noqa: S603 - built-in PowerShell, constant script
            [
                str(powershell_path()),
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                _encoded(NOTIFY_SCRIPT),
            ],
            env=environment,
            capture_output=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def read_export() -> str:
    """Return the decoy-read events the SYSTEM relay exported, as XML ('' if none yet)."""
    export = protected_dirs().program_data / "KeySnare" / EXPORT_FILE_NAME
    try:
        return _run_tool("wevtutil.exe", "qe", str(export), "/lf:true", "/f:xml")
    except OSError:
        return ""


def start_reader(decoy: Path) -> int:
    """Start a separate program that reads a decoy after a short pause, as a thief would.

    The pause leaves time to record its process ID; the path travels in an environment variable.
    """
    reader = subprocess.Popen(  # noqa: S603 - built-in PowerShell, constant script
        [
            str(powershell_path()),
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            _encoded(READER_SCRIPT),
        ],
        env={**os.environ, "KEYSNARE_DECOY": str(decoy)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return reader.pid


def powershell_path() -> Path:
    """Return the built-in Windows PowerShell, by its absolute System32 path."""
    return system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def store_python_data_dir(data_dir: Path) -> Path | None:
    """Return where Microsoft Store Python really keeps `data_dir`, or None for other Pythons.

    Store Python writes under AppData go to a private per-package folder that only it sees.
    """
    family = _package_family_name()
    if family is None:
        return None
    return data_dir.parent / "Packages" / family / "LocalCache" / "Local" / data_dir.name


def handler_path() -> Path:
    """Return the windowless Python (pythonw.exe) next to the running one."""
    executable = Path(sys.executable)
    windowless = executable.with_name("pythonw.exe")
    return windowless if windowless.is_file() else executable


def _encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _package_family_name() -> str | None:
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    get_family = getattr(ctypes.windll.kernel32, "GetCurrentPackageFamilyName", None)
    if get_family is None:
        return None
    length = wintypes.UINT(0)
    if get_family(ctypes.byref(length), None) == APPMODEL_ERROR_NO_PACKAGE:
        return None
    buffer = ctypes.create_unicode_buffer(length.value)
    if get_family(ctypes.byref(length), buffer) != 0:
        return None
    return buffer.value


def _run_tool(tool: str, *arguments: str) -> str:
    executable = system_directory() / tool
    try:
        completed = subprocess.run(  # noqa: S603 - built-in tool by full path, no shell
            [str(executable), *arguments],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise OSError(f"{tool} did not finish in time") from error
    if completed.returncode != 0:
        raise OSError(completed.stderr.strip() or f"{tool} failed")
    return completed.stdout


def _windows_api_path(function_name: str) -> str:
    if sys.platform != "win32":
        raise OSError("traps are Windows-only")
    import ctypes

    buffer = ctypes.create_unicode_buffer(MAX_PATH_BUFFER)
    if not getattr(ctypes.windll.kernel32, function_name)(buffer, MAX_PATH_BUFFER):
        raise ctypes.WinError()
    return buffer.value
