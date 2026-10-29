"""Tell whether a decoy is still the file KeySnare wrote, without ever reading its content.

Reading a decoy's data is exactly what its audit rule watches, so it would raise an alert. On
Windows this opens the file with FILE_READ_ATTRIBUTES access only (never FILE_READ_DATA) and
without following links, and asks for its NTFS identity. A replaced file has a new file ID.
"""

import os
import sys
from dataclasses import dataclass
from pathlib import Path

# Access rights and flags for CreateFileW. FILE_READ_DATA (0x1) is deliberately absent.
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = -1
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3


@dataclass(frozen=True)
class FileIdentity:
    """What makes a file this exact file: size, times and its NTFS file ID."""

    size: int
    modified: int
    created: int
    volume: int
    file_index: int


def file_identity(path: Path) -> FileIdentity | None:
    """Return the file's identity, or None if it does not exist, without reading its content."""
    if sys.platform == "win32":
        return _windows_identity(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    created = getattr(info, "st_birthtime_ns", info.st_ctime_ns)
    return FileIdentity(info.st_size, info.st_mtime_ns, created, info.st_dev, info.st_ino)


def _windows_identity(path: Path) -> FileIdentity | None:
    if sys.platform != "win32":
        raise OSError("Windows only")
    import ctypes
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", FileTime),
            ("last_access_time", FileTime),
            ("last_write_time", FileTime),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(
        str(path),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_ALL,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle in (None, INVALID_HANDLE_VALUE, ctypes.c_void_p(-1).value):
        error = ctypes.get_last_error()
        if error in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
            return None
        raise ctypes.WinError(error)
    try:
        info = ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)
    return FileIdentity(
        size=(info.file_size_high << 32) | info.file_size_low,
        modified=(info.last_write_time.high << 32) | info.last_write_time.low,
        created=(info.creation_time.high << 32) | info.creation_time.low,
        volume=info.volume_serial_number,
        file_index=(info.file_index_high << 32) | info.file_index_low,
    )
