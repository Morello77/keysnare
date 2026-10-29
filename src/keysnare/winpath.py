"""Compare Windows paths the way Windows does, from any operating system.

Every Windows path comparison in KeySnare goes through `canonical`, which accepts the forms
Windows and its event log use for the same file.
"""

import ntpath
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePath

ShortNameExpander = Callable[[str], str]

# Prefixes that only change how a path is passed to Windows, not which file it names.
NAMESPACE_PREFIXES = (
    ("\\\\?\\UNC\\", "\\\\"),
    ("\\\\?\\", ""),
    ("\\\\.\\", ""),
    ("\\??\\", ""),
    ("\\Device\\Mup\\", "\\\\"),
)


@dataclass(frozen=True)
class PathForms:
    """Machine-specific translations, supplied by Windows at runtime and faked in tests.

    `devices` maps kernel names such as \\Device\\HarddiskVolume3 or \\SystemRoot to a drive or
    folder. `expand_short_names` turns 8.3 names such as DEV~1 into long names.
    """

    devices: Mapping[str, str] = field(default_factory=dict)
    expand_short_names: ShortNameExpander | None = None


NO_FORMS = PathForms()


def canonical(path: str | PurePath, forms: PathForms = NO_FORMS) -> str:
    """Return one spelling for every form of a Windows path, for comparison only."""
    # str() first: building a Windows path from a POSIX path object turns "C:/x" into "C:x".
    text = str(path).replace("/", "\\")
    text = _strip_namespace_prefix(text)
    text = _translate_device(text, forms.devices)
    if forms.expand_short_names and "~" in text:
        text = forms.expand_short_names(text)
    text = ntpath.normpath(text)
    drive, rest = ntpath.splitdrive(text)
    if rest not in ("", "\\"):
        text = drive + rest.rstrip("\\")
    return _fold_case(text)


def same_windows_path(a: str | PurePath, b: str | PurePath, forms: PathForms = NO_FORMS) -> bool:
    """Return True if both name the same file. Empty paths never match."""
    if not str(a) or not str(b):
        return False
    return canonical(a, forms) == canonical(b, forms)


def parent_of(path: str | PurePath, forms: PathForms = NO_FORMS) -> str:
    """Return the canonical form of a path's folder."""
    return ntpath.dirname(canonical(path, forms))


def _strip_namespace_prefix(text: str) -> str:
    for prefix, replacement in NAMESPACE_PREFIXES:
        if text[: len(prefix)].upper() == prefix.upper():
            return replacement + text[len(prefix) :]
    return text


def _translate_device(text: str, devices: Mapping[str, str]) -> str:
    for device in sorted(devices, key=len, reverse=True):
        prefix = device.replace("/", "\\")
        head = text[: len(prefix)]
        rest = text[len(prefix) :]
        if head.upper() == prefix.upper() and (rest == "" or rest.startswith("\\")):
            return devices[device] + rest
    return text


def _fold_case(text: str) -> str:
    # Windows compares names letter by letter with a simple uppercase table, so a letter whose
    # uppercase is several letters (ß -> SS) stays as it is.
    return "".join(char.upper() if len(char.upper()) == 1 else char for char in text)
