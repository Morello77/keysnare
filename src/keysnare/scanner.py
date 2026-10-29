"""Scan known credential locations and walk folders for credential files."""

import os
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from keysnare.detect import PRESENCE_RULES, find_secrets
from keysnare.locations import (
    Category,
    CredentialFile,
    Platform,
    current_platform,
    existing_files,
    known_locations,
)
from keysnare.masking import mask_secret
from keysnare.risk import Risk, risk_for
from keysnare.winpath import canonical

DECOY_REASON = "KeySnare decoy (not read)"
WALK_THREADS = 16

Progress = Callable[[int], None]

MAX_WALK_FILE_BYTES = 1024 * 1024
# Windows refuses paths over 260 characters unless they carry the \\?\ prefix. Prefixing from 240
# leaves room for the file names appended to a folder path.
WINDOWS_LONG_PATH_FROM = 240
WINDOWS_LONG_PATH_PREFIX = "\\\\?\\"
WINDOWS_LONG_UNC_PREFIX = "\\\\?\\UNC\\"

# Folders that never hold the user's own secrets: dependencies, environments, caches, temp files,
# and VS Code folders (KeySnare stays away from extension storage).
SKIPPED_FOLDERS = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".cache",
        "cache",
        "caches",
        "temp",
        "tmp",
        ".tmp",
        ".npm",
        ".nuget",
        ".gradle",
        ".m2",
        ".cargo",
        ".rustup",
        ".vscode",
        ".vscode-server",
        ".vscode-insiders",
    }
)
# Skipped only directly under the home folder; their known files are checked by exact path.
SKIPPED_HOME_FOLDERS = frozenset({"appdata", "library"})
ENV_FILE_PREFIX = ".env."


@dataclass(frozen=True)
class Finding:
    """A secret found in a file on disk."""

    rule_id: str
    category: Category
    path: Path
    line: int | None
    # repr=False: printing or logging this object must never show the secret.
    secret: str | None = field(default=None, repr=False)

    @property
    def masked(self) -> str | None:
        """The secret with all but its first and last 4 characters hidden."""
        return mask_secret(self.secret) if self.secret is not None else None

    @property
    def risk(self) -> Risk:
        """How dangerous this finding is and why."""
        return risk_for(self.rule_id)


@dataclass(frozen=True)
class SkippedPath:
    """A file or folder that was not scanned, and why."""

    path: Path
    reason: str


@dataclass(frozen=True)
class ScanResult:
    """Everything a scan found, checked and skipped."""

    findings: list[Finding]
    files_checked: list[Path]
    skipped: list[SkippedPath]
    platform: Platform


def scan(
    root: Path | None = None,
    *,
    home: Path | None = None,
    env: Mapping[str, str] | None = None,
    platform: Platform | None = None,
    decoys: Sequence[Path] = (),
    progress: Progress | None = None,
) -> ScanResult:
    """Scan the home folder (default) or `root`, which may be a folder or a single file.

    Files in `decoys` (KeySnare's own trap decoys) are never opened: reading one would raise an
    alert. They are listed as skipped instead. `progress` is called with the number of folders
    walked so far.
    """
    home = home or Path.home()
    platform = platform or current_platform()
    known = existing_files(known_locations(home, os.environ if env is None else env, platform))
    skipped: list[SkippedPath] = []
    if root is None:
        candidates = [*known, *_walk(home, home, skipped, progress)]
    elif root.is_file():
        candidates = [_known_or_walked(root, known)]
    else:
        inside = [file for file in known if file.path.is_relative_to(root)]
        candidates = [*inside, *_walk(root, home, skipped, progress)]
    decoy_keys = {canonical(decoy) for decoy in decoys}
    to_read = []
    for file in _unique(candidates):
        if canonical(file.path) in decoy_keys:
            skipped.append(SkippedPath(file.path, DECOY_REASON))
        else:
            to_read.append(file)
    return _scan_files(to_read, skipped, platform)


def walk_category(file_name: str, folder_name: str) -> Category | None:
    """Return the category of a file found while walking, or None if it is not a credential file."""
    name = file_name.lower()
    if name == ".env" or name.startswith(ENV_FILE_PREFIX):
        return Category.ENV_FILE
    if name == ".npmrc":
        return Category.NPMRC
    if name == "nuget.config":
        return Category.NUGET
    if name == "mcp.json" and folder_name.lower() == ".cursor":
        return Category.MCP_CONFIG
    if name.endswith(".ppk"):
        return Category.SSH_KEY
    return None


def _known_or_walked(path: Path, known: list[CredentialFile]) -> CredentialFile:
    for file in known:
        if file.path == path:
            return file
    category = walk_category(path.name, path.parent.name) or Category.ENV_FILE
    return CredentialFile(category, path)


@dataclass
class _FolderResult:
    files: list[CredentialFile] = field(default_factory=list)
    folders: list[Path] = field(default_factory=list)
    skipped: list[SkippedPath] = field(default_factory=list)


def _walk(
    root: Path, home: Path, skipped: list[SkippedPath], progress: Progress | None
) -> list[CredentialFile]:
    # Reading folders is mostly waiting on the disk, which threads can overlap. The walk goes one
    # depth level at a time: each thread reads one folder, and only this loop combines results.
    found: list[CredentialFile] = []
    folders_done = 0
    level = [root]
    with ThreadPoolExecutor(max_workers=WALK_THREADS) as pool:
        while level:
            next_level: list[Path] = []
            for result in pool.map(lambda folder: _read_folder(folder, home), level):
                found += result.files
                skipped += result.skipped
                next_level += result.folders
                folders_done += 1
                if progress:
                    progress(folders_done)
            level = next_level
    return sorted(found, key=lambda file: str(file.path))


def _read_folder(folder: Path, home: Path) -> _FolderResult:
    result = _FolderResult()
    try:
        entries = list(os.scandir(_os_path(folder)))
    except OSError as error:
        result.skipped.append(SkippedPath(folder, f"could not open folder: {error.strerror}"))
        return result
    for entry in entries:
        if _is_link(entry):
            continue
        # Built from the folder, not entry.path, so reports never show the \\?\ prefix.
        path = folder / entry.name
        if entry.is_dir(follow_symlinks=False):
            name = entry.name.lower()
            if name == ".git":
                if os.path.isfile(_os_path(path / "config")):
                    result.files.append(CredentialFile(Category.GIT_REMOTE, path / "config"))
            elif name not in SKIPPED_FOLDERS and not (
                folder == home and name in SKIPPED_HOME_FOLDERS
            ):
                result.folders.append(path)
            continue
        category = walk_category(entry.name, folder.name)
        if category is None:
            continue
        if entry.stat(follow_symlinks=False).st_size > MAX_WALK_FILE_BYTES:
            result.skipped.append(SkippedPath(path, "larger than 1 MB"))
        else:
            result.files.append(CredentialFile(category, path))
    return result


def _is_link(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    # On Windows, junctions and cloud placeholders (e.g. OneDrive) are reparse points.
    attributes = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _os_path(path: Path) -> str:
    """Return the path as the operating system needs it, with the long-path prefix on Windows."""
    text = os.path.abspath(path)
    if sys.platform != "win32" or len(text) < WINDOWS_LONG_PATH_FROM:
        return text
    if text.startswith(WINDOWS_LONG_PATH_PREFIX):
        return text
    if text.startswith("\\\\"):
        return WINDOWS_LONG_UNC_PREFIX + text[2:]
    return WINDOWS_LONG_PATH_PREFIX + text


def _unique(files: list[CredentialFile]) -> list[CredentialFile]:
    seen: dict[str, CredentialFile] = {}
    for file in files:
        seen.setdefault(os.path.normcase(os.path.abspath(file.path)), file)
    return list(seen.values())


def _scan_files(
    files: list[CredentialFile], skipped: list[SkippedPath], platform: Platform
) -> ScanResult:
    findings: list[Finding] = []
    checked: list[Path] = []
    for file in files:
        try:
            findings.extend(_scan_file(file))
        except OSError as error:
            # strerror, unlike str(error), never repeats the full path into the report.
            skipped.append(SkippedPath(file.path, f"could not read: {error.strerror or error}"))
            continue
        checked.append(file.path)
    findings.sort(key=lambda f: (str(f.path), f.line or 0))
    return ScanResult(findings, checked, skipped, platform)


def _scan_file(file: CredentialFile) -> list[Finding]:
    os_path = Path(_os_path(file.path))
    if file.category in PRESENCE_RULES:
        if os_path.stat().st_size == 0:
            return []
        return [Finding(PRESENCE_RULES[file.category], file.category, file.path, None)]
    text = os_path.read_text(encoding="utf-8", errors="replace")
    return [
        Finding(d.rule_id, file.category, file.path, d.line, d.secret)
        for d in find_secrets(file.category, text)
    ]
