import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from keysnare.trap.identity import FILE_READ_ATTRIBUTES, file_identity

FILE_READ_DATA = 0x0001


def icacls(*arguments: str) -> None:
    executable = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
    subprocess.run([str(executable), *arguments], check=True, capture_output=True)  # noqa: S603


@pytest.fixture
def unreadable(tmp_path: Path) -> Iterator[Path]:
    """A file the current user may not read the data of (but may still look up)."""
    path = tmp_path / "decoy"
    path.write_text("KeySnare decoy")
    if sys.platform == "win32":
        user = os.environ["USERNAME"]
        icacls(str(path), "/deny", f"{user}:(RD)")
        yield path
        icacls(str(path), "/remove:d", user)
    else:
        path.chmod(0)
        yield path
        path.chmod(0o600)


def test_identity_never_needs_read_data_access(unreadable: Path) -> None:
    with pytest.raises(PermissionError):
        unreadable.read_bytes()

    assert file_identity(unreadable) is not None


def test_access_requested_is_attributes_only() -> None:
    assert FILE_READ_ATTRIBUTES == 0x0080
    assert not FILE_READ_ATTRIBUTES & FILE_READ_DATA


def test_missing_file_has_no_identity(tmp_path: Path) -> None:
    assert file_identity(tmp_path / "missing") is None


def test_identity_is_stable_while_the_file_is_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "decoy"
    path.write_text("KeySnare decoy")

    assert file_identity(path) == file_identity(path)


def test_replaced_file_has_a_new_identity_even_with_same_size_and_content(tmp_path: Path) -> None:
    path = tmp_path / "decoy"
    path.write_text("KeySnare decoy")
    before = file_identity(path)
    replacement = tmp_path / "replacement"
    replacement.write_text("KeySnare decoy")

    os.replace(replacement, path)

    after = file_identity(path)
    assert before is not None and after is not None
    assert after.file_index != before.file_index


def test_edited_file_has_a_new_identity(tmp_path: Path) -> None:
    path = tmp_path / "decoy"
    path.write_text("KeySnare decoy")
    before = file_identity(path)

    path.write_text("edited by the user")

    assert file_identity(path) != before
