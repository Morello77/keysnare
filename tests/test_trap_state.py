from pathlib import Path

import pytest

from keysnare.trap.decoys import DecoyKind
from keysnare.trap.identity import FileIdentity
from keysnare.trap.state import (
    AuditBefore,
    DecoyRecord,
    TrapState,
    data_dir,
    load_state,
    save_state,
)

IDENTITY = FileIdentity(size=120, modified=2**60, created=2**59, volume=7, file_index=2**40)


def sample_state(tmp_path: Path) -> TrapState:
    return TrapState(
        decoys=(
            DecoyRecord(DecoyKind.SSH_KEY, tmp_path / ".ssh" / "id_rsa_backup", IDENTITY),
            DecoyRecord(DecoyKind.NPMRC, tmp_path / ".npmrc", IDENTITY),
        ),
        created_folders=(tmp_path / ".ssh",),
        audit_before=AuditBefore.NO_AUDITING,
        installed_at="2026-10-27T12:00:00+00:00",
    )


def test_state_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "KeySnare" / "traps.json"
    state = sample_state(tmp_path)

    save_state(state, path)

    assert load_state(path) == state


def test_missing_state_is_none(tmp_path: Path) -> None:
    assert load_state(tmp_path / "traps.json") is None


@pytest.mark.parametrize(
    "content", ["not json", "[]", '{"version": 99}', '{"version": 2, "decoys": "x"}']
)
def test_damaged_state_raises_value_error(tmp_path: Path, content: str) -> None:
    path = tmp_path / "traps.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        load_state(path)


def test_save_replaces_the_file_in_one_step(tmp_path: Path) -> None:
    path = tmp_path / "traps.json"
    save_state(sample_state(tmp_path), path)

    save_state(sample_state(tmp_path), path)

    assert [p.name for p in tmp_path.iterdir()] == ["traps.json"]


@pytest.mark.parametrize(
    ("before", "restore_needed"),
    [
        (AuditBefore.NO_AUDITING, True),
        (AuditBefore.FAILURE, True),
        (AuditBefore.SUCCESS, False),
        (AuditBefore.SUCCESS_AND_FAILURE, False),
        (AuditBefore.UNKNOWN, None),
    ],
)
def test_restore_is_needed_only_if_success_auditing_was_off(
    before: AuditBefore, restore_needed: bool | None
) -> None:
    assert before.restore_needed is restore_needed


def test_data_dir_is_under_local_app_data() -> None:
    assert data_dir({"LOCALAPPDATA": "C:/Users/dev/AppData/Local"}) == Path(
        "C:/Users/dev/AppData/Local/KeySnare"
    )


def test_data_dir_requires_local_app_data() -> None:
    with pytest.raises(ValueError):
        data_dir({})
