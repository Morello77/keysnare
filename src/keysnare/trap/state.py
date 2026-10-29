"""What `trap install` changed, saved so `trap remove` can undo exactly that."""

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from keysnare.trap.decoys import DecoyKind
from keysnare.trap.identity import FileIdentity

# Version 2 records each decoy's file identity instead of a hash of its content.
STATE_VERSION = 2
STATE_FILE_NAME = "traps.json"


class AuditBefore(Enum):
    """The "File System" audit setting before install, as the user read it from auditpol."""

    NO_AUDITING = "no-auditing"
    SUCCESS = "success"
    FAILURE = "failure"
    SUCCESS_AND_FAILURE = "success-and-failure"
    UNKNOWN = "unknown"

    @property
    def restore_needed(self) -> bool | None:
        """True if success auditing was off before, None if nobody knows."""
        if self is AuditBefore.UNKNOWN:
            return None
        return self in (AuditBefore.NO_AUDITING, AuditBefore.FAILURE)


@dataclass(frozen=True)
class DecoyRecord:
    """A decoy KeySnare created, with the file identity it had right after being written."""

    kind: DecoyKind
    path: Path
    identity: FileIdentity


@dataclass(frozen=True)
class TrapState:
    """Everything `trap install` changed."""

    decoys: tuple[DecoyRecord, ...]
    created_folders: tuple[Path, ...]
    audit_before: AuditBefore
    installed_at: str


def data_dir(env: Mapping[str, str]) -> Path:
    """Return KeySnare's data folder, %LOCALAPPDATA%\\KeySnare. Raises ValueError if unset."""
    local_app_data = env.get("LOCALAPPDATA")
    if not local_app_data:
        raise ValueError("LOCALAPPDATA is not set")
    return Path(local_app_data) / "KeySnare"


def save_state(state: TrapState, path: Path) -> None:
    """Write the state file in one step, so it is never left half-written."""
    data = {
        "version": STATE_VERSION,
        "decoys": [
            {"kind": d.kind.value, "path": str(d.path), "identity": asdict(d.identity)}
            for d in state.decoys
        ],
        "created_folders": [str(folder) for folder in state.created_folders],
        "audit_before": state.audit_before.value,
        "installed_at": state.installed_at,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def load_state(path: Path) -> TrapState | None:
    """Read the state file. Returns None if it is missing; raises ValueError if it is damaged."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        return _parse(json.loads(text))
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError(f"damaged trap state file: {error}") from error


def _parse(data: Any) -> TrapState:
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise ValueError("unsupported trap state file")
    decoys = data["decoys"]
    if not isinstance(decoys, list):
        raise ValueError("damaged trap state file: decoys is not a list")
    return TrapState(
        decoys=tuple(
            DecoyRecord(
                DecoyKind(d["kind"]),
                Path(d["path"]),
                FileIdentity(**{key: int(value) for key, value in d["identity"].items()}),
            )
            for d in decoys
        ),
        created_folders=tuple(Path(folder) for folder in data["created_folders"]),
        audit_before=AuditBefore(data["audit_before"]),
        installed_at=str(data["installed_at"]),
    )
