import re
from pathlib import Path

import pytest

from keysnare.trap.admin import (
    AUDIT_RESTORE_COMMANDS,
    REMOVAL_COMMANDS,
    powershell_quote,
    render_setup_commands,
)

DOCS = Path(__file__).resolve().parent.parent / "docs"
PLACEHOLDER_DECOYS = [Path("<decoy path 1>"), Path("<decoy path 2>")]


def powershell_blocks(doc: str) -> list[str]:
    text = (DOCS / doc).read_text(encoding="utf-8")
    return re.findall(r"```powershell\n(.*?)```", text, re.DOTALL)


@pytest.mark.parametrize("doc", ["design-traps.md", "usage.md"])
def test_printed_commands_match_the_published_templates(doc: str) -> None:
    setup, removal, audit_restore = powershell_blocks(doc)

    assert render_setup_commands(PLACEHOLDER_DECOYS) == setup
    assert removal == REMOVAL_COMMANDS
    assert audit_restore == AUDIT_RESTORE_COMMANDS


def test_only_the_decoy_lines_change_between_machines() -> None:
    first = render_setup_commands([Path("C:/Users/a/.ssh/id_rsa_backup")]).splitlines()
    second = render_setup_commands(
        [Path("D:/home/b/.aws/credentials.old"), Path("D:/home/b/.kube/config.bak")]
    ).splitlines()
    template = render_setup_commands(PLACEHOLDER_DECOYS).splitlines()

    def without_decoys(lines: list[str]) -> list[str]:
        return [line for line in lines if not re.fullmatch(r"    '[^']*'", line)]

    assert without_decoys(first) == without_decoys(second) == without_decoys(template)


def test_folder_is_created_and_checked_before_any_audit_change() -> None:
    setup = render_setup_commands(PLACEHOLDER_DECOYS)

    folder_checked = setup.index("right after creating it")
    assert folder_checked < setup.index('auditpol.exe" /set')
    assert folder_checked < setup.index("AddAuditRule")


def test_decoys_are_rechecked_around_their_audit_rule() -> None:
    setup = render_setup_commands(PLACEHOLDER_DECOYS)
    loop = setup[setup.index("$auditRule = ") : setup.index("# 5. The event source.")]

    assert loop.index("GetAttributes") < loop.index("SetAccessControl")
    assert loop.rindex("GetAttributes") > loop.index("SetAccessControl")


def test_system_task_runs_only_system32_programs() -> None:
    setup = render_setup_commands(PLACEHOLDER_DECOYS)
    commands = re.findall(r"<Command>(.*?)</Command>", setup)

    assert commands == ["$system32\\wevtutil.exe", "$system32\\eventcreate.exe"]


def test_paths_are_single_quoted() -> None:
    assert (
        powershell_quote(Path("C:/Users/dev/.npmrc"))
        == "'" + str(Path("C:/Users/dev/.npmrc")) + "'"
    )


@pytest.mark.parametrize(
    "bad", ["C:/x\n& evil", "C:/x\r", "C:/x\x00y", "C:/x\x1b", "C:/Users/o'brien/.npmrc"]
)
def test_unsafe_paths_are_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        render_setup_commands([Path(bad)])


def test_setup_needs_at_least_one_decoy() -> None:
    with pytest.raises(ValueError):
        render_setup_commands([])
