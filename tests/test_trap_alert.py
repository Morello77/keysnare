import json
from pathlib import Path

import pytest
from fakes import exported_event

from keysnare.trap.alert import (
    NOTIFY_SCRIPT,
    ProtectedDirs,
    RawEvent,
    decide,
    handle_alert,
    handle_export,
    load_user_allowlist,
    parse_exported_events,
)
from keysnare.trap.decoys import DecoyKind
from keysnare.trap.identity import FileIdentity
from keysnare.trap.manager import TrapPaths, read_alerts
from keysnare.trap.state import AuditBefore, DecoyRecord, TrapState, save_state
from keysnare.winpath import PathForms

DIRS = ProtectedDirs(
    program_data=Path("C:/ProgramData"),
    program_files=Path("C:/Program Files"),
    system32=Path("C:/Windows/System32"),
)
DECOY = Path("C:/Users/dev/.aws/credentials.old")
STATE = TrapState(
    decoys=(DecoyRecord(DecoyKind.AWS_CREDENTIALS, DECOY, FileIdentity(1, 2, 3, 4, 5)),),
    created_folders=(),
    audit_before=AuditBefore.UNKNOWN,
    installed_at="now",
)


def event(
    process: str = "C:/Users/dev/AppData/Local/Temp/stealer.exe", pid: str = "0x1a2b"
) -> RawEvent:
    return RawEvent(process=process, pid=pid, decoy=str(DECOY))


def test_unknown_program_reading_a_decoy_is_an_alert() -> None:
    decision = decide(event(), STATE, DIRS, frozenset(), test_pid=None)

    assert decision.kind == "alert"
    assert decision.pid == 0x1A2B
    assert decision.decoy_label == "AWS credentials"


@pytest.mark.parametrize(
    "process",
    [
        "C:/ProgramData/Microsoft/Windows Defender/Platform/4.18.25010.11-0/MsMpEng.exe",
        "C:/Program Files/Windows Defender/MsMpEng.exe",
        "C:/Windows/System32/SearchProtocolHost.exe",
        "C:/Windows/System32/SearchIndexer.exe",
    ],
)
def test_defender_and_indexer_at_protected_paths_are_ignored(process: str) -> None:
    assert decide(event(process), STATE, DIRS, frozenset(), test_pid=None).kind == "ignored"


@pytest.mark.parametrize(
    "process",
    [
        "C:/Users/dev/AppData/Local/Temp/MsMpEng.exe",
        "C:/ProgramData/Microsoft/Windows Defender/MsMpEng.exe",
        "C:/ProgramData/Microsoft/Windows Defender/Platform/x/sub/MsMpEng.exe",
        "C:/Users/dev/SearchIndexer.exe",
    ],
)
def test_lookalikes_outside_protected_paths_still_alert(process: str) -> None:
    assert decide(event(process), STATE, DIRS, frozenset(), test_pid=None).kind == "alert"


def test_user_allowlisted_program_is_ignored() -> None:
    backup = "D:/Tools/Backup/backup.exe"

    decision = decide(event(backup), STATE, DIRS, frozenset({Path(backup)}), test_pid=None)

    assert decision.kind == "ignored"


@pytest.mark.parametrize(
    "process",
    [
        "C:/python/python.exe",
        "C:/python/pythonw.exe",
        "C:/node/node.exe",
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
        "C:/Windows/System32/cmd.exe",
    ],
)
def test_interpreters_can_never_be_allowlisted(process: str, tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"allow": [process, "D:/Tools/backup.exe"]}))

    allowlist = load_user_allowlist(config)

    assert allowlist == frozenset({Path("D:/Tools/backup.exe")})
    assert decide(event(process), STATE, DIRS, allowlist, test_pid=None).kind == "alert"


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (RawEvent("relative/evil.exe", "0x10", str(DECOY)), "process"),
        (RawEvent("C:/x\nForged line", "0x10", str(DECOY)), "process"),
        (RawEvent("C:/evil.exe", "12; rm", str(DECOY)), "pid"),
        (RawEvent("C:/evil.exe", "0x10", "C:/Users/dev/.ssh/id_ed25519"), "decoy"),
        (RawEvent("C:/evil.exe", "0x10", ""), "decoy"),
    ],
)
def test_malformed_or_forged_events_are_rejected(raw: RawEvent, reason: str) -> None:
    decision = decide(raw, STATE, DIRS, frozenset(), test_pid=None)

    assert decision.kind == "rejected"
    assert reason in decision.reason


EVENT_FORMS = PathForms(
    devices={r"\Device\HarddiskVolume3": "C:"},
    expand_short_names=lambda text: text.replace("PROGRA~3", "ProgramData").replace("DEV~1", "dev"),
)


@pytest.mark.parametrize(
    ("process", "decoy", "kind"),
    [
        (
            r"\Device\HarddiskVolume3\ProgramData\Microsoft"
            r"\Windows Defender\Platform\4.18\MsMpEng.exe",
            r"\??\C:\Users\dev\.aws\credentials.old",
            "ignored",
        ),
        (
            r"C:\PROGRA~3\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            r"C:\Users\DEV~1\.AWS\CREDENTIALS.OLD",
            "ignored",
        ),
        (
            r"\Device\HarddiskVolume3\Users\dev\AppData\Local\Temp\stealer.exe",
            r"\\?\C:\Users\dev\.aws\credentials.old",
            "alert",
        ),
    ],
)
def test_events_in_other_path_forms_are_understood(process: str, decoy: str, kind: str) -> None:
    raw = RawEvent(process=process, pid="0x10", decoy=decoy)

    assert decide(raw, STATE, DIRS, frozenset(), None, EVENT_FORMS).kind == kind


def test_trap_test_reads_are_marked_as_tests() -> None:
    decision = decide(event(pid="0x10"), STATE, DIRS, frozenset(), test_pid=16)

    assert decision.kind == "alert" and decision.is_test


def test_decimal_pid_is_accepted() -> None:
    assert decide(event(pid="4242"), STATE, DIRS, frozenset(), test_pid=None).pid == 4242


class FakeNotifier:
    def __init__(self, works: bool = True) -> None:
        self.works = works
        self.texts: list[str] = []

    def __call__(self, text: str) -> bool:
        self.texts.append(text)
        return self.works


def paths_with_state(tmp_path: Path) -> TrapPaths:
    paths = TrapPaths(home=tmp_path / "home", data_dir=tmp_path / "KeySnare")
    save_state(STATE, paths.state_file)
    return paths


def test_alert_is_logged_and_notified(tmp_path: Path) -> None:
    paths = paths_with_state(tmp_path)
    notifier = FakeNotifier()

    handle_alert(event(), paths, DIRS, notifier, now="2026-10-27T12:00Z")

    [logged] = read_alerts(paths)
    assert logged["kind"] == "alert"
    assert logged["process"] == "C:/Users/dev/AppData/Local/Temp/stealer.exe"
    assert logged["notified"] is True
    assert "stealer.exe" in notifier.texts[0]
    assert "AWS credentials" in notifier.texts[0]


def test_ignored_and_rejected_events_are_logged_but_not_counted_or_notified(
    tmp_path: Path,
) -> None:
    paths = paths_with_state(tmp_path)
    notifier = FakeNotifier()

    handle_alert(event("C:/Windows/System32/SearchIndexer.exe"), paths, DIRS, notifier, "t")
    handle_alert(RawEvent("bad", "x", "y"), paths, DIRS, notifier, "t")

    lines = paths.alerts_file.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["kind"] for line in lines] == ["ignored", "rejected"]
    assert read_alerts(paths) == []
    assert notifier.texts == []


def test_alert_is_logged_even_if_the_notification_fails(tmp_path: Path) -> None:
    paths = paths_with_state(tmp_path)

    handle_alert(event(), paths, DIRS, FakeNotifier(works=False), now="t")

    assert read_alerts(paths)[0]["notified"] is False


def test_exported_events_are_parsed_as_data() -> None:
    export = exported_event("7", "C:/Temp/a & b.exe") + "\r\n" + exported_event("8", "C:/x.exe")

    exported_decoy = r"C:\Users\dev\.aws\credentials.old"
    assert list(parse_exported_events(export)) == [
        RawEvent("C:/Temp/a & b.exe", "0x10", exported_decoy, "7"),
        RawEvent("C:/x.exe", "0x10", exported_decoy, "8"),
    ]


def test_each_exported_event_alerts_exactly_once(tmp_path: Path) -> None:
    paths = paths_with_state(tmp_path)
    notifier = FakeNotifier()
    export = exported_event("7", "C:/Temp/stealer.exe")

    first = handle_export(export, paths, DIRS, notifier, "t1")
    second = handle_export(
        export + exported_event("9", "C:/Temp/other.exe"), paths, DIRS, notifier, "t2"
    )

    assert [d.process for d in first] == ["C:/Temp/stealer.exe"]
    assert [d.process for d in second] == ["C:/Temp/other.exe"]
    assert len(notifier.texts) == 2
    assert [a["record_id"] for a in read_alerts(paths)] == ["7", "9"]


@pytest.mark.parametrize(
    "export",
    [
        '<!DOCTYPE x [<!ENTITY a "aaaa">]>' + exported_event("1", "C:/x.exe"),
        "<Event><unclosed>",
    ],
)
def test_hostile_or_broken_exports_are_rejected_and_logged(tmp_path: Path, export: str) -> None:
    paths = paths_with_state(tmp_path)

    assert handle_export(export, paths, DIRS, FakeNotifier(), "t") == []
    [entry] = [json.loads(line) for line in paths.alerts_file.read_text().splitlines()]
    assert entry["kind"] == "rejected" and "unreadable export" in entry["reason"]


def test_non_numeric_record_id_is_rejected() -> None:
    raw = RawEvent("C:/x.exe", "0x10", str(DECOY), record_id="7; drop")

    assert decide(raw, STATE, DIRS, frozenset(), None).kind == "rejected"


def test_notification_script_reads_text_only_from_the_environment() -> None:
    assert "$env:KEYSNARE_ALERT_TEXT" in NOTIFY_SCRIPT
    assert "SecurityElement]::Escape" in NOTIFY_SCRIPT
