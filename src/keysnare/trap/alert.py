"""The alert handler, started non-elevated by the alert task when a decoy is read.

It reads the decoy-read events the SYSTEM relay exported to the protected ProgramData folder.
Everything in them comes from events a hostile program can influence, so it is validated and
treated as data only: never passed to a shell, never pasted into a script.
"""

import json
import ntpath
import re
import xml.etree.ElementTree as ET  # noqa: S405 - DTDs and entities are refused before parsing
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from keysnare.trap.decoys import DecoyKind
from keysnare.trap.manager import TrapPaths
from keysnare.trap.state import TrapState, load_state
from keysnare.winpath import NO_FORMS, PathForms, canonical, parent_of, same_windows_path

Notifier = Callable[[str], bool]
DecisionKind = Literal["alert", "ignored", "rejected"]

MAX_PATH_LENGTH = 32767
PID = re.compile(r"0x[0-9a-fA-F]{1,8}|[0-9]{1,10}")
RECORD_ID = re.compile(r"[0-9]{1,20}")
EVENT_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"
# wevtutil never writes these; refusing them rules out entity-expansion tricks in the parser.
FORBIDDEN_XML = ("<!DOCTYPE", "<!ENTITY")
# Poisoned npm and PyPI packages run inside these, so they are never allowlisted.
INTERPRETERS = frozenset(
    {
        "python.exe",
        "pythonw.exe",
        "py.exe",
        "node.exe",
        "deno.exe",
        "bun.exe",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "bash.exe",
        "sh.exe",
        "java.exe",
        "javaw.exe",
        "ruby.exe",
        "perl.exe",
        "php.exe",
    }
)
INDEXER_PROGRAMS = frozenset({"searchprotocolhost.exe", "searchindexer.exe"})
DECOY_LABELS = {
    DecoyKind.SSH_KEY: "SSH key",
    DecoyKind.AWS_CREDENTIALS: "AWS credentials",
    DecoyKind.DOCKER_CONFIG: "Docker login",
    DecoyKind.KUBECONFIG: "Kubernetes config",
    DecoyKind.GH_HOSTS: "GitHub CLI token",
    DecoyKind.GCLOUD_ADC: "Google Cloud credentials",
    DecoyKind.GIT_CREDENTIALS: "Git credentials",
    DecoyKind.NPMRC: "npm token",
}
TEST_PID_FILE = "test-pid.txt"
NOTIFY_SCRIPT = (
    "$text = [Security.SecurityElement]::Escape($env:KEYSNARE_ALERT_TEXT);"
    "$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
    " ContentType = WindowsRuntime];"
    "$null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument,"
    " ContentType = WindowsRuntime];"
    "$xml = [Windows.Data.Xml.Dom.XmlDocument]::new();"
    "$xml.LoadXml(\"<toast><visual><binding template='ToastGeneric'>"
    '<text>KeySnare alert</text><text>$text</text></binding></visual></toast>");'
    "$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe';"
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app)"
    ".Show([Windows.UI.Notifications.ToastNotification]::new($xml))"
)


@dataclass(frozen=True)
class RawEvent:
    """The fields of one decoy-read event, exactly as exported. Untrusted."""

    process: str
    pid: str
    decoy: str
    record_id: str = ""


@dataclass(frozen=True)
class ProtectedDirs:
    """Folders only administrators can write to, from Windows APIs rather than variables."""

    program_data: Path
    program_files: Path
    system32: Path


@dataclass(frozen=True)
class Decision:
    """What to do with one decoy read."""

    kind: DecisionKind
    reason: str
    process: str = ""
    pid: int | None = None
    decoy: str = ""
    decoy_label: str = ""
    is_test: bool = False


def decide(
    raw: RawEvent,
    state: TrapState | None,
    dirs: ProtectedDirs,
    user_allowlist: frozenset[Path],
    test_pid: int | None,
    forms: PathForms = NO_FORMS,
) -> Decision:
    """Validate an event and decide whether it is an alert."""
    if raw.record_id and not RECORD_ID.fullmatch(raw.record_id):
        return Decision("rejected", "invalid event record id")
    if not _is_safe_absolute_path(raw.process, forms):
        return Decision("rejected", "invalid process path")
    if not PID.fullmatch(raw.pid):
        return Decision("rejected", "invalid pid")
    decoys = state.decoys if state else ()
    record = next((r for r in decoys if same_windows_path(r.path, raw.decoy, forms)), None)
    if record is None:
        return Decision("rejected", "not a KeySnare decoy")
    pid = int(raw.pid, 16) if raw.pid.startswith("0x") else int(raw.pid)
    allowed = _allow_reason(raw.process, dirs, user_allowlist, forms)
    return Decision(
        kind="ignored" if allowed else "alert",
        reason=allowed or "decoy read",
        process=raw.process,
        pid=pid,
        decoy=str(record.path),
        decoy_label=DECOY_LABELS[record.kind],
        is_test=not allowed and pid == test_pid,
    )


def load_user_allowlist(config_file: Path) -> frozenset[Path]:
    """Return the programs the user allowed in config.json, always dropping interpreters."""
    try:
        config = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    entries = config.get("allow", []) if isinstance(config, dict) else []
    return frozenset(
        Path(entry)
        for entry in entries
        if isinstance(entry, str) and _program_name(entry, NO_FORMS) not in INTERPRETERS
    )


def handle_alert(
    raw: RawEvent,
    paths: TrapPaths,
    dirs: ProtectedDirs,
    notify: Notifier,
    now: str,
    forms: PathForms = NO_FORMS,
) -> Decision:
    """Decide, log every decision, and notify the user of real alerts."""
    decision = decide(
        raw,
        load_state(paths.state_file),
        dirs,
        load_user_allowlist(paths.data_dir / "config.json"),
        _test_pid(paths),
        forms,
    )
    entry: dict[str, object] = {"time": now, "kind": decision.kind, "reason": decision.reason}
    if RECORD_ID.fullmatch(raw.record_id):
        entry["record_id"] = raw.record_id
    if decision.kind != "rejected":
        entry |= {"process": decision.process, "pid": decision.pid, "decoy": decision.decoy}
    if decision.kind == "alert":
        entry["test"] = decision.is_test
        entry["notified"] = notify(alert_text(decision))
    _log(paths, entry)
    return decision


def handle_export(
    export_xml: str,
    paths: TrapPaths,
    dirs: ProtectedDirs,
    notify: Notifier,
    now: str,
    forms: PathForms = NO_FORMS,
) -> list[Decision]:
    """Handle every exported decoy-read event not handled before, each exactly once."""
    try:
        events = list(parse_exported_events(export_xml))
    except ValueError as error:
        _log(paths, {"time": now, "kind": "rejected", "reason": f"unreadable export: {error}"})
        return []
    handled = _handled_record_ids(paths)
    return [
        handle_alert(event, paths, dirs, notify, now, forms)
        for event in events
        if event.record_id not in handled
    ]


def parse_exported_events(export_xml: str) -> Iterator[RawEvent]:
    """Read `wevtutil qe /f:xml` output. Raises ValueError for anything that is not plain XML."""
    if any(marker in export_xml for marker in FORBIDDEN_XML):
        raise ValueError("the export contains a DTD or entity declaration")
    try:
        root = ET.fromstring(f"<Events>{export_xml}</Events>")  # noqa: S314 - DTDs refused above
    except ET.ParseError as error:
        raise ValueError(f"the export is not valid XML: {error}") from error
    for event in root.iter(f"{EVENT_NAMESPACE}Event"):
        data = {
            item.get("Name", ""): item.text or "" for item in event.iter(f"{EVENT_NAMESPACE}Data")
        }
        yield RawEvent(
            process=data.get("ProcessName", ""),
            pid=data.get("ProcessId", ""),
            decoy=data.get("ObjectName", ""),
            record_id=event.findtext(f"{EVENT_NAMESPACE}System/{EVENT_NAMESPACE}EventRecordID")
            or "",
        )


def alert_text(decision: Decision) -> str:
    """Return the notification text for an alert."""
    prefix = "TEST: " if decision.is_test else ""
    return (
        f"{prefix}A program read your decoy {decision.decoy_label}. "
        f"Program: {decision.process}. If this was not you, run 'keysnare scan' and rotate "
        "your real credentials. If it was you, you can ignore this."
    )


def _allow_reason(
    process: str, dirs: ProtectedDirs, user_allowlist: frozenset[Path], forms: PathForms
) -> str:
    name = _program_name(process, forms)
    folder = parent_of(process, forms)
    if name in INTERPRETERS:
        return ""
    if name == "msmpeng.exe" and _is_defender_folder(folder, dirs, forms):
        return "Microsoft Defender"
    if name in INDEXER_PROGRAMS and folder == canonical(dirs.system32, forms):
        return "Windows Search indexer"
    if any(same_windows_path(allowed, process, forms) for allowed in user_allowlist):
        return "allowed in config.json"
    return ""


def _is_defender_folder(folder: str, dirs: ProtectedDirs, forms: PathForms) -> bool:
    platform = canonical(f"{dirs.program_data}\\Microsoft\\Windows Defender\\Platform", forms)
    program_files = canonical(f"{dirs.program_files}\\Windows Defender", forms)
    return ntpath.dirname(folder) == platform or folder == program_files


def _program_name(process: str, forms: PathForms) -> str:
    return ntpath.basename(canonical(process, forms)).lower()


def _is_safe_absolute_path(text: str, forms: PathForms) -> bool:
    return (
        0 < len(text) <= MAX_PATH_LENGTH
        and not any(ord(char) < 32 for char in text)
        and ntpath.isabs(canonical(text, forms))
    )


def _log(paths: TrapPaths, entry: dict[str, object]) -> None:
    paths.data_dir.mkdir(parents=True, exist_ok=True)
    with open(paths.alerts_file, "a", encoding="utf-8") as log:
        log.write(json.dumps(entry) + "\n")


def _handled_record_ids(paths: TrapPaths) -> set[str]:
    try:
        lines = paths.alerts_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return set()
    handled = set()
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("record_id"), str):
            handled.add(entry["record_id"])
    return handled


def _test_pid(paths: TrapPaths) -> int | None:
    try:
        return int((paths.data_dir / TEST_PID_FILE).read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None
