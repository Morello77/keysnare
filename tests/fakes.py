"""Test doubles shared by the trap tests."""

from pathlib import Path
from xml.sax.saxutils import escape


class FakeSystem:
    def __init__(
        self, elevated: bool = False, fail_register: bool = False, fail_mark: bool = False
    ) -> None:
        self.elevated = elevated
        self.fail_register = fail_register
        self.fail_mark = fail_mark
        self.task_xml: str | None = None
        self.not_indexed: list[Path] = []

    def is_elevated(self) -> bool:
        return self.elevated

    def user_sid(self) -> str:
        return "S-1-5-21-1-2-3-1001"

    def mark_not_indexed(self, path: Path) -> None:
        if self.fail_mark:
            raise OSError("The parameter is incorrect")
        self.not_indexed.append(path)

    def register_task(self, xml: str) -> None:
        if self.fail_register:
            raise OSError("Access is denied")
        self.task_xml = xml

    def delete_task(self) -> bool:
        existed = self.task_xml is not None
        self.task_xml = None
        return existed

    def task_status(self) -> str | None:
        return "Ready" if self.task_xml is not None else None


def exported_event(
    record: str, process: str, pid: str = "0x10", decoy: str = r"C:\Users\dev\.aws\credentials.old"
) -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f"<System><EventID>4663</EventID><EventRecordID>{record}</EventRecordID></System>"
        f'<EventData><Data Name="ObjectName">{escape(decoy)}</Data>'
        f'<Data Name="ProcessId">{pid}</Data>'
        f'<Data Name="ProcessName">{escape(process)}</Data></EventData></Event>'
    )
