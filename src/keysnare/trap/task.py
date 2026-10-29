"""The user's Task Scheduler task that starts the alert handler after the SYSTEM relay fires.

It runs as the user with least privilege: no elevated context ever runs KeySnare's code. It is
triggered by the relay's Application-log event, which standard users may subscribe to (they may
not subscribe to the Security log; see docs/design-traps.md).
"""

from pathlib import Path
from xml.sax.saxutils import escape

from keysnare.trap.admin import EVENT_SOURCE, RELAY_EVENT_ID

TASK_NAME = "\\KeySnare\\DecoyRead"
HANDLER_ARGUMENTS = "-m keysnare trap alert"


def relay_query() -> str:
    """Return the event query for the relay's fixed "decoy read" event."""
    select = f"*[System[Provider[@Name='{EVENT_SOURCE}'] and EventID={RELAY_EVENT_ID}]]"
    return (
        '<QueryList><Query Id="0" Path="Application">'
        f'<Select Path="Application">{escape(select)}</Select>'
        "</Query></QueryList>"
    )


def build_task_xml(handler: Path, user_sid: str) -> str:
    """Return the Task Scheduler XML for the user's alert task."""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>KeySnare</Author>
    <Description>Shows a KeySnare alert when a program reads a decoy credential.</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>{escape(relay_query())}</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user_sid)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(str(handler))}</Command>
      <Arguments>{escape(HANDLER_ARGUMENTS)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""
