"""The admin commands KeySnare prints for the user to run. Never run by KeySnare itself.

These templates are published word for word in docs/design-traps.md and docs/usage.md, so users
can check what they are about to run as administrator. Only the decoy path lines may differ.
{0CCE921D-69AE-11D9-BED3-505054503030} is Windows' fixed ID for the "File System" audit category;
names are translated on non-English systems.
"""

from collections.abc import Sequence
from pathlib import Path

DECOY_LINES = "<decoy lines>"
RELAY_TASK_NAME = "KeySnare Decoy Read Relay"
RELAY_EVENT_ID = 100
EVENT_SOURCE = "KeySnare"
EXPORT_FILE_NAME = "decoy-reads.evtx"

# The folder check, shared by the setup and removal templates.
_FOLDER_CHECK = r"""
$ErrorActionPreference = 'Stop'
$folder = [Environment]::GetFolderPath('CommonApplicationData') + '\KeySnare'
$relay = 'KeySnare Decoy Read Relay'
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$adminsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$link = [IO.FileAttributes]::ReparsePoint
$scheduler = [Activator]::CreateInstance([Type]::GetTypeFromProgID('Schedule.Service'))
$scheduler.Connect()

function Test-KeySnareFolder {
    # Returns '' if the folder is missing or exactly as KeySnare creates it, else the reason.
    if ([IO.File]::Exists($folder)) { return 'is a file' }
    if (-not [IO.Directory]::Exists($folder)) { return '' }
    $info = [IO.DirectoryInfo]::new($folder)
    if ($info.Attributes -band $link) { return 'is a link (junction, symlink or mount point)' }
    foreach ($item in $info.GetFileSystemInfos()) {
        if ($item.Attributes -band $link) { return "contains a link: $($item.Name)" }
        if ($item -is [IO.DirectoryInfo]) { return "contains a folder: $($item.Name)" }
    }
    $acl = $info.GetAccessControl()
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner -ne $adminsSid -and $owner -ne $systemSid) { return "is owned by $owner" }
    $wanted = @{ "$systemSid" = 'FullControl'; "$adminsSid" = 'FullControl'
        "$usersSid" = 'ReadAndExecute, Synchronize' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $seen = @{}
    foreach ($rule in $rules) {
        $id = "$($rule.IdentityReference)"
        if ($rule.IsInherited -or "$($rule.AccessControlType)" -ne 'Allow' -or
            "$($rule.FileSystemRights)" -ne $wanted[$id] -or
            "$($rule.InheritanceFlags)" -ne 'ContainerInherit, ObjectInherit') {
            return 'does not have exactly the permissions KeySnare sets'
        }
        $seen[$id] = $true
    }
    if (-not $acl.AreAccessRulesProtected -or $seen.Count -ne 3 -or $rules.Count -ne 3) {
        return 'does not have exactly the permissions KeySnare sets'
    }
    return ''
}
"""

SETUP_TEMPLATE = (
    r"""
# KeySnare trap setup. Run in an administrator "powershell -NoProfile" window.
# Uses only programs from System32 and built-in .NET classes; no PowerShell cmdlets.
# It first checks everything, and stops without changing anything if a check fails. Then it:
#   1. creates C:\ProgramData\KeySnare (owner Administrators, SYSTEM and Administrators full
#      control, Users read only, no inherited permissions) and checks it again,
#   2. shows the current "File System" audit setting (KeySnare asks you for it next),
#   3. turns on "File System" success auditing,
#   4. adds a "read data" audit rule for Everyone (S-1-1-0) to each KeySnare decoy below,
#      checking just before and just after that the decoy is still a plain file,
#   5. registers the Application log event source "KeySnare",
#   6. registers the SYSTEM task "KeySnare Decoy Read Relay". When a decoy is read, it runs only
#      wevtutil.exe and eventcreate.exe from System32, with the fixed arguments built below.
$decoys = @(
<decoy lines>
)
$system32 = [Environment]::SystemDirectory
$everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')"""
    + _FOLDER_CHECK
    + r"""
# Checks. Nothing has been changed yet.
foreach ($decoy in $decoys) {
    $file = [IO.FileInfo]::new($decoy)
    if (-not $file.Exists -or ($file.Attributes -band $link)) {
        throw "Stopped, nothing was changed: the decoy $decoy is missing or is a link."
    }
}
$problem = Test-KeySnareFolder
if ($problem) {
    throw ("Stopped, nothing was changed: $folder $problem. KeySnare did not make it that way; " +
        'something on this computer may be trying to take over this admin step. Look at it first.')
}
$taskExists = $true
try { $null = $scheduler.GetFolder('\').GetTask($relay) } catch { $taskExists = $false }
if ($taskExists) { throw "Stopped, nothing was changed: a task named '$relay' already exists." }

# 1. The protected folder, created with its final permissions in one step, then checked again.
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetOwner($adminsSid)
$security.SetAccessRuleProtection($true, $false)
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
foreach ($grant in @(@($systemSid, 'FullControl'), @($adminsSid, 'FullControl'),
        @($usersSid, 'ReadAndExecute'))) {
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $grant[0], $grant[1], $inherit, 'None', 'Allow'))
}
$null = [IO.Directory]::CreateDirectory($folder, $security)
$problem = Test-KeySnareFolder
if ($problem) {
    throw "Stopped: right after creating it, $folder $problem. Nothing else was changed."
}

# 2-3. Audit setting.
& "$system32\auditpol.exe" /get /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}'
& "$system32\auditpol.exe" /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable
if ($LASTEXITCODE -ne 0) { throw 'auditpol.exe failed.' }

# 4. A "read data" audit rule on each decoy, checking it is still a plain file before and after.
$auditRule = [Security.AccessControl.FileSystemAuditRule]::new($everyone, 'ReadData', 'Success')
foreach ($decoy in $decoys) {
    if ([IO.File]::GetAttributes($decoy) -band $link) { throw "Stopped: $decoy became a link." }
    $acl = [IO.File]::GetAccessControl($decoy, 'Audit')
    $acl.AddAuditRule($auditRule)
    [IO.File]::SetAccessControl($decoy, $acl)
    if ([IO.File]::GetAttributes($decoy) -band $link) {
        throw ("Stopped: $decoy became a link while its audit rule was set, so the rule may " +
            'be on the file it points to. Run keysnare trap remove, then check that file.')
    }
}

# 5. The event source.
& "$system32\eventcreate.exe" /L APPLICATION /SO KeySnare /T INFORMATION /ID 1 /D 'KeySnare setup'
if ($LASTEXITCODE -ne 0) { throw 'eventcreate.exe failed.' }

# 6. The SYSTEM relay task. Its arguments are fixed here and never change afterwards.
$reads = ($decoys.ForEach({ "Data[@Name='ObjectName']='$_'" })) -join ' or '
$trigger = "*[System[(EventID=4663)]] and *[EventData[$reads]]"
$recent = "$trigger and *[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
$query = "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>" +
    [Security.SecurityElement]::Escape($trigger) + '</Select></Query></QueryList>'
$export = "epl Security `"$folder\decoy-reads.evtx`" `"/q:$recent`" /ow:true"
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$([Security.SecurityElement]::Escape($query))</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="System">
    <Exec>
      <Command>$system32\wevtutil.exe</Command>
      <Arguments>$([Security.SecurityElement]::Escape($export))</Arguments>
    </Exec>
    <Exec>
      <Command>$system32\eventcreate.exe</Command>
      <Arguments>/L APPLICATION /SO KeySnare /T WARNING /ID 100 /D "A KeySnare decoy was read."</Arguments>
    </Exec>
  </Actions>
</Task>
"@
# 2 = create only (never replace a task), 5 = run as a service account (SYSTEM).
$null = $scheduler.GetFolder('\').RegisterTask($relay, $taskXml, 2, 'SYSTEM', $null, 5)
'KeySnare setup finished. Go back to the KeySnare window.'
"""
).lstrip("\n")

REMOVAL_COMMANDS = (
    r"""
# KeySnare trap removal. Run in an administrator "powershell -NoProfile" window.
# Uses only built-in .NET classes; no PowerShell cmdlets. It checks C:\ProgramData\KeySnare like
# setup does, and stops without changing anything if the folder, or anything in it, is a link or
# not as KeySnare made it. Then it disables, stops and deletes the SYSTEM task "KeySnare Decoy
# Read Relay", deletes the Application log event source "KeySnare" (checking again after a
# pause, in case a late relay run re-created it) and deletes the folder. Safe to run twice."""
    + _FOLDER_CHECK
    + r"""
$problem = Test-KeySnareFolder
if ($problem) {
    throw ("Stopped, nothing was changed: $folder $problem. KeySnare did not make it that way; " +
        'look at it before deleting anything.')
}
# Disable and stop the relay first, so no later run can re-create what is deleted next.
$root = $scheduler.GetFolder('\')
$task = $null
try { $task = $root.GetTask($relay) } catch { "The task '$relay' was not found." }
if ($task) {
    $task.Enabled = $false
    $task.Stop(0)
    $root.DeleteTask($relay, 0)
    "Disabled, stopped and deleted the task '$relay'."
}
if ([Diagnostics.EventLog]::SourceExists('KeySnare')) {
    [Diagnostics.EventLog]::DeleteEventSource('KeySnare')
    'Deleted the event source KeySnare.'
}
# A relay run that had already started could still re-create the source, so check again.
[Threading.Thread]::Sleep(5000)
if ([Diagnostics.EventLog]::SourceExists('KeySnare')) {
    [Diagnostics.EventLog]::DeleteEventSource('KeySnare')
    'A late relay run had re-created the event source KeySnare. Deleted it again.'
}
if ([IO.Directory]::Exists($folder)) {
    foreach ($file in [IO.Directory]::GetFiles($folder)) { [IO.File]::Delete($file) }
    [IO.Directory]::Delete($folder)
    "Deleted $folder."
}
'KeySnare removal finished.'
"""
).lstrip("\n")

AUDIT_RESTORE_COMMANDS = r"""
# KeySnare audit restore. Run in an administrator "powershell -NoProfile" window.
# Turns "File System" success auditing back off, as it was before KeySnare.
$auditpol = [Environment]::SystemDirectory + '\auditpol.exe'
& $auditpol /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:disable
""".lstrip("\n")


def render_setup_commands(decoy_paths: Sequence[Path]) -> str:
    """Return the setup commands for these decoys. Raises ValueError for an unsafe path."""
    if not decoy_paths:
        raise ValueError("at least one decoy path is needed")
    decoy_lines = "\n".join(f"    {powershell_quote(path)}" for path in decoy_paths)
    return SETUP_TEMPLATE.replace(DECOY_LINES, decoy_lines)


def powershell_quote(path: Path) -> str:
    """Quote a decoy path for the setup commands. Raises ValueError if it cannot be used safely.

    Paths with ' are refused rather than escaped: the relay's event query puts each path in
    single quotes, and XPath has no way to escape one.
    """
    text = str(path)
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"refusing a path with control characters: {text!r}")
    if "'" in text:
        raise ValueError(f"refusing a path containing ': {text!r}")
    return f"'{text}'"
