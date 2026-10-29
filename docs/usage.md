# Using KeySnare

KeySnare runs fully offline. It never sends anything over the network and never prints a full
secret.

## Commands

```
keysnare --version
keysnare scan [PATH] [--json | --sarif | --quiet] [--fail-on LEVEL] [--show-full-paths]
              [--output FILE]
```

`keysnare scan` with no path scans your home folder: every known credential location (see
[credential-locations.md](credential-locations.md)) plus a walk for `.env`, `.npmrc`,
`nuget.config`, `.cursor/mcp.json`, `*.ppk` and `.git/config` files. With a `PATH`, it scans only
that folder or file.

`python -m keysnare` works the same way as `keysnare`.

## Options

| Option | Effect |
|---|---|
| `--json` | Print a JSON report instead of the terminal report. |
| `--sarif` | Print a SARIF 2.1.0 report, for code-scanning tools such as GitHub code scanning. |
| `--quiet` | Print only the one-line summary. |
| `--fail-on LEVEL` | Lowest severity that makes the exit code 1: `critical`, `high` (default), `medium` or `low`. |
| `--show-full-paths` | Show full paths. By default your home folder is shown as `~`. |
| `--output FILE` | Write the report to `FILE` instead of the screen: UTF-8 without a byte-order mark, `\n` line endings, no colors. |

`--json`, `--sarif` and `--quiet` cannot be combined.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the `--fail-on` level. There may be findings below it. |
| `1` | At least one finding at or above the `--fail-on` level. |
| `2` | Error: invalid arguments, a path that does not exist, or the scan failed. |

Example: fail a CI job only for critical findings with `keysnare scan . --fail-on critical`.

## What the reports contain

- **Masked values only.** Secrets are shown as their first and last 4 characters
  (`AKIA****WXYZ`). Secrets shorter than 16 characters are shown as `****`. Files that are
  themselves the finding, such as an SSH key without a passphrase, show no value at all.
- **Home-relative paths.** Your home folder is shown as `~`, so screenshots and reports are safe to
  share. In SARIF, such paths are relative to a `HOME` base that is named but never given a
  location. Use `--show-full-paths` to see full paths.
- **Why and how to fix.** Every finding states its severity, why it is risky, and fix steps for
  your operating system.
- **Skipped paths.** Files and folders that could not be read are listed, never silently ignored.

## Colors

The terminal report uses colors only when it is printed to a real terminal. Set the `NO_COLOR`
environment variable (any non-empty value) to turn colors off. Redirected or piped output never
contains colors.

## Decoy traps (Windows)

```
keysnare trap install [--yes]
keysnare trap status
keysnare trap test
keysnare trap remove [--purge]
```

Traps plant fake, clearly marked credentials where stealers look, and show a Windows
notification when a program reads one. The full design, including every system change and how
it is undone, is in [design-traps.md](design-traps.md).

Run trap commands in a **normal** terminal. KeySnare refuses to run as administrator. The
admin-only changes (the protected folder `C:\ProgramData\KeySnare`, file auditing, an audit rule
on each decoy, the `KeySnare` event source and the SYSTEM relay task) are made by you, with
commands KeySnare prints. **Before running them, check they match the templates below.** The only
part that may differ is the list of decoy paths in the setup commands: one line per decoy, in
single quotes.

To run them: press Win+R, type `powershell -NoProfile`, press Ctrl+Shift+Enter, then paste.

Setup, printed by `keysnare trap install`:

```powershell
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
    '<decoy path 1>'
    '<decoy path 2>'
)
$system32 = [Environment]::SystemDirectory
$everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
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
```

Removal, printed by `keysnare trap remove` every time:

```powershell
# KeySnare trap removal. Run in an administrator "powershell -NoProfile" window.
# Uses only built-in .NET classes; no PowerShell cmdlets. It checks C:\ProgramData\KeySnare like
# setup does, and stops without changing anything if the folder, or anything in it, is a link or
# not as KeySnare made it. Then it disables, stops and deletes the SYSTEM task "KeySnare Decoy
# Read Relay", deletes the Application log event source "KeySnare" (checking again after a
# pause, in case a late relay run re-created it) and deletes the folder. Safe to run twice.
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
```

Audit restore, printed by `keysnare trap remove` when success auditing was off before you
installed:

```powershell
# KeySnare audit restore. Run in an administrator "powershell -NoProfile" window.
# Turns "File System" success auditing back off, as it was before KeySnare.
$auditpol = [Environment]::SystemDirectory + '\auditpol.exe'
& $auditpol /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:disable
```

`trap remove` keeps your alert history (`%LOCALAPPDATA%\KeySnare\alerts.jsonl`) if it contains
any alerts, and prints where it is. `--purge` deletes it too.

**Microsoft Store Python.** Windows keeps the files that Store Python writes under AppData in a
private folder, `%LOCALAPPDATA%\Packages\<Python package>\LocalCache\Local\KeySnare`, so that is
where the trap records and alert history live. `trap install` says so before it asks to continue.
Uninstalling or resetting that Python deletes the folder; `trap remove` can then only list the
decoys for you to delete by hand. For traps, the python.org installer avoids this.

## Saving a report to a file

Use `--output`, especially in PowerShell:

```
keysnare scan --sarif --output keysnare.sarif
```

Avoid `>` in Windows PowerShell 5.1: it re-encodes the report and adds a byte-order mark that
strict JSON and SARIF readers reject. `--output` writes the file directly, exactly as KeySnare
produced it. If the file cannot be written, the exit code is `2`.
