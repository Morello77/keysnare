# Design: decoy traps (Windows prototype)

Status: implemented in v0.1.

## Goal

Plant fake credentials where credential stealers look, and tell the user when any program reads
one. A real tool has no reason to open a decoy, so a read is a strong sign that something on the
machine is collecting credentials.

## Safety rules for this feature

1. **Existing files are never modified.** KeySnare only *creates new* decoy files where no file
   exists. It never edits, appends to, renames or deletes a file it did not create.
2. **Decoys never break the user's tools.** A decoy goes only where no installed tool or client
   library reads it in normal use.
3. **KeySnare's code never runs elevated.** No administrator or SYSTEM context ever executes code
   from a user-writable path (see "Security of KeySnare itself").
4. **Every system change is recorded and reversible.** `keysnare trap remove` undoes them.
5. **Development safety:** trap features are tested only in disposable GitHub Actions Windows
   runners or a VM, never on a developer's own machine.

---

## Where decoys go

Every decoy must pass these checks at install time:

- no file exists at that path;
- no tool or client library reads that path on Windows, based on the tool's documented lookup
  order, with the environment variables that change that order checked at install time;
- the path is not named in a config the user controls (`IdentityFile` in `~/.ssh/config`, any
  file listed in `KUBECONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, and so on).

A decoy path must also not contain `'`. The event query that watches decoys puts each path in
single quotes, and Windows paths can never contain the other quote character, `"`. On a machine
whose home folder contains `'` (for example `C:\Users\O'Brien`), traps are not available, and
`trap install` says so.

### Sibling files in folders stealers copy whole

Many stealers copy entire folders such as `.ssh`, `.aws`, `.docker` and `.kube`. The real tools
read only specific file names inside them, so an extra file with another name is never read by
them. These decoys are safe **whether or not the tool is installed**.

| Decoy | Why the real tool never reads it |
|---|---|
| `~\.ssh\id_rsa_backup` | `ssh` tries only default key names (`id_rsa`, `id_ed25519`, ...) and names listed in `~/.ssh/config` |
| `~\.aws\credentials.old` | The AWS CLI and SDKs read only `credentials`, `config` and their cache folders |
| `~\.docker\config.json.bak` | Docker reads only `config.json` (plus its `contexts`, `buildx` and plugin folders) |
| `~\.kube\config.bak` | kubectl reads `~/.kube/config` or the files in `KUBECONFIG` only |

### Cross-platform paths that Windows tools do not use

Stealers written for Linux and macOS often check Linux-style paths on Windows too. On Windows,
the real tools store these files elsewhere.

| Decoy | Real Windows location | Planted only if |
|---|---|---|
| `~\.config\gh\hosts.yml` | `%AppData%\GitHub CLI\hosts.yml`. GitHub CLI uses `~/.config/gh` on Windows only when `XDG_CONFIG_HOME` points there ([gh manual](https://cli.github.com/manual/gh_help_environment)) | `XDG_CONFIG_HOME` and `GH_CONFIG_DIR` are unset or point elsewhere |
| `~\.config\gcloud\application_default_credentials.json` | `%APPDATA%\gcloud\`. gcloud and Google's client libraries use `%APPDATA%` on Windows ([gcloud configurations](https://docs.cloud.google.com/sdk/gcloud/guide/configurations), [AIP-4113](https://google.aip.dev/auth/4113)) | `CLOUDSDK_CONFIG` and `GOOGLE_APPLICATION_CREDENTIALS` do not point there |

### Standard locations, only when unused

These are the real locations on Windows, so they are planted only when the file is absent **and**
the tool that reads it is not installed (a read-only PATH lookup).

| Decoy | Planted only if |
|---|---|
| `~\.git-credentials` | file absent and Git's credential helper is not `store` (Git reads this file only with `store`) |
| `~\.aws\credentials` | file absent and `aws` not installed |
| `~\.docker\config.json` | file absent and `docker` not installed |
| `~\.npmrc` | file absent and `npm` not installed |
| `~\.kube\config` | file absent and `kubectl` not installed |

### Deliberately not used

- **`.env` anywhere:** libraries such as python-dotenv search parent folders for `.env`, so a
  decoy could be loaded into the user's own programs.
- **`~\.netrc` / `~\_netrc`:** Git's HTTPS transport (through curl) reads it on every connection,
  causing false alarms and possibly failed pushes.
- **`~\.pypirc`:** an upload tool could use the decoy login.
- **`~\.azure\`:** the Azure CLI uses this folder on Windows too, and old versions read extra file
  names in it.
- **Anything inside project folders:** it could be committed to Git by accident.
- **macOS-only paths (`~/Library/...`):** creating a `Library` folder in a Windows home folder
  looks odd, for little gain.

### Proving no tool reads the decoys

Documentation can be wrong, so the Windows integration test checks it. GitHub's `windows-latest`
runners come with the GitHub CLI, AWS CLI, Google Cloud CLI, kubectl, Docker, Git and npm. After
`trap install`, the test runs a read-only command from each (`gh auth status`,
`aws configure list`, `gcloud config list`, `kubectl config view`, `docker info`,
`git config --list`, `npm config list`). It then checks that **no alert** was raised and each
tool's output is unchanged.

`trap install` prints the exact list of decoys it will create before doing anything.

## What a decoy looks like

**Worth stealing.** Each decoy has the exact format of the real file, with values in the right
shape (correct prefixes and lengths), so a stealer's pattern matching picks it up.

**Clearly marked.** Every decoy carries `keysnare-decoy` where a human reading it sees it at once:

- INI and YAML files: a first line `# KeySnare decoy - not a real credential.`
- JSON files: a `"_comment": "KeySnare decoy - not a real credential."` field.
- Values carry a fixed marker, for example an AWS key ID starting `AKIAKEYSNAREDECOY` and a GitHub
  token starting `ghp_KeySnareDecoy`. AWS key IDs use only A–Z and 2–7, which the marker fits.
- SSH key: the key's comment field (stored inside the file) is `keysnare-decoy`.

**Never valid.** Values are random characters plus the fixed marker, generated at install time.
No provider ever issued them, so they authenticate nowhere. The SSH key is random bytes in the
OpenSSH file format, not a working key pair. The repository never contains a complete decoy
value; values are built at runtime, so push protection and secret scanners are never triggered.

**KeySnare never reads a decoy's data after install.** Reading it is exactly what the audit rule
watches, so it would raise a false alarm (and wake the SYSTEM relay). `trap test`, through a
separate program, is the only intended reader.

- `keysnare scan` reads the trap state file and reports decoy paths as "decoy (not read)".
- `trap status` and `trap remove` decide whether a decoy is unchanged from its **file identity**,
  recorded right after it was written: size, last-modified time, creation time, and the NTFS file
  ID (volume serial number and file index). KeySnare gets these by opening the file with
  `FILE_READ_ATTRIBUTES` access only, never `FILE_READ_DATA`, and without following links. A
  replaced file gets a new file ID, even with the same size, times and content; an edited file
  gets a new size or modified time.

---

## Detecting reads on Windows

| Option | How it works | Admin? | Background program? | Reliability | Names the program? |
|---|---|---|---|---|---|
| **A. File auditing, Event 4663** | Turn on "File System" auditing and add an audit rule (SACL) to each decoy. Windows writes Security event 4663 for each read. | To set up | No | High; done by the kernel, survives reboots | Yes, full path and process ID |
| B. Last-access time | Watch the "last accessed" time | No | Needs polling | Low: often switched off, updated up to an hour late, changed by antivirus | No |
| C. ETW (Kernel-File events) | A program subscribes to the kernel's live file events | Yes | **Yes, always running** | High while running | Yes |
| D. File change notifications | Windows reports changes to files | No | Yes | Reports writes, **not reads** | No |
| E. Sysmon | Sysinternals logging service | Yes | Yes (a service) | Does not log file reads | n/a |
| F. Filter driver | Kernel driver sees every file open | Yes | Yes (driver) | Highest | Yes |

**Recommendation: A, file auditing with Event 4663.** It is built into every Windows edition,
including Home. It needs no running program, names the program that read the file, and adds
almost nothing to the Security log, because audit rules exist only on the decoys. The audit rule
watches **"Read data"** only, so browsing a folder or reading file attributes (what Explorer does)
raises no event. C is the right base for a later real-time monitor (planned in C++ or C#), but
it needs a program running all the time.

---

## Security of KeySnare itself

### The threat

KeySnare is installed with pip, so its code lives in user-writable folders (a virtual environment
or `site-packages`). Malware running as the user, **without** admin rights, can change that code.

A natural design would have a scheduled task run KeySnare's Python code **with highest
privileges** whenever a decoy is read. Malware could then change KeySnare's code and read a decoy
on purpose to get its own code run as administrator. That is a privilege escalation: KeySnare
would make the machine less safe.

### The rule

**No elevated context (administrator or SYSTEM) ever executes code from a user-writable path.**

- KeySnare's Python code always runs **non-elevated**: scans, the alert handler, `trap install`,
  `trap remove`, everything.
- KeySnare refuses to run when started elevated, and says to use a normal terminal.
- The few changes that need admin rights are made by the **user**, running a short list of
  commands that use only **built-in Windows binaries**, which KeySnare prints (see "Install
  flow").

### The relay design

A SYSTEM task triggered by a decoy read runs two built-in programs from System32, with arguments
fixed at install time: `wevtutil.exe` copies the recent decoy-read events into
`C:\ProgramData\KeySnare\decoy-reads.evtx`, then `eventcreate.exe` writes a fixed "decoy read"
event to the Application log. The user's own least-privilege task, triggered by that Application
event, starts KeySnare's handler, which reads the exported events with `wevtutil.exe qe`. Alerts
name the program, its process ID and the decoy.

No event text ever reaches an elevated command: the SYSTEM task's arguments are fixed when the
administrator registers it. The events travel as data, through a file only administrators can
write.

### Alternatives considered

| Alternative | What runs elevated | Why it was not used |
|---|---|---|
| A user task triggered directly by Security-log events, receiving the event fields from the trigger (`ValueQueries`) | Nothing | Windows refuses to register it (see below). |
| Adding the user to the "Event Log Readers" group, so a non-elevated handler can read the Security log | Nothing at alert time | Lets **any** malware running as the user read the whole Security log (logons and more). |
| A SYSTEM relay that only writes the fixed Application event, without exporting events | `eventcreate.exe` only | Alerts could not say which program read the decoy, because the program name cannot reach an elevated command without putting event text into its arguments. |
| An elevated PowerShell script as the handler | PowerShell, running code KeySnare wrote | Breaks the rule above. |

The integration test on a Windows runner shows why a direct Security-log trigger cannot work:

| A task triggered by Security-log events, running as a standard user… | Result |
|---|---|
| registered by the standard user | Access is denied |
| registered by an administrator, still running as the standard user (least privilege) | Access is denied |
| (for comparison) triggered by **Application**-log events, registered by the standard user | Allowed |

Windows requires that a task's own account can read the Security log, and standard users
cannot.

### Event text is data, never code

- The handler takes no event fields on its command line. It reads them from the exported events
  with the built-in `wevtutil.exe qe`, as untrusted data. It refuses any export that contains a
  `<!DOCTYPE` or `<!ENTITY` declaration (wevtutil never writes one) before parsing it.
- The handler validates every field (an absolute path, no control characters, a numeric process
  ID, and a decoy KeySnare recorded). It drops events that fail, and logs that it did. Each event
  is alerted once, tracked by its event record ID.
- Fields are never passed to a shell or interpreted. The notification text reaches PowerShell
  through an environment variable and is XML-escaped inside the notification template. It is
  never pasted into the PowerShell command.

### The ProgramData folder: junction and symlink attacks

`C:\ProgramData` lets **standard users create folders**. That makes a classic attack possible:
malware running as the user pre-creates `C:\ProgramData\KeySnare`, owned by itself, or makes it
a junction or symlink pointing somewhere else. Later, SYSTEM writes the exported events "into"
it, and the write lands wherever the attacker chose, or the attacker can read or swap the files
the handler trusts.

Protections, all in the admin commands, which run before any change:

- **Refuse a folder KeySnare did not create.** If `C:\ProgramData\KeySnare` already exists, setup
  continues only if it is owned by Administrators or SYSTEM, has exactly KeySnare's permissions
  (below), and holds no subfolders. Otherwise it stops, changes nothing, and explains that
  something on the computer may be trying to take over the admin step.
- **Refuse links.** Setup and removal stop if the folder, or anything in it, is a reparse point:
  a junction, symlink or mount point.
- **No unsafe moment at creation.** The folder is created with its final permissions in one step
  (`Directory.CreateDirectory(path, security)`), so it never exists with the default ProgramData
  permissions, even briefly.
- **Exact permissions:** owner Administrators; inheritance from `C:\ProgramData` turned off;
  SYSTEM and Administrators full control; Users read and execute only. Standard users can never
  create, change, rename or delete anything inside it, or the folder itself.
- **Fixed programs and arguments.** The SYSTEM task calls `wevtutil.exe` and `eventcreate.exe`
  by their absolute System32 paths (never through `PATH`), with arguments fixed when the admin
  registers it. `wevtutil epl ... /ow:true` overwrites its one target file in place, and its query
  (the decoy paths, last 24 hours) is fixed at install time.
- **The relay task sits at the top level of Task Scheduler.** Standard users can create task
  folders, so the relay is not placed in the user's own `\KeySnare\` folder. It is registered in
  "create only" mode, so if a task with its name already exists, setup stops.

Malware can still pre-create the folder simply to **block** installation. That is a
denial of service, not an escalation, and setup's message says what to look at.

### Remaining risks, stated honestly

- **Malware running as the user can silence alerts.** The alert task, handler and alert log all
  belong to the user, so malware with the user's rights could disable or change them before
  reading decoys. Two things still hold: (a) Windows keeps writing event 4663 to the Security log,
  which only an administrator can clear, so there is evidence for later; (b) the decoys stay
  worthless to the attacker. A tamper-proof alert path needs the later real-time monitor running
  as a protected service.
- **A modified KeySnare could print malicious admin commands.** KeySnare's code is
  user-writable, so malware could change it to print different commands, and the user would run
  them as administrator. Mitigations:
  - The commands are readable and **identical every time except for the list of decoy paths**.
    The exact templates are published below and in `docs/usage.md`, so users can compare before
    running them. A test makes sure the printed commands match the published templates. The setup
    commands are about 150 lines long, because every check is spelled out.
  - The commands use only programs from System32 (found through `[Environment]::SystemDirectory`,
    not an environment variable) and built-in .NET and COM classes. They call no PowerShell
    cmdlets. The only things they write are the protected folder (after the checks above), the
    audit settings, the SYSTEM task and the event source.
  - Things a reviewer can check at a glance: the SYSTEM task runs only `wevtutil.exe` and
    `eventcreate.exe`; nothing in the commands downloads, runs or reads a file from a
    user-writable folder; the only user paths are the decoys, which only receive an audit rule.
- **Install-time trust in general.** If the account is already compromised when the user opens an
  administrator shell, malware has other ways in as well: a user PowerShell profile (avoided with
  `-NoProfile`), modules planted in the user's module folder (PowerShell loads PSReadLine from
  there when an interactive window starts), or a changed user `PATH`. Microsoft does not treat UAC
  as a security boundary between a user and their own admin rights, so no tool can fully remove
  this risk. The fix in this design is about the part an attacker could trigger at will: the alert
  path, which runs on every decoy read, never runs elevated.
- **A decoy swapped for a link while the admin step runs (a race).** The setup commands check
  that each decoy is a plain file, then set its audit rule. If the user has Developer Mode turned
  on (which lets non-admin programs create symlinks), malware could replace a decoy with a symlink
  between that check and the moment the rule is set. The rule would then land on the file the link
  points to. **Impact: extra Security-log entries when that file is read; no privilege gain**,
  because an audit rule only adds logging and never grants access. To narrow the gap, the commands
  re-check each decoy just before and just after setting its rule. If the after-check finds a
  link, they stop and say which file to check. Closing the gap completely would need opening the
  file in a way that refuses to follow links, which .NET Framework does not offer, so a small
  window remains.
- **Decoy marker.** An attacker who reads a decoy by hand can see it is a KeySnare decoy. That is
  the price of decoys being clearly identifiable as KeySnare decoys, which is a design rule.

---

## How alerts reach the user

No program runs in the background. Windows starts each step only when a decoy is read.

1. **SYSTEM relay task** `KeySnare Decoy Read Relay` (registered by the admin commands).
   Trigger: Security log, event 4663, for any decoy path. Actions, in order, both by absolute
   System32 path with fixed arguments:
   - `wevtutil.exe epl Security "C:\ProgramData\KeySnare\decoy-reads.evtx" "/q:<reads of the
     decoys in the last 24 hours>" /ow:true`
   - `eventcreate.exe /L APPLICATION /SO KeySnare /T WARNING /ID 100 /D "A KeySnare decoy was
     read."`
2. **User task** `\KeySnare\DecoyRead` (registered by `trap install`, no admin needed). Trigger:
   Application log, source `KeySnare`, event 100. Action: `pythonw.exe -m keysnare trap alert`,
   running as the user, **least privilege**, only while logged on. (`pythonw` is the windowless
   Python, so no console flashes.)
3. **Handler** (non-elevated): reads `decoy-reads.evtx` with `wevtutil.exe qe ... /lf:true
   /f:xml`, skips events it has already handled (by event record ID), validates each one, checks
   the allowlist, appends to `%LOCALAPPDATA%\KeySnare\alerts.jsonl`, and shows a Windows
   notification. Its sender shows as "Windows PowerShell": a "KeySnare" sender would need a
   Start menu shortcut, which would be one more system change.

Anyone can write events to the Application log, so malware could fake the "decoy read" event.
That only makes the handler re-read the export and find nothing new: it never trusts the
Application event itself.

Notification: *"KeySnare: a program read your decoy AWS credentials. Program:
C:\...\example.exe. If this was not you, run `keysnare scan` and rotate your real credentials. If
it was you, you can ignore this."*

Reads while nobody is logged on raise no notification, but event 4663 is still recorded.

## Avoiding false alarms

| Source | Approach |
|---|---|
| Microsoft Defender scanning the decoy | Allowlist `MsMpEng.exe` **only** at its protected install paths (`%ProgramData%\Microsoft\Windows Defender\Platform\<version>\`, `%ProgramFiles%\Windows Defender\`). Any other `MsMpEng.exe` still alerts. KeySnare never adds Defender exclusions. |
| Windows Search indexer | Decoys get the "not content indexed" attribute. `SearchProtocolHost.exe` and `SearchIndexer.exe` in `C:\Windows\System32` are allowlisted. |
| Backup and sync tools | File History's default folders exclude dot-folders like `.ssh` and `.aws`. For other tools, the alert names the program, and the user can add its full path to `%LOCALAPPDATA%\KeySnare\config.json`. |
| Real CLIs and client libraries | Prevented by placement, and checked by the integration test. |
| KeySnare itself | The scanner never opens decoys. |
| The user opening a decoy | Alerts. It is a real read; the notification says so. |

**Never allowlisted:** `python.exe`, `pythonw.exe`, `node.exe`, `powershell.exe`, `pwsh.exe`,
`cmd.exe` and other interpreters. Poisoned npm and PyPI packages run inside them.

---

## Install flow

`keysnare trap install` runs in a **normal** (non-elevated) terminal:

1. Refuses to run if elevated, and explains why.
2. Prints the plan: every decoy and every system change. Asks for confirmation (`--yes` skips
   the question, for CI).
3. Without admin rights, it creates the decoy files, sets their "not content indexed" attribute,
   registers the user's least-privilege alert task (triggered by the Application-log relay
   event), and writes the state file.
4. Prints the **setup commands** (template below) and how to run them:
   - Press Win+R, type `powershell -NoProfile`, press **Ctrl+Shift+Enter** to open it as
     administrator. `-NoProfile` matters: the user's PowerShell profile is a user-writable script
     that would otherwise run as administrator.
   - Compare the commands with the template in `docs/usage.md`, then paste them.
5. Asks what the first command showed next to "File System" (`No Auditing`, `Success`,
   `Failure`, `Success and Failure`, or "not sure"), and saves the answer in the state file. The
   elevated commands never write anything themselves, so this is how `trap remove` knows the
   original setting. `--yes` skips the questions and records "not sure".
6. Asks the user to run `keysnare trap test` to prove the whole chain works. A non-elevated
   KeySnare cannot read audit settings or audit rules, so an end-to-end test is the real check.

## Admin command templates

KeySnare prints these exact commands. The **only** part that ever changes is the list of decoy
paths in the setup commands: one line per decoy, each in single quotes. Decoy paths never
contain `'` (see "Where decoys go"). Anything else that differs from these templates was not
written by KeySnare. Do not run it.

What to check before pasting, in plain words:

- Every program it runs is in System32: `auditpol.exe`, `eventcreate.exe`, `wevtutil.exe`.
- The SYSTEM task runs **only** `wevtutil.exe` and `eventcreate.exe`.
- The only paths in your user folder are the decoys in the list. They only receive an audit rule.
- Every check comes first. If a check fails, the commands stop before changing anything.

**Setup** (printed by `keysnare trap install`):

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

**Removal** (printed by `keysnare trap remove`, every time):

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

**Audit restore** (printed by `keysnare trap remove`, only if the saved answer was
`No Auditing` or `Failure`, meaning success auditing was off before):

```powershell
# KeySnare audit restore. Run in an administrator "powershell -NoProfile" window.
# Turns "File System" success auditing back off, as it was before KeySnare.
$auditpol = [Environment]::SystemDirectory + '\auditpol.exe'
& $auditpol /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:disable
```

`{0CCE921D-69AE-11D9-BED3-505054503030}` is Windows' fixed ID for the "File System" audit
category. KeySnare uses the ID because category names are translated on non-English Windows.
The audit rules on the decoys need no restore command: they are deleted along with the decoys.

## Commands

Windows-only in v1. On macOS and Linux they explain that and exit with code 2.

| Command | What it does |
|---|---|
| `keysnare trap install` | As in "Install flow". |
| `keysnare trap status` | Read-only and non-elevated. For each decoy: exists, unchanged (file identity matches, checked without reading it). Whether the alert task is registered and enabled. The latest alerts. It says that audit settings can only be confirmed with `trap test`. |
| `keysnare trap test` | Simulates a theft. A separate, non-allowlisted process (`powershell.exe -NoProfile -Command Get-Content <decoy>`) reads one decoy. KeySnare waits up to 30 seconds for the alert in `alerts.jsonl`, then reports success or which step failed. The user sees the real notification. The test alert is marked as a test. |
| `keysnare trap remove` | Undoes every change it can without admin rights (table below), prints what it did, then prints the **removal** admin commands (always) and the **audit restore** command (if auditing was off before). Safe to run twice. |
| `keysnare trap remove --purge` | Same, and also deletes the alert history. |
| `keysnare trap alert ...` | Internal; started by the task. |

**Alert history on remove:** if `alerts.jsonl` contains any alerts, it is kept
and its full path is printed. `--purge` deletes it too. If it holds no alerts, it is deleted.

## Every system change, and how it is undone

| # | Change | Needs admin | Made by | Undone by |
|---|---|---|---|---|
| 1 | Audit policy: "File System" success auditing on | Yes | User, with the printed commands | `trap remove` prints the restore command if the saved answer says it was off before. If the answer was "not sure", it explains how to check with `auditpol /get` and decide. |
| 2 | Decoy files, and folders such as `.ssh`, `.aws`, `.config\gh` if they did not exist | No | `trap install` | Each decoy is deleted **only if its file identity still matches**; an edited or replaced file is left alone and reported. A folder is deleted only if KeySnare created it and it is now empty. |
| 3 | Audit rule (SACL) "Everyone: Read data, success" on each decoy | Yes | User, with the printed commands | Deleted with the decoy file. Never added to any other file. |
| 4 | "Not content indexed" attribute on each decoy | No | `trap install` | Deleted with the decoy file |
| 5 | Scheduled task `\KeySnare\DecoyRead` (the user's own, least privilege, Application-log trigger) | No | `trap install` | Task deleted by `trap remove` |
| 6 | KeySnare data folder `%LOCALAPPDATA%\KeySnare\` | No | `trap install`, alerts | Deleted; `alerts.jsonl` kept if it has alerts (see above) |
| 7 | Security log entries (event 4663) and Application log entries (KeySnare events 1 and 100) | No | Windows | Not deleted. KeySnare never clears or edits Windows logs. |
| 8 | Folder `C:\ProgramData\KeySnare` (owner Administrators, protected permissions) and the file `decoy-reads.evtx` inside it | Yes | User, with the printed setup commands | Removal commands: same link and ownership checks as setup, then the file and folder are deleted |
| 9 | Application-log event source `KeySnare` (registry key `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\KeySnare`, created by `eventcreate.exe`) | Yes | User, with the printed setup commands | Removal commands delete it |
| 10 | SYSTEM task `KeySnare Decoy Read Relay` (top level of Task Scheduler) | Yes | User, with the printed setup commands | Removal commands delete it |

No services, drivers, firewall rules, Defender settings, startup entries or other registry keys are
created or changed.

If the state file is missing or damaged, `trap remove` deletes the user's alert task by its fixed
name, and **lists** any files at the possible decoy paths without deleting them: without the
recorded file identities, only reading the files could prove they are KeySnare's, and reading a
decoy raises an alert. It does not suggest turning auditing off, because it no longer knows the
original setting; it explains how to check it instead. The state file is user-writable, so malware could change the saved audit setting; the
worst outcome is auditing left on or off, which does not affect the machine's security much.

## Testing

- **Unit tests (every OS):**
  - decoy generation (correct format, the marker in every value);
  - placement rules, including every environment-variable condition;
  - allowlist matching, including a fake `MsMpEng.exe` outside the protected paths;
  - field validation in the alert handler, including hostile input;
  - refusing to run elevated;
  - state file round trip;
  - file identity: works on a file whose data the user may not read (proving attribute-only
    access), and changes when a file is replaced or edited;
  - `trap status`, `trap remove` and `keysnare scan` never open a decoy for reading (a guard
    makes any such read fail the test);
  - the scanner skipping decoys;
  - alert history kept or deleted on remove.
- **Integration test (GitHub Actions `windows-latest`, a disposable runner).** The harness is
  `tests/integration/trap_harness.ps1`. Runners always run as administrator, and KeySnare
  refuses to run elevated (there is no bypass in KeySnare's code, ever), so the harness creates
  a temporary **standard user** and runs every KeySnare command as that user. The runner's admin
  account plays the administrator's part.
  1. Snapshot: the user's decoy locations, the "File System" audit setting, the `\KeySnare\`
     task folder, the relay task, the `KeySnare` event source and `C:\ProgramData\KeySnare`.
  2. As the standard user: `trap install --yes`. As admin: run the printed setup commands, after
     checking they match the published template exactly (apart from the decoy lines).
  3. **ProgramData hardening, after install.** As the standard user, each of these must fail:
     creating a file in `C:\ProgramData\KeySnare`, changing `decoy-reads.evtx`, renaming or
     deleting the folder, and replacing it with a junction. As admin: the folder's owner and
     permissions are exactly as designed.
  4. As the standard user: run each installed tool's read-only command. As admin: assert the
     Security log has **no** event 4663 for a decoy. This check does not depend on the alert task.
  5. **Harness-only change:** the temporary user is never logged on interactively, so the alert
     task as KeySnare registers it (interactive only) cannot fire. The harness therefore tries to
     re-register it with S4U logon ("run whether user is logged on or not", no stored password):
     the standard user exports and deletes their task, and the admin registers the same XML with
     S4U. **KeySnare's own code never does this.** It exists only in the test harness.
  6. As the standard user: `trap test`. As admin: assert event 4663 was recorded for the
     simulated theft, and that the relay wrote `decoy-reads.evtx`. Then check for a test alert in
     `alerts.jsonl`. If none arrives, the job records why and **does not fail**: that path is
     covered by the manual check below.
  7. As the standard user: `trap remove --purge`. As admin: run the printed removal commands, and
     the audit restore commands if auditing was off before. Then compare everything with the
     snapshot. Any difference fails the job.
  8. **Malicious pre-creation, on a fresh state.** Before a second install, the standard user
     creates `C:\ProgramData\KeySnare` themselves (which ProgramData allows), and in a third
     round makes it a junction to a folder they own. In both cases the admin setup commands must
     stop with their explanation, and the audit setting, decoy audit rules, event source and
     relay task must be unchanged. The harness then cleans up and checks the snapshot again.
- **What the integration test covers.** On the runner it proves: setup from the printed,
  template-matching commands; every ProgramData hardening check; no real tool reading a decoy;
  event 4663 for the simulated theft; the SYSTEM relay writing its export, which the standard user
  cannot change; setup refusing a pre-created folder and a junction without changing anything;
  and a full restore after remove, including running the removal commands twice. It cannot cover
  the last hop, from the relay's Application event through the user's task to `alerts.jsonl` and
  the notification: Windows refuses the S4U re-registration on the runner ("Access is denied"),
  and the task as designed runs only in an interactive logon session.
- **Manual check of the notification.** On a real Windows machine with an interactive login, run
  `trap install`, the printed setup commands and `trap test`, confirm that the notification
  appears, then run `trap remove` and its printed commands.
