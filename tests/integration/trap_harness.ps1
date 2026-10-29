<#
KeySnare trap integration test.

RUNS ONLY ON DISPOSABLE GITHUB ACTIONS WINDOWS RUNNERS. Never run it on a real machine: it creates
a local user, changes the audit policy, creates C:\ProgramData\KeySnare, an event source and
scheduled tasks. It refuses to start outside GitHub Actions.

GitHub runners always run as administrator, and KeySnare refuses to run elevated (there is no
bypass in KeySnare's code, ever). So this harness creates a temporary STANDARD user and runs every
KeySnare command as that user. The runner's admin account plays the administrator's part: it runs
the printed admin commands and checks the results.

HARNESS-ONLY CHANGE (step 5): the harness tries to re-register the user's alert task with S4U logon
("run whether user is logged on or not", no stored password), because the temporary user is never
logged on interactively and the task as KeySnare registers it would not fire. KeySnare's own code
never does this. See docs/design-traps.md, "Testing".

Fails the job for: install or remove errors, printed admin commands that differ from the published
template, admin command errors, a standard user able to change C:\ProgramData\KeySnare, setup not
refusing a pre-created folder or junction, any non-system program reading a decoy, no event 4663
or no relay export for the simulated theft, or anything not restored.
Only warns if the alert does not reach alerts.jsonl (covered by the manual check in the design doc).
#>
param([Parameter(Mandatory = $true)] [string] $KeySnare)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This harness runs only on GitHub Actions runners.' }

$failures = New-Object System.Collections.Generic.List[string]
function Fail([string] $message) { $failures.Add($message); Write-Host "::error::$message" }
function Note([string] $message) { Write-Host "::warning::$message" }

$auditpol = [Environment]::SystemDirectory + '\auditpol.exe'
$fileSystemAudit = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$protectedFolder = [Environment]::GetFolderPath('CommonApplicationData') + '\KeySnare'
$relayTask = 'KeySnare Decoy Read Relay'
$cmd = [Environment]::SystemDirectory + '\cmd.exe'
function Get-AuditSetting { (& $auditpol /get /subcategory:$fileSystemAudit /r | ConvertFrom-Csv).'Inclusion Setting' }

# --- Temporary standard user ---------------------------------------------------------------
$user = 'ksuser'
$chars = [char[]]((48..57) + (65..90) + (97..122))
$password = (-join (1..24 | ForEach-Object { $chars | Get-Random })) + '!a1'
$secure = ConvertTo-SecureString $password -AsPlainText -Force
New-LocalUser -Name $user -Password $secure -PasswordNeverExpires | Out-Null
$credential = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", $secure)
$work = 'C:\ks-out'
New-Item -ItemType Directory -Force $work | Out-Null
icacls $work /grant "${user}:(OI)(CI)M" | Out-Null

function Invoke-AsUser([string] $Program, [string[]] $Arguments, [string] $Name) {
    $stdout = "$work\$Name.out.txt"
    $stderr = "$work\$Name.err.txt"
    $process = Start-Process -FilePath $Program -ArgumentList $Arguments -Credential $credential `
        -LoadUserProfile -Wait -PassThru -NoNewWindow -WorkingDirectory $work `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Out      = [IO.File]::ReadAllText($stdout)
        Err      = [IO.File]::ReadAllText($stderr)
    }
}
function Invoke-CmdAsUser([string] $CommandLine, [string] $Name) {
    Invoke-AsUser $cmd @('/c', $CommandLine) $Name
}

$version = Invoke-AsUser $KeySnare @('--version') 'version'
Write-Host "Running as standard user '$user': $($version.Out.Trim())"
$sid = (Get-LocalUser $user).SID.Value
$userHome = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath

# --- Read-only tool commands ---------------------------------------------------------------
$tools = @(
    @('gh', 'auth', 'status'), @('aws', 'configure', 'list'), @('gcloud', 'config', 'list'),
    @('kubectl', 'config', 'view'), @('docker', 'version'), @('git', 'config', '--list'),
    @('npm', 'config', 'list')
)
function Invoke-Tools([string] $Phase) {
    foreach ($tool in $tools) {
        # Applications only (.exe, .cmd): Start-Process cannot launch PowerShell scripts like npm.ps1.
        $command = Get-Command $tool[0] -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $command) { Note "$($tool[0]) is not installed on this runner"; continue }
        $arguments = @($tool | Select-Object -Skip 1)
        Invoke-AsUser $command.Source $arguments "$Phase-$($tool[0])" | Out-Null
    }
}

# --- Snapshot ------------------------------------------------------------------------------
$watched = '.ssh', '.aws', '.docker', '.kube', '.config', '.git-credentials', '.npmrc',
    'AppData\Local\KeySnare'
function Get-Snapshot {
    $files = foreach ($relative in $watched) {
        $path = Join-Path $userHome $relative
        if (Test-Path -LiteralPath $path) {
            $path
            Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName }
        }
    }
    [pscustomobject]@{
        Files           = @($files | Sort-Object)
        Audit           = Get-AuditSetting
        UserTasks       = @(Get-ScheduledTask -TaskPath '\KeySnare\' -ErrorAction SilentlyContinue).Count
        RelayTask       = [bool](Get-ScheduledTask -TaskName $relayTask -ErrorAction SilentlyContinue)
        EventSource     = [Diagnostics.EventLog]::SourceExists('KeySnare')
        ProtectedFolder = Test-Path -LiteralPath $protectedFolder
    }
}
function Compare-WithBefore([string] $When) {
    $after = Get-Snapshot
    foreach ($difference in @(Compare-Object $before.Files $after.Files)) {
        Fail "$When, not restored: $($difference.InputObject) ($($difference.SideIndicator))"
    }
    foreach ($property in 'Audit', 'UserTasks', 'RelayTask', 'EventSource', 'ProtectedFolder') {
        if ("$($after.$property)" -ne "$($before.$property)") {
            Fail "$When, not restored: $property is '$($after.$property)', was '$($before.$property)'"
        }
    }
}

function Get-DecoyReads([datetime] $Since, [string[]] $Decoys) {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $Since } `
        -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        $data = @{}
        ([xml]$event.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
        if ($Decoys -contains $data['ObjectName']) {
            [pscustomobject]@{ Process = $data['ProcessName']; Decoy = $data['ObjectName'] }
        }
    }
}
$systemReaders = 'MsMpEng.exe', 'SearchProtocolHost.exe', 'SearchIndexer.exe'

# --- Printed admin commands ----------------------------------------------------------------
function Get-PrintedBlock([string] $Text, [string] $FirstLine, [string] $LastLinePrefix) {
    $lines = $Text -split "`r?`n"
    $start = [Array]::FindIndex($lines, [Predicate[string]] { param($l) $l.StartsWith($FirstLine) })
    if ($start -lt 0) { return $null }
    for ($i = $start; $i -lt $lines.Length; $i++) {
        if ($lines[$i].StartsWith($LastLinePrefix)) { return ($lines[$start..$i] -join "`n") + "`n" }
    }
    return $null
}
function Get-SetupBlock([string] $Text) {
    Get-PrintedBlock $Text '# KeySnare trap setup.' "'KeySnare setup finished."
}
function Get-RemovalBlock([string] $Text) {
    Get-PrintedBlock $Text '# KeySnare trap removal.' "'KeySnare removal finished."
}
function Get-AuditRestoreBlock([string] $Text) {
    Get-PrintedBlock $Text '# KeySnare audit restore.' '& $auditpol /set'
}
$published = [IO.File]::ReadAllText("$PSScriptRoot\..\..\docs\usage.md") -replace "`r`n", "`n"
$publishedSetup = Get-SetupBlock $published
$publishedRemoval = Get-RemovalBlock $published
function Without-DecoyLines([string] $Block) {
    (($Block -split "`n") | Where-Object { $_ -notmatch "^    '[^']*'$" }) -join "`n"
}

function Invoke-AdminBlock([string] $Block, [string] $Name) {
    $file = "$work\$Name.ps1"
    [IO.File]::WriteAllText($file, $Block)
    # A refusal on stderr is an expected result here, not a harness error.
    $ErrorActionPreference = 'Continue'
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Out = $output }
}

function Get-DecoyAuditRuleCount([string[]] $Decoys) {
    $count = 0
    foreach ($decoy in $Decoys) {
        if (Test-Path -LiteralPath $decoy) {
            $count += [IO.File]::GetAccessControl($decoy, 'Audit').GetAuditRules(
                $true, $false, [Security.Principal.SecurityIdentifier]).Count
        }
    }
    $count
}

function Install-AsUser([string] $Name) {
    $install = Invoke-AsUser $KeySnare @('trap', 'install', '--yes') $Name
    Write-Host $install.Out
    if ($install.ExitCode -ne 0) { throw "trap install failed ($($install.ExitCode)): $($install.Err)" }
    $setup = Get-SetupBlock $install.Out
    if (-not $setup) { throw 'trap install printed no setup commands' }
    if ((Without-DecoyLines $setup) -ne (Without-DecoyLines $publishedSetup)) {
        Fail 'The printed setup commands differ from the template published in docs/usage.md'
    }
    $state = Get-Content "$userHome\AppData\Local\KeySnare\traps.json" -Raw | ConvertFrom-Json
    [pscustomobject]@{ Setup = $setup; Decoys = @($state.decoys | ForEach-Object { $_.path }) }
}

# --- 1. Warm up tools, then snapshot -------------------------------------------------------
Invoke-Tools 'warmup'
$before = Get-Snapshot
Write-Host "Before: $($before | ConvertTo-Json -Compress -Depth 1)"

# --- 2. Install as the standard user; admin runs the printed setup commands ----------------
$installed = Install-AsUser 'install'
$decoys = $installed.Decoys
Write-Host "Decoys: $($decoys -join ', ')"
$setupRun = Invoke-AdminBlock $installed.Setup 'setup'
Write-Host $setupRun.Out
if ($setupRun.ExitCode -ne 0) { throw "The setup commands failed ($($setupRun.ExitCode))" }
if ((Get-AuditSetting) -notmatch 'Success') { Fail 'Success auditing is not on after setup' }

# --- 3. ProgramData hardening: the standard user cannot change the protected folder --------
$folderAcl = [IO.Directory]::GetAccessControl($protectedFolder)
if ($folderAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') {
    Fail "$protectedFolder is not owned by Administrators"
}
if (-not $folderAcl.AreAccessRulesProtected) { Fail "$protectedFolder inherits permissions" }
$null = Invoke-CmdAsUser "echo evil> `"$protectedFolder\evil.txt`"" 'harden-write'
if (Test-Path -LiteralPath "$protectedFolder\evil.txt") { Fail 'A standard user created a file in the protected folder' }
$null = Invoke-CmdAsUser "mkdir `"$protectedFolder\sub`"" 'harden-mkdir'
if (Test-Path -LiteralPath "$protectedFolder\sub") { Fail 'A standard user created a folder in the protected folder' }
$null = Invoke-CmdAsUser "ren `"$protectedFolder`" KeySnare-moved" 'harden-rename'
$null = Invoke-CmdAsUser "rmdir /s /q `"$protectedFolder`"" 'harden-delete'
if (-not (Test-Path -LiteralPath $protectedFolder)) { Fail 'A standard user renamed or deleted the protected folder' }
$null = Invoke-CmdAsUser "mklink /J `"$protectedFolder\link`" `"$userHome`"" 'harden-junction-inside'
if (Test-Path -LiteralPath "$protectedFolder\link") { Fail 'A standard user created a junction in the protected folder' }
$null = Invoke-CmdAsUser "rmdir `"$protectedFolder`" & mklink /J `"$protectedFolder`" `"$userHome`"" 'harden-junction-swap'
if (([IO.DirectoryInfo]::new($protectedFolder).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    Fail 'A standard user replaced the protected folder with a junction'
}

# --- 4. Real tools must never read a decoy -------------------------------------------------
$toolsStart = Get-Date
Invoke-Tools 'check'
Start-Sleep -Seconds 3
foreach ($read in @(Get-DecoyReads $toolsStart $decoys)) {
    if ($systemReaders -notcontains (Split-Path $read.Process -Leaf)) {
        Fail "A real tool read a decoy: $($read.Process) read $($read.Decoy)"
    }
}

# --- 5. HARNESS-ONLY: re-register the user's alert task with S4U logon -----------------------
# An admin may not modify a task the user owns, so the user exports and deletes their task and
# the admin registers the same XML with S4U logon. The harness deletes that copy after step 6.
$schtasks = [Environment]::SystemDirectory + '\schtasks.exe'
$harnessTask = $false
try {
    $exported = Invoke-AsUser $schtasks @('/Query', '/TN', '\KeySnare\DecoyRead', '/XML') 'task-export'
    if ($exported.ExitCode -ne 0) { throw "export failed: $($exported.Err)" }
    $s4uXml = $exported.Out.Replace('<LogonType>InteractiveToken</LogonType>', '<LogonType>S4U</LogonType>')
    $deleted = Invoke-AsUser $schtasks @('/Delete', '/TN', '\KeySnare\DecoyRead', '/F') 'task-delete'
    if ($deleted.ExitCode -ne 0) { throw "delete failed: $($deleted.Err)" }
    Register-ScheduledTask -Xml $s4uXml -TaskPath '\KeySnare\' -TaskName 'DecoyRead' | Out-Null
    $harnessTask = $true
    Write-Host 'Harness re-registered the user alert task with S4U logon (test harness only).'
} catch {
    Note "Could not re-register the user alert task with S4U: $($_.Exception.Message)"
}

# --- 6. Simulated theft ---------------------------------------------------------------------
$testStart = Get-Date
$test = Invoke-AsUser $KeySnare @('trap', 'test') 'test'
Write-Host $test.Out
Start-Sleep -Seconds 2
$theft = @(Get-DecoyReads $testStart $decoys | Where-Object { $_.Process -like '*\powershell.exe' })
if (-not $theft) { Fail 'Windows recorded no event 4663 for the simulated theft: audit setup did not work' }
$export = "$protectedFolder\decoy-reads.evtx"
if (-not (Test-Path -LiteralPath $export)) {
    $relayInfo = Get-ScheduledTaskInfo -TaskName $relayTask -ErrorAction SilentlyContinue
    Fail "The SYSTEM relay wrote no export (last result: $($relayInfo.LastTaskResult))"
} else {
    $exportHash = (Get-FileHash -LiteralPath $export).Hash
    $null = Invoke-CmdAsUser "echo evil>> `"$export`"" 'harden-export'
    if ((Get-FileHash -LiteralPath $export).Hash -ne $exportHash) { Fail 'A standard user changed the relay export' }
}
if ($test.ExitCode -eq 0) {
    Write-Host 'Alert reached alerts.jsonl through the relay and the user task.'
} else {
    $info = Get-ScheduledTaskInfo -TaskPath '\KeySnare\' -TaskName 'DecoyRead' -ErrorAction SilentlyContinue
    $how = if ($harnessTask) { 'with the S4U copy' } else { 'S4U re-registration was not possible' }
    Note ("No test alert in alerts.jsonl ($how). User task last run: $($info.LastRunTime), " +
        "result: $($info.LastTaskResult). Confirm with the manual check in docs/design-traps.md.")
}
if ($harnessTask) {
    Unregister-ScheduledTask -TaskPath '\KeySnare\' -TaskName 'DecoyRead' -Confirm:$false
    Write-Host 'Harness deleted its S4U copy of the user alert task.'
}

# --- 7. Remove as the standard user; admin runs the printed removal (and audit restore) -----
function Remove-AsUser([string] $Name) {
    $remove = Invoke-AsUser $KeySnare @('trap', 'remove', '--purge') $Name
    Write-Host $remove.Out
    if ($remove.ExitCode -ne 0) { Fail "trap remove failed ($($remove.ExitCode)): $($remove.Err)" }
    $remove.Out
}
$removeOut = Remove-AsUser 'remove'
$removal = Get-RemovalBlock $removeOut
if ($removal -ne $publishedRemoval) { Fail 'The printed removal commands differ from the published template' }
$removalRun = Invoke-AdminBlock $removal 'removal'
Write-Host $removalRun.Out
if ($removalRun.ExitCode -ne 0) { Fail "The removal commands failed ($($removalRun.ExitCode))" }
$secondRun = Invoke-AdminBlock $removal 'removal-again'
Write-Host $secondRun.Out
if ($secondRun.ExitCode -ne 0) { Fail "Running the removal commands a second time failed ($($secondRun.ExitCode))" }
if ($before.Audit -notmatch 'Success') {
    $restore = Get-AuditRestoreBlock $removeOut
    if (-not $restore) { Fail 'trap remove printed no audit restore commands' }
    elseif ((Invoke-AdminBlock $restore 'audit-restore').ExitCode -ne 0) { Fail 'The audit restore commands failed' }
}
Compare-WithBefore 'After remove'

# --- 8. Setup must refuse a pre-created folder or junction, and change nothing --------------
function Test-RefusesPrecreated([string] $Round, [string] $Precreate) {
    $null = Invoke-CmdAsUser $Precreate "$Round-precreate"
    if (-not (Test-Path -LiteralPath $protectedFolder)) { Fail "$Round could not pre-create the folder"; return }
    $attempt = Install-AsUser "$Round-install"
    $run = Invoke-AdminBlock $attempt.Setup "$Round-setup"
    Write-Host $run.Out
    if ($run.ExitCode -eq 0) { Fail "$Round : setup did not refuse the pre-created $protectedFolder" }
    if ($run.Out -notmatch 'Stopped, nothing was changed') { Fail "$Round : setup gave no explanation" }
    if ((Get-AuditSetting) -ne $before.Audit) { Fail "$Round : the audit setting was changed" }
    if ((Get-DecoyAuditRuleCount $attempt.Decoys) -ne 0) { Fail "$Round : decoys received audit rules" }
    if ([Diagnostics.EventLog]::SourceExists('KeySnare')) { Fail "$Round : the event source was created" }
    if (Get-ScheduledTask -TaskName $relayTask -ErrorAction SilentlyContinue) { Fail "$Round : the relay task was created" }
    $null = Invoke-CmdAsUser "rmdir `"$protectedFolder`"" "$Round-cleanup"
    $null = Remove-AsUser "$Round-remove"
}
Test-RefusesPrecreated 'precreated-folder' "mkdir `"$protectedFolder`""
$null = Invoke-CmdAsUser "mkdir `"$userHome\jtarget`"" 'junction-target'
Test-RefusesPrecreated 'precreated-junction' "mklink /J `"$protectedFolder`" `"$userHome\jtarget`""
$null = Invoke-CmdAsUser "rmdir `"$userHome\jtarget`"" 'junction-target-cleanup'
Compare-WithBefore 'After the pre-creation rounds'

Remove-LocalUser $user
if ($failures.Count -gt 0) { Write-Host "$($failures.Count) failure(s)."; exit 1 }
Write-Host 'Trap integration test passed: install -> test -> remove restored everything.'
