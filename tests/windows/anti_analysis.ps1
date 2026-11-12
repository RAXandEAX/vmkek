#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('All', 'Debugger', 'Integrity', 'Instrumentation', 'Scheduling', 'Response', 'Compatibility', 'Clean', 'StartupDebugger', 'LateDebugger',
        'WinDbg', 'X64dbg', 'IDA', 'Ghidra', 'BinaryNinja', 'Frida')]
    [string] $Case = 'All',
    [ValidateSet('observe', 'enforce')]
    [string] $Profile = 'observe',
    [ValidateRange(1, 30)]
    [int] $Repeat = 1,
    [Parameter(Mandatory)] [string] $OutputDir,
    [string] $IdeExecutable,
    [string] $CargoTargetDir,
    [switch] $CompatibilitySoak
)

$ErrorActionPreference = 'Stop'
$Profile = $Profile.ToLowerInvariant()
if ($CompatibilitySoak -and $Case -ne 'Compatibility') { throw 'CompatibilitySoak requires the Compatibility case' }
if ($Case -eq 'Compatibility') { . (Join-Path $PSScriptRoot 'a08_compatibility.ps1') }
$probeSeconds = 25
$buildSeconds = 180
$logLimit = 32768
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$runPrefix = if ($Case -eq 'Debugger') { 'a03-' } elseif ($Case -eq 'Integrity') { 'a04-' } elseif ($Case -eq 'Instrumentation') { 'a05-' } elseif ($Case -eq 'Scheduling') { 'a06-' } elseif ($Case -eq 'Response') { 'a07-' } elseif ($Case -eq 'Compatibility') { 'a08-' } else { 'a02-' }
$run = (New-Item -ItemType Directory -Path (Join-Path $OutputDir ($runPrefix + [guid]::NewGuid().ToString('N'))) -Force).FullName
$rows = [Collections.Generic.List[object]]::new()
$cases = @(
    @{ Id = 'Clean'; Args = @('--gated'); Oracle = 'created_clean,ready,exited'; Attached = $false }
    @{ Id = 'StartupDebugger'; Args = @(); Oracle = 'created_debug,debug_process_event,initial_breakpoint,exited'; Attached = $true }
    @{ Id = 'LateDebugger'; Args = @('--attach-after-ready'); Oracle = 'created_clean,ready,attach_succeeded,debug_process_event,initial_breakpoint,exited'; Attached = $true }
)
$lateOracle = $cases[2].Oracle -replace ',exited$', ''
$cleanOracle = $cases[0].Oracle
$debuggerCases = $cases + @(
    @{ Id = 'LateDetach'; Args = @('--attach-detach'); Oracle = "$lateOracle,detach_ready,detach_succeeded,exited"; Attached = $true; Scenario = 'detach' }
    @{ Id = 'SoftwareBreakpoint'; Args = @('--software-breakpoint'); Oracle = "$lateOracle,software_breakpoint,exited"; Attached = $true; Scenario = 'software'; EvidenceEvent = 'software_breakpoint' }
    @{ Id = 'HardwareBreakpoint'; Args = @('--hardware-breakpoint'); Oracle = "$lateOracle,hardware_armed,hardware_breakpoint_restored,exited"; Attached = $true; Scenario = 'hardware'; EvidenceEvent = 'hardware_breakpoint_restored' }
    @{ Id = 'BreakpointControl'; Args = @('--gated'); Oracle = $cleanOracle; Attached = $false; Scenario = 'breakpoint_control' }
    @{ Id = 'CleanData'; Args = @('--gated'); Oracle = $cleanOracle; Attached = $false; Scenario = 'data' }
    @{ Id = 'CleanCpuLoad'; Args = @('--gated'); Oracle = $cleanOracle; Attached = $false; Scenario = 'cpu_load' }
    @{ Id = 'CleanConcurrent'; Args = @('--gated'); Oracle = $cleanOracle; Attached = $false; Scenario = 'concurrent' }
    @{ Id = 'CleanIde'; Args = @('--gated'); Oracle = $cleanOracle; Attached = $false; Scenario = 'ide' }
    @{ Id = 'DebuggerDisabled'; Args = @('--attach-after-ready'); Oracle = "$lateOracle,exited"; Attached = $true; Scenario = 'disabled' }
    @{ Id = 'CleanDebuggerDisabled'; Args = @('--gated'); Oracle = $cleanOracle; Attached = $false; Scenario = 'disabled' }
)
$responseCases = @(
    $cases[0], $cases[1], $cases[2], $debuggerCases[3],
    @{ Id = 'OnlineStartupDebugger'; Args = @(); Oracle = $cases[1].Oracle; Attached = $true; Scenario = 'online_startup'; Online = $true; Startup = $true },
    @{ Id = 'OnlineLateDebugger'; Args = $cases[2].Args; Oracle = $cases[2].Oracle; Attached = $true; Scenario = 'online_late'; Online = $true },
    @{ Id = 'OfflineBoundary'; Boundary = $true },
    @{ Id = 'OnlineBoundary'; Boundary = $true; Online = $true }
)
$instrumentationCases = 'Clean', 'CleanRenamed', 'MarkerClean', 'StalkerClean', 'BenignProfiler',
    'OwnedMarkerDuringFridaAttach', 'FridaSpawn', 'FridaAttach',
    'FridaGadget', 'FridaInterceptor', 'FridaInterceptorRenamed', 'FridaStalker' | ForEach-Object { @{ Id = $_ } }
$tools = [ordered]@{
    WinDbg = @('windbg.exe', 'cdb.exe', 'WinDbgX.exe')
    X64dbg = @('x64dbg.exe')
    IDA = @('ida.exe', 'ida64.exe')
    Ghidra = @('ghidraRun.bat')
    BinaryNinja = @('binaryninja.exe')
    Frida = @('frida.exe')
}

function Initialize-LabProcessLauncher([string] $RunnerDirectory) {
    if (!('Vmkek.Lab.ProcessJob' -as [type])) {
        Add-Type -Path (Join-Path $RunnerDirectory 'anti_analysis_process.cs')
    }
    $launcher = @'
$ErrorActionPreference = 'Stop'
$launch = $env:VMKEK_A02_LAUNCH | ConvertFrom-Json
Remove-Item Env:VMKEK_A02_LAUNCH
$gate = [Threading.EventWaitHandle]::OpenExisting($launch.gate)
try {
    if (!$gate.WaitOne(10000)) { exit 122 }
} finally {
    $gate.Dispose()
}
$target = [Diagnostics.ProcessStartInfo]::new($launch.program)
$target.WorkingDirectory = $launch.directory
$target.UseShellExecute = $false
$target.CreateNoWindow = $true
if ($launch.hidden) { $target.WindowStyle = 'Hidden' }
$target.RedirectStandardOutput = $true
$target.RedirectStandardError = $true
foreach ($arg in $launch.arguments) { $target.ArgumentList.Add([string] $arg) }
$child = [Diagnostics.Process]::Start($target)
try {
    if ($launch.pidFile) { [IO.File]::WriteAllText($launch.pidFile, [string] $child.Id) }
    $stdout = $child.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())
    $stderr = $child.StandardError.BaseStream.CopyToAsync([Console]::OpenStandardError())
    $child.WaitForExit()
    [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]] @($stdout, $stderr)).GetAwaiter().GetResult()
    exit $child.ExitCode
} finally {
    $child.Dispose()
}
'@
    $script:LabLauncherCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($launcher))
}

function Invoke-Bounded($Program, [string[]] $Arguments, $Directory, $LimitSeconds, $Name, $ProbeEnvironment) {
    $info = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'))
    $info.WorkingDirectory = $Directory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in '-NoProfile', '-NonInteractive', '-EncodedCommand', $script:LabLauncherCommand) {
        $info.ArgumentList.Add($arg)
    }
    $gateName = 'Local\vmkek-a02-launch-' + [guid]::NewGuid().ToString('N')
    if ($null -ne $ProbeEnvironment) {
        $info.Environment.Clear()
        foreach ($key in 'SystemRoot', 'SystemDrive', 'WINDIR') {
            if (Test-Path "Env:$key") { $info.Environment[$key] = (Get-Item "Env:$key").Value }
        }
        $info.Environment['TEMP'] = $Directory
        $info.Environment['TMP'] = $Directory
        foreach ($key in $ProbeEnvironment.Keys) { $info.Environment[$key] = $ProbeEnvironment[$key] }
    } else {
        foreach ($key in @($info.Environment.Keys)) {
            if ($key -like 'VMKEK_*') { $null = $info.Environment.Remove($key) }
        }
    }
    $info.Environment['VMKEK_A02_LAUNCH'] = @{
        gate = $gateName; program = $Program; arguments = $Arguments; directory = $Directory
    } | ConvertTo-Json -Compress
    $stdout = Join-Path $Directory "$Name.stdout.log"
    $stderr = Join-Path $Directory "$Name.stderr.log"
    $reason = $null
    $exitCode = $null
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $streams = @()
    $started = $false
    $assigned = $false
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $job = $null
    $gate = $null
    try {
        $job = [Vmkek.Lab.ProcessJob]::Create()
        $gate = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $gateName)
        if (!$process.Start()) { throw 'Process failed to start' }
        $started = $true
        try {
            $job.Assign($process.SafeHandle)
            $assigned = $true
            if (!$gate.Set()) { throw 'Launcher release failed' }
        } catch {
            $reason = 'process-job-error'
            throw
        }
        $streams = @(
            @{ Reader = $process.StandardOutput; Path = $stdout }
            @{ Reader = $process.StandardError; Path = $stderr }
        )
        foreach ($stream in $streams) {
            $stream.Buffer = [char[]]::new(1024)
            $stream.Text = [Text.StringBuilder]::new()
            $stream.Pending = $stream.Reader.ReadAsync($stream.Buffer, 0, $stream.Buffer.Length)
        }
        while (!$process.HasExited -or @($streams | Where-Object { $null -ne $_.Pending }).Count) {
            if ($clock.Elapsed.TotalSeconds -ge $LimitSeconds) {
                $reason = 'timeout'
                break
            }
            $progress = $false
            foreach ($stream in $streams) {
                if ($null -eq $stream.Pending -or !$stream.Pending.IsCompleted) { continue }
                $progress = $true
                $count = $stream.Pending.GetAwaiter().GetResult()
                if ($count -eq 0) {
                    $stream.Pending = $null
                    continue
                }
                $remaining = $logLimit - $stream.Text.Length
                $null = $stream.Text.Append($stream.Buffer, 0, [Math]::Min($remaining, $count))
                if ($count -gt $remaining) {
                    $reason = 'log-limit'
                    break
                }
                $stream.Pending = $stream.Reader.ReadAsync($stream.Buffer, 0, $stream.Buffer.Length)
            }
            if ($reason) { break }
            if (!$progress) { Start-Sleep -Milliseconds 10 }
        }
    } catch {
        if (!$reason) { $reason = if ($started) { 'process-io-error' } else { 'process-start-error' } }
    } finally {
        if ($null -ne $job) { $job.Dispose() }
        if ($null -ne $gate) { $gate.Dispose() }
        if ($started) {
            try {
                if (!$assigned -and !$process.HasExited) { $process.Kill() }
                if ($process.WaitForExit(1000)) { $exitCode = $process.ExitCode }
                else { $reason = 'process-cleanup-error' }
            } catch {
                $reason = 'process-cleanup-error'
            }
        }
        $process.Dispose()
        foreach ($stream in $streams) {
            [IO.File]::WriteAllText($stream.Path, $stream.Text.ToString())
        }
        foreach ($path in $stdout, $stderr) {
            if (!(Test-Path -LiteralPath $path)) { [IO.File]::WriteAllText($path, '') }
        }
    }
    [pscustomobject]@{
        program = $Program; arguments = $Arguments; exitCode = $exitCode
        reason = $reason; elapsedMs = $clock.ElapsedMilliseconds; stdout = [IO.Path]::GetRelativePath($run, $stdout); stderr = [IO.Path]::GetRelativePath($run, $stderr)
    }
}

function Get-ToolEvidence([string] $Id) {
    $path = $null
    $candidate = @($tools[$Id] | ForEach-Object {
        Get-Command $_ -CommandType Application -ErrorAction SilentlyContinue
    } | Select-Object -First 1)
    if ($candidate.Count) { $path = $candidate[0].Source }
    if ($null -eq $path) {
        return @{ presence = 'not-found-on-path'; nativeDebug = 'not-run'; reason = 'tool-not-found-on-path' }
    }
    $reason = switch ($Id) {
        Frida { 'instrumentation-adapter-out-of-scope' }
        Ghidra { 'native-debug-launcher-unverified' }
        default { 'native-debug-adapter-unavailable' }
    }
    $evidence = @{ presence = 'found-on-path'; nativeDebug = 'not-run'; path = $path; reason = $reason }
    try {
        $evidence.version = (Get-Item -LiteralPath $path).VersionInfo.FileVersion
        $evidence.sha256 = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
    } catch {
        $evidence.reason = 'tool-metadata-unavailable'
    }
    $evidence
}

function Start-LabIde($Directory, $Executable) {
    if (!$Executable) { $Executable = Join-Path $env:LOCALAPPDATA 'Programs/Microsoft VS Code/Code.exe' }
    if (!(Test-Path -LiteralPath $Executable -PathType Leaf)) { return $null }
    $Executable = (Resolve-Path -LiteralPath $Executable).Path
    $metadata = Get-Item -LiteralPath $Executable
    if ($metadata.Name -ne 'Code.exe' -or $metadata.VersionInfo.ProductName -notlike '*Visual Studio Code*') {
        return $null
    }
    $ideDir = (New-Item -ItemType Directory -Path (Join-Path $Directory 'ide')).FullName
    $userDir = (New-Item -ItemType Directory -Path (Join-Path $ideDir 'user')).FullName
    $settingsDir = (New-Item -ItemType Directory -Path (Join-Path $userDir 'User')).FullName
    '{"telemetry.telemetryLevel":"off","update.mode":"none","workbench.startupEditor":"none"}' |
        Set-Content -LiteralPath (Join-Path $settingsDir 'settings.json')
    $document = Join-Path $ideDir 'vmkek-a03-ide-fixture.rs'
    'fn main() {}' | Set-Content -LiteralPath $document
    $pidFile = Join-Path $ideDir 'child.pid'
    $gateName = 'Local\vmkek-a03-ide-' + [guid]::NewGuid().ToString('N')
    $job = [Vmkek.Lab.ProcessJob]::Create()
    $gate = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $gateName)
    $launcher = [Diagnostics.Process]::new()
    $child = $null
    $assigned = $false
    try {
        $info = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh.exe'))
        $info.WorkingDirectory = $ideDir
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.WindowStyle = 'Hidden'
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        foreach ($arg in '-NoProfile', '-NonInteractive', '-EncodedCommand', $script:LabLauncherCommand) {
            $info.ArgumentList.Add($arg)
        }
        foreach ($key in @($info.Environment.Keys)) {
            if ($key -match '^(VSCODE_|ELECTRON_|NODE_|VMKEK_)') { $null = $info.Environment.Remove($key) }
        }
        $info.Environment['VMKEK_A02_LAUNCH'] = @{
            gate = $gateName; program = $Executable; directory = $ideDir; hidden = $true; pidFile = $pidFile
            arguments = @('--new-window', '--disable-extensions', '--disable-telemetry',
                '--user-data-dir', $userDir, '--extensions-dir', (Join-Path $ideDir 'extensions'), $document)
        } | ConvertTo-Json -Compress
        $launcher.StartInfo = $info
        if (!$launcher.Start()) { throw 'IDE launcher start failed' }
        $job.Assign($launcher.SafeHandle)
        $assigned = $true
        if (!$gate.Set()) { throw 'IDE launcher release failed' }
        $streams = @($launcher.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null),
            $launcher.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null))
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ($timer.Elapsed.TotalSeconds -lt 15 -and !$launcher.HasExited) {
            if (!$child -and (Test-Path -LiteralPath $pidFile -PathType Leaf)) {
                $id = [int] [IO.File]::ReadAllText($pidFile)
                $child = [Diagnostics.Process]::GetProcessById($id)
            }
            if ($child -and !$child.HasExited) {
                $child.Refresh()
                if ([Vmkek.Lab.ProcessJob]::HasWindowTitle($child.SafeHandle, 'vmkek-a03-ide-fixture.rs')) {
                    return @{
                        job = $job; launcher = $launcher; child = $child; streams = $streams
                        sha256 = (Get-FileHash -LiteralPath $Executable).Hash.ToLowerInvariant()
                        version = $metadata.VersionInfo.ProductVersion
                    }
                }
            }
            Start-Sleep -Milliseconds 50
        }
        throw 'IDE did not open the dedicated fixture'
    } catch {
        Write-Warning ("Isolated IDE setup failed: " + $_.Exception.Message)
        $job.Dispose()
        if (!$assigned) {
            try { if (!$launcher.HasExited) { $launcher.Kill() } } catch {}
        }
        if ($child) { $child.Dispose() }
        $launcher.Dispose()
        return $null
    } finally {
        $gate.Dispose()
    }
}

function Get-IdeEvidence {
    if (!$script:labIde) { return @{ verified = $false } }
    $child = $script:labIde.child
    $child.Refresh()
    @{
        verified = (!$child.HasExited -and [Vmkek.Lab.ProcessJob]::HasWindowTitle($child.SafeHandle, 'vmkek-a03-ide-fixture.rs'))
        product = 'Visual Studio Code'; sha256 = $script:labIde.sha256; version = $script:labIde.version
    }
}

function Stop-LabIde {
    if (!$script:labIde) { return }
    $ide = $script:labIde
    try {
        $ide.job.Dispose()
        if (!$ide.launcher.WaitForExit(3000) -or !$ide.child.WaitForExit(3000)) {
            throw 'Owned IDE process tree did not exit'
        }
    } catch { $manifest.cleanupError = 'ide-job-cleanup-failed' }
    finally {
        $ide.child.Dispose()
        $ide.launcher.Dispose()
        $script:labIde = $null
    }
}

function Get-PhaseRecords($Text, $Prefix) {
    @([regex]::Matches($Text, "(?m)^$Prefix=(\w+) tick_ms=(\d+)\r?$") | ForEach-Object {
        @{ name = $_.Groups[1].Value; tickMs = [long] $_.Groups[2].Value }
    })
}

function Invoke-LabCase($Definition, [int] $Iteration) {
    $directory = (New-Item -ItemType Directory -Path (Join-Path $run "$($Definition.Id)-$Iteration")).FullName
    $record = Join-Path $directory 'fixture.log'
    $childEnvironment = @{ VMKEK_A02_PROFILE = $Profile; VMKEK_A02_RECORD = $record }
    if ($Definition.Scenario) { $childEnvironment.VMKEK_A03_SCENARIO = $Definition.Scenario }
    if ($Definition.Compatibility) { $childEnvironment.VMKEK_A08_ACTIVITY_DLL = $compatibilityDll }
    $ideExpected = $Definition.Scenario -eq 'ide'
    $ideOwned = $null -ne $script:labIde
    $ideBefore = if ($ideExpected) { Get-IdeEvidence }
    $arguments = @('--lab', $fixture) + $Definition.Args
    $result = if ($Definition.Online) {
        Invoke-ResponseProcess $observer $arguments $directory 'observer' $childEnvironment
    } else {
        Invoke-Bounded $observer $arguments $directory $probeSeconds 'observer' $childEnvironment
    }
    $oracleText = [IO.File]::ReadAllText((Join-Path $run $result.stdout))
    $fixtureText = ''
    $oversized = $false
    if (Test-Path -LiteralPath $record -PathType Leaf) {
        $file = Get-Item -LiteralPath $record
        if ($file.Length -le $logLimit) { $fixtureText = [IO.File]::ReadAllText($record) }
        else { $oversized = $true; Clear-Content -LiteralPath $record }
    }
    $oracle = @(Get-PhaseRecords $oracleText 'oracle')
    $phases = @(Get-PhaseRecords $fixtureText 'phase')
    $mitigations = @([regex]::Matches($oracleText, '(?m)^mitigation=(\w+) (flags=0x[\da-f]{8}|unavailable=\d+)\r?$') | ForEach-Object {
        @{ name = $_.Groups[1].Value; result = $_.Groups[2].Value }
    })
    $observations = [regex]::Matches($fixtureText, '(?m)^observation=(\w+) reason=(\w+) decision=(\w+) tick_ms=(\d+)\r?$')
    $policy = [regex]::Match($fixtureText, '(?m)^policy_sha256=([\da-f]{64}) policy_epoch=(\d+)\r?$')
    $invokes = [regex]::Matches($fixtureText, '(?m)^invoke_status=(\d+) output_check=(true|false)\r?$')
    $expectedAttached = @([bool] $Definition.Attached)
    $expectedPhases = 'startup,idle,protected_call,shutdown'
    if ($Definition.Scenario -eq 'detach') {
        $expectedAttached += $false
        $expectedPhases = 'startup,idle,protected_call,recovery_wait,protected_call,shutdown'
    }
    $calls = @(
        for ($index = 0; $index -lt $observations.Count -and $index -lt $invokes.Count; $index++) {
            $sample = $observations[$index]
            $invoke = $invokes[$index]
            $event = if ($index -eq 1) { 'detach_succeeded' }
                     elseif ($Definition.EvidenceEvent) { $Definition.EvidenceEvent }
                     else { 'initial_breakpoint' }
            $oracleTick = @($oracle | Where-Object name -eq $event | Select-Object -First 1)
            $sampleTick = [long] $sample.Groups[4].Value
            @{
                observation = $sample.Groups[1].Value; reason = $sample.Groups[2].Value
                decision = $sample.Groups[3].Value; sampleTickMs = $sampleTick
                eventToSampleMs = if ($oracleTick.Count) { $sampleTick - $oracleTick[0].tickMs }
                invokeStatus = $invoke.Groups[1].Value; outputVerified = ($invoke.Groups[2].Value -eq 'true')
            }
        }
    )
    $groundTruth = if (($oracle.name -join ',') -eq $Definition.Oracle) {
        if ($expectedAttached.Count -eq 2) { 'attached-then-detached' }
        elseif ($Definition.Attached) { 'attached' } else { 'clean-owned-child' }
    }
    $timeline = @($oracle[0].tickMs)
    if ($Definition.Id -eq 'StartupDebugger' -or $Definition.Startup) {
        $timeline += @($oracle[1].tickMs, $oracle[2].tickMs)
    }
    $timeline += @($phases[0].tickMs, $phases[1].tickMs)
    if ($Definition.Id -ne 'StartupDebugger' -and !$Definition.Startup) {
        $timeline += @($oracle | Where-Object name -in 'ready', 'attach_succeeded',
            'debug_process_event', 'initial_breakpoint', 'software_breakpoint',
            'hardware_armed', 'hardware_breakpoint_restored' | ForEach-Object { $_.tickMs })
    }
    $timeline += @($phases[2].tickMs, $calls[0].sampleTickMs)
    if ($expectedAttached.Count -eq 2) {
        $timeline += @($phases[3].tickMs)
        $timeline += @($oracle | Where-Object name -in 'detach_ready', 'detach_succeeded' | ForEach-Object { $_.tickMs })
        $timeline += @($phases[4].tickMs, $calls[1].sampleTickMs)
    }
    $timeline += @($phases[-1].tickMs, $oracle[-1].tickMs)
    $timelineValid = ($null -notin $timeline) -and (($timeline -join ',') -eq (($timeline | Sort-Object) -join ','))
    $scenarioEvidence = Get-ScenarioEvidence $Definition.Scenario $fixtureText
    $scenarioEvidence.labIdeActive = $ideOwned
    $scenarioEvidence.verified = $scenarioEvidence.verified -and ($ideExpected -eq $ideOwned)
    if ($ideExpected) { $scenarioEvidence.verified = $scenarioEvidence.verified -and $ideBefore.verified }
    $compatibility = if ($Definition.Compatibility) { Get-CompatibilityEvidence $Definition $fixtureText $oracleText $mitigations }
    $expectedMitigations = if ($Definition.Compatibility) { 4 } else { 3 }
    $reason = $result.reason
    if (!$reason) {
        $reason = if ($result.exitCode -ne 0) { 'observer-or-child-exit' }
        elseif ($oversized) { 'fixture-log-limit' }
        elseif (!$groundTruth) { 'oracle-mismatch' }
        elseif (($phases.name -join ',') -ne $expectedPhases) { 'phase-mismatch' }
        elseif (!$timelineValid) { 'timeline-mismatch' }
        elseif (!$policy.Success -or $mitigations.Count -ne $expectedMitigations) { 'metadata-incomplete' }
        elseif (!$scenarioEvidence.verified) { 'scenario-control-mismatch' }
        elseif ($Definition.Compatibility -and !$compatibility.verified) { 'compatibility-control-mismatch' }
        elseif ($observations.Count -ne $expectedAttached.Count -or $invokes.Count -ne $expectedAttached.Count) { 'sample-count-mismatch' }
        else { Compare-ObservedCalls $calls $expectedAttached ($Definition.Scenario -eq 'disabled') }
    }
    $row = @{
        id = $Definition.Id; iteration = $Iteration; profile = $Profile; required = $true
        runtimeProfile = if ($Definition.Online) { 'Online' } else { 'Offline' }
        status = if ($reason) { 'failed' } else { 'verified' }; reason = $reason
        groundTruth = $groundTruth; oracle = $oracle; phases = $phases; mitigations = $mitigations
        observation = $calls[0].observation; observationReason = $calls[0].reason
        decision = $calls[0].decision; sampleTickMs = $calls[0].sampleTickMs
        breakpointToSampleMs = $calls[0].eventToSampleMs
        invokeStatus = $calls[0].invokeStatus; outputVerified = $calls[0].outputVerified
        calls = $calls; scenarioEvidence = $scenarioEvidence
        policySha256 = $policy.Groups[1].Value; policyEpoch = $policy.Groups[2].Value; seed = $null
        process = $result; fixtureLog = [IO.Path]::GetRelativePath($run, $record)
    }
    if ($Definition.Compatibility) { $row.compatibility = $compatibility }
    $row
}

function Compare-ObservedCalls($Calls, [bool[]] $ExpectedAttached, [bool] $Disabled) {
    for ($index = 0; $index -lt $ExpectedAttached.Count; $index++) {
        $attached = $ExpectedAttached[$index]
        $expectedObservation = if ($Disabled) { 'Disabled' }
                               elseif ($attached) { 'Observed' } else { 'NotObservedWithinScope' }
        $expectedDecision = if ($Disabled) { 'Allow' }
                            elseif ($attached -and $Profile -eq 'enforce') { 'RequestOwnStop' }
                            else { 'ReportOnly' }
        $stopLatched = $Profile -eq 'enforce' -and $ExpectedAttached[0] -and !$Disabled
        $expectedStatus = if ($stopLatched) { '3' } else { '0' }
        $call = $Calls[$index]
        if ($call.observation -ne $expectedObservation -or $call.reason -ne 'None') { return 'observation-mismatch' }
        if ($call.decision -ne $expectedDecision) { return 'decision-mismatch' }
        if ($call.invokeStatus -ne $expectedStatus -or !$call.outputVerified) { return 'invoke-mismatch' }
    }
}

function Get-ScenarioEvidence($Scenario, $Text) {
    switch ($Scenario) {
        { $_ -in 'hardware', 'breakpoint_control' } { @{ verified = ($Text -match '(?m)^breakpoint_function=restored\r?$') } }
        'online_startup' {
            $acknowledged = $Text -match '(?m)^online_report=acknowledged repeated_deny=true\r?$'
            @{ verified = $acknowledged; serverAcknowledged = $acknowledged }
        }
        'online_late' {
            $acknowledged = $Text -match '(?m)^online_report=acknowledged repeated_deny=true\r?$'
            $clean = $Text -match '(?m)^online_clean_before_attach=true\r?$'
            @{ verified = ($acknowledged -and $clean); serverAcknowledged = $acknowledged; cleanBeforeAttach = $clean }
        }
        'data' { @{ verified = ($Text -match '(?m)^data_byte=0xcc\r?$') } }
        'cpu_load' {
            $load = [regex]::Match($Text, '(?m)^load_workers=4 load_iterations=(\d+)\r?$')
            @{ verified = ($load.Success -and [long] $load.Groups[1].Value -gt 4); iterations = $load.Groups[1].Value }
        }
        'concurrent' { @{ verified = ($Text -match '(?m)^call_integrity=recursive_and_concurrent\r?$') } }
        'ide' { Get-IdeEvidence }
        default { @{ verified = $true } }
    }
}

function Get-MissingCaseRows($Definitions, $Completed, [string] $Reason) {
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($row in $Completed) {
        if ($row.required) { $null = $seen.Add("$($row.id)/$($row.iteration)") }
    }
    foreach ($definition in $Definitions) {
        foreach ($iteration in 1..$Repeat) {
            if (!$seen.Add("$($definition.Id)/$iteration")) { continue }
            @{
                id = $definition.Id; iteration = $iteration; profile = $Profile; required = $true
                status = 'not-run'; reason = $Reason
            }
        }
    }
}

function Invoke-ResponseProcess($Program, $Arguments, $Directory, $Name, $ProbeEnvironment) {
    $scratch = (New-Item -ItemType Directory -Path (Join-Path $buildDir.FullName ('response-config-' + [guid]::NewGuid().ToString('N')))).FullName
    try {
        $localConfig = Join-Path $scratch 'config.bin'
        Copy-Item -LiteralPath $script:responseConfig -Destination $localConfig
        $ProbeEnvironment.VMKEK_A07_ONLINE_CONFIG = $localConfig
        Invoke-Bounded $Program $Arguments $Directory $probeSeconds $Name $ProbeEnvironment
    } finally {
        if ([IO.Path]::GetDirectoryName($scratch) -ne $buildDir.FullName) { throw 'Response config directory outside owned build' }
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}

function Invoke-ResponseBoundary($Definition, [int] $Iteration) {
    $directory = (New-Item -ItemType Directory -Path (Join-Path $run "$($Definition.Id)-$Iteration")).FullName
    $filter = if ($Definition.Online) { 'online::tests::lifecycle::response::native_response_active_reentry_and_parallel' }
              else { 'observations::tests::response::response_offline_stop_discards_admitted_work_and_latches_for_the_activation' }
    $program = $observer
    $mode = if ($Definition.Online) { '--response-active' } else { '--response-offline-active' }
    $arguments = @('--lab', $responseTests, $mode)
    $record = Join-Path $directory 'response-proof.log'
    $probeEnvironment = @{ VMKEK_A07_RESPONSE_RECORD = $record }
    $result = if ($Definition.Online) {
        Invoke-ResponseProcess $program $arguments $directory 'response' $probeEnvironment
    } else {
        Invoke-Bounded $program $arguments $directory $probeSeconds 'response' $probeEnvironment
    }
    $stdout = [IO.File]::ReadAllText((Join-Path $run $result.stdout))
    $oracle = @(Get-PhaseRecords $stdout 'oracle')
    $proof = ''
    if ((Test-Path -LiteralPath $record -PathType Leaf) -and (Get-Item -LiteralPath $record).Length -le $logLimit) {
        $proof = [IO.File]::ReadAllText($record)
    }
    $signature = if ($Definition.Online) { 'wipes=verified report=acknowledged' }
                 else { 'inconclusive=recovered fresh=allowed' }
    $policy = [regex]::Match($proof, "(?m)^active=2 reentry=committed cancelled=2 outputs=intact $signature policy_sha256=([\da-f]{64}) epoch=(\d+)\r?$")
    $expectedOracle = if ($Definition.Online) { $cases[2].Oracle } else { $debuggerCases[3].Oracle }
    $reason = if ($result.reason) { $result.reason }
              elseif ($result.exitCode -ne 0) { 'response-test-exit' }
              elseif (!$policy.Success) { 'response-proof-mismatch' }
              elseif (($oracle.name -join ',') -ne $expectedOracle) { 'response-oracle-mismatch' }
    $row = @{
        id = $Definition.Id; iteration = $Iteration; profile = $Profile; required = $true
        runtimeProfile = if ($Definition.Online) { 'Online' } else { 'Offline' }
        scope = 'native-runtime-held-admission-boundary'; oracle = $oracle
        policySha256 = $policy.Groups[1].Value; policyEpoch = $policy.Groups[2].Value
        status = if ($reason) { 'failed' } else { 'verified' }; reason = $reason
        process = $result; test = $filter; proof = $policy.Value.Trim()
    }
}

function Invoke-SchedulingCase([int] $Iteration) {
    $directory = (New-Item -ItemType Directory -Path (Join-Path $run "Scheduling-$Iteration")).FullName
    $result = Invoke-Bounded $fixture @() $directory $probeSeconds 'scheduling' @{}
    $stdout = [IO.File]::ReadAllText((Join-Path $run $result.stdout))
    $scenarios = @([regex]::Matches($stdout, '(?m)^scheduling scenario=(\w+) result=verified(?: ([^\r\n]+))?\r?$') |
        ForEach-Object { @{ name = $_.Groups[1].Value; evidence = $_.Groups[2].Value } })
    $admission = @([regex]::Matches($stdout, '(?m)^admission mode=(\w+) count=(\d+) p50_ns=(\d+) p95_ns=(\d+) max_ns=(\d+)\r?$') |
        ForEach-Object { @{ mode = $_.Groups[1].Value; count = [long]$_.Groups[2].Value
            p50Ns = [long]$_.Groups[3].Value; p95Ns = [long]$_.Groups[4].Value; maxNs = [long]$_.Groups[5].Value } })
    $startup = [regex]::Match($stdout, '(?m)^cost baseline_start_ns=(\d+) observed_start_ns=(\d+) verification_ns=(\d+)\r?$')
    $events = [regex]::Match($stdout, '(?m)^scheduling scenario=sustained_event result=verified invoke=Denied detect_ns=(\d+) reaction_ns=(\d+)\r?$')
    $policies = @([regex]::Matches($stdout, '(?m)^policy epoch=1 sha256=([0-9a-f]{64})\r?$') |
        ForEach-Object { @{ epoch = 1; sha256 = $_.Groups[1].Value } })
    $reason = $result.reason
    if (!$reason) {
        $reason = if ($result.exitCode -ne 0) { 'fixture-exit' }
        elseif (($scenarios.name -join ',') -ne 'concurrent_load,stale,read_error,resumed,sustained_event,closed,observe_continues') { 'scheduling-scenario-mismatch' }
        elseif (($admission.mode -join ',') -ne 'disabled,enabled' -or (($admission | ForEach-Object { $_.count }) -join ',') -ne '512,512' -or
            !$startup.Success -or !$events.Success -or $policies.Count -ne 2) { 'scheduling-metadata-incomplete' }
    }
    @{
        id = 'Scheduling'; iteration = $Iteration; profile = $Profile; required = $true
        status = if ($reason) { 'failed' } else { 'verified' }; reason = $reason
        scenarios = $scenarios; admission = $admission; policies = $policies
        baselineStartupNs = if ($startup.Success) { [long]$startup.Groups[1].Value }
        observedStartupNs = if ($startup.Success) { [long]$startup.Groups[2].Value }
        verificationNs = if ($startup.Success) { [long]$startup.Groups[3].Value }
        detectionNs = if ($events.Success) { [long]$events.Groups[1].Value }
        reactionNs = if ($events.Success) { [long]$events.Groups[2].Value }
        detectionOracle = 'owned-synthetic-state'; process = $result; seed = $null
    }
}

function Invoke-IntegrityCase([int] $Iteration) {
    $directory = (New-Item -ItemType Directory -Path (Join-Path $run "Integrity-$Iteration")).FullName
    $result = Invoke-Bounded $fixture $integrityDlls $directory $probeSeconds 'integrity' @{}
    $stdout = [IO.File]::ReadAllText((Join-Path $run $result.stdout))
    $scenarios = @([regex]::Matches($stdout, '(?m)^integrity scenario=(\w+) result=verified(?: ([^\r\n]+))?\r?$') |
        ForEach-Object { @{ name = $_.Groups[1].Value; evidence = $_.Groups[2].Value } })
    $cost = @([regex]::Matches($stdout, '(?m)^cost pass=(\w+) file_bytes=(\d+) layout_bytes=(\d+) memory_bytes=(\d+) elapsed_ns=(\d+)\r?$') |
        ForEach-Object { @{ pass = $_.Groups[1].Value; fileBytes = [long]$_.Groups[2].Value
            layoutBytes = [long]$_.Groups[3].Value; memoryBytes = [long]$_.Groups[4].Value; elapsedNs = [long]$_.Groups[5].Value } })
    $policies = @([regex]::Matches($stdout, '(?m)^policy epoch=(\d+) sha256=([0-9a-f]{64})\r?$') |
        ForEach-Object { @{ epoch = [long]$_.Groups[1].Value; sha256 = $_.Groups[2].Value } })
    $mitigations = @([regex]::Matches($stdout, '(?m)^mitigation name=(\w+) available=(\d+) flags=(0x[0-9a-f]{8})\r?$') |
        ForEach-Object { @{ name = $_.Groups[1].Value; available = $_.Groups[2].Value -eq '1'; flags = $_.Groups[3].Value } })
    $reason = $result.reason
    if (!$reason) {
        $reason = if ($result.exitCode -ne 0) { 'fixture-exit' }
        elseif (($scenarios.name -join ',') -ne 'held_module,clean,outside_scope,inside_scope,inaccessible,restored,unloaded,signed_update') { 'integrity-scenario-mismatch' }
        elseif (($cost.pass -join ',') -ne 'full,incremental' -or $cost[0].fileBytes -le 0 -or
            $cost[0].layoutBytes -le 0 -or $cost[1].fileBytes -ne 0 -or $cost[1].layoutBytes -ne 0 -or
            $cost[1].memoryBytes -le 0 -or $cost[1].memoryBytes -ne $cost[0].memoryBytes) { 'integrity-cost-mismatch' }
        elseif (($policies.epoch -join ',') -ne '1,2' -or $mitigations.Count -ne 3) { 'integrity-metadata-incomplete' }
    }
    @{
        id = 'Integrity'; iteration = $Iteration; profile = $Profile; required = $true
        status = if ($reason) { 'failed' } else { 'verified' }; reason = $reason
        scenarios = $scenarios; cost = $cost; policies = $policies; mitigations = $mitigations
        decision = 'measurement-only'; process = $result; seed = $null
    }
}

function Invoke-InstrumentationCase([string] $Id, [int] $Iteration) {
    if ($Id -eq 'FridaGadget' -and !$gadgetPath) {
        return @{ id = $Id; iteration = $Iteration; profile = $Profile; required = $true
            status = 'not-run'; classification = 'unsupported'; reason = $gadgetReason }
    }
    $directory = (New-Item -ItemType Directory -Path (Join-Path $run "$Id-$Iteration")).FullName
    $executable = if ($Id -in 'StalkerClean', 'FridaStalker') { $stalkerFixture } else { $fixture }
    $module = $instrumentationDll
    $scratch = New-Item -ItemType Directory -Path (Join-Path $buildDir.FullName "case-$Id-$Iteration")
    $renamed = $Id.EndsWith('Renamed', [StringComparison]::Ordinal)
    if ($renamed) {
        $executable = Join-Path $directory 'instrumentation_lab_renamed.exe'
        $module = Join-Path $directory 'a05-renamed.dll'
        Copy-Item -LiteralPath $fixture -Destination $executable
        Copy-Item -LiteralPath $instrumentationDll -Destination $module
    }
    $arguments = @('-B', '-s', $controller, $Id, $executable, $module)
    if ($Id -eq 'FridaGadget') { $arguments += $gadgetPath }
    try {
        $result = Invoke-Bounded $python $arguments $directory $probeSeconds 'instrumentation' @{
            PYTHONPATH = $frida.packageRoot; TEMP = $scratch.FullName; TMP = $scratch.FullName
        }
    } finally {
        if ($renamed) {
            Remove-Item -LiteralPath $executable, $module -ErrorAction SilentlyContinue
        }
        if ($scratch.Parent.FullName -ne $buildDir.FullName -or $scratch.Name -notlike 'case-*' -or
            ($scratch.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Instrumentation scratch directory is outside the owned build'
        }
        $scratch.Delete($true)
    }
    $stdout = [IO.File]::ReadAllText((Join-Path $run $result.stdout))
    $json = [regex]::Match($stdout, '(?m)^a05 (\{[^\r\n]+\})\r?$')
    $measurement = if ($json.Success) { $json.Groups[1].Value | ConvertFrom-Json }
    $expectedActivity = switch ($Id) {
        'FridaSpawn' { 'spawn,witness' }
        { $_ -in 'FridaAttach', 'OwnedMarkerDuringFridaAttach' } { 'witness' }
        'FridaGadget' { 'gadget' }
        { $_ -in 'FridaInterceptor', 'FridaInterceptorRenamed' } { 'witness,interceptor' }
        'FridaStalker' { 'witness,stalker' }
        'BenignProfiler' { 'witness,profiler' }
        default { '' }
    }
    $fixtureKey = if ($Id -in 'StalkerClean', 'FridaStalker') { 'instrumentation_lab_stalker.exe' }
                  else { 'instrumentation_lab.exe' }
    $toolCase = $Id.StartsWith('Frida') -or $Id -eq 'OwnedMarkerDuringFridaAttach'
    $reason = $result.reason
    if (!$reason) {
        $reason = if ($result.exitCode -ne 0) { 'tool-or-fixture-exit' }
        elseif (!$measurement) { 'missing-fixture-measurement' }
        elseif (($measurement.activity.kind -join ',') -ne $expectedActivity) { 'tool-activity-mismatch' }
        elseif ($measurement.fridaVersion -ne $frida.fridaVersion -or
                $measurement.fridaSha256 -ne $frida.fridaSha256 -or
                $measurement.fixtureSha256 -ne $manifest.binaries[$fixtureKey] -or
                $measurement.moduleSha256 -ne $manifest.binaries['a05-owned.dll']) { 'provenance-mismatch' }
        elseif ($measurement.decision -ne 'ReportOnly' -or $measurement.invokeStatus -ne 0 -or
                $measurement.fixtureMarker -ne 44 -or $measurement.policyEpoch -ne 1 -or
                $measurement.policySha256 -notmatch '^[a-f0-9]{64}$') { 'observe-contract-mismatch' }
        elseif ($measurement.teardown.method -ne 'owned-job-close' -or ($null -eq $measurement.teardown.exitCode -or $measurement.teardown.exitCode -ne 0)) {
            'owned-teardown-unverified'
        }
        elseif ($Id -eq 'BenignProfiler' -and $measurement.profilerElapsedNs -le 0) { 'profiler-control-mismatch' }
        elseif ($Id -eq 'OwnedMarkerDuringFridaAttach' -and ($measurement.classification -ne 'detected' -or
                $measurement.changeTickMs -lt $measurement.activity[0].tickMs -or
                $measurement.changeTickMs -gt $measurement.sampleTickMs -or $measurement.protection -ne 0x20)) {
            'controlled-marker-mismatch'
        }
        elseif ($toolCase -and $measurement.classification -notin
            'detected', 'missed', 'inconclusive', 'unsupported') { 'instrumentation-classification-mismatch' }
        elseif (!$toolCase -and $measurement.classification -ne 'clean') { 'clean-control-mismatch' }
    }
    @{
        id = $Id; iteration = $Iteration; profile = $Profile; required = $true
        status = if ($reason) { 'failed' } else { 'verified' }; reason = $reason
        classification = $measurement.classification; measurement = $measurement
        fixtureProfile = if ($fixtureKey -eq 'instrumentation_lab_stalker.exe') { 'compiler-default-research' }
                         else { 'cfg-cet' }
        fixtureName = Split-Path -Leaf $executable; moduleName = Split-Path -Leaf $module
        process = $result; seed = $null
    }
}

function Get-DebuggerCapabilities([string] $Build) {
    @{
        signalId = 'DebuggerAttachment'; scope = 'native-x64-current-process'; build = $Build
        status = if ($Build -eq '10.0.26300.9974') { 'supported' } else { 'Unsupported' }
        source = 'WindowsDebuggerApis'; dependencyGroup = 'ProcessDebugState'
        coverage = @('startup', 'late-attach', 'detach', 'software-breakpoint', 'hardware-breakpoint')
        limitation = 'Sustained user-mode attachment within the sampled process'
    }
    @{
        signalId = 'LegacyStandaloneLayout'; scope = 'legacy-pe-only'; status = 'Unsupported'
        limitation = 'Existing standalone checks lack per-signal A03 qualification'
        checks = @('BeingDebugged', 'NtGlobalFlag', 'HeapFlags', 'HardwareDr', 'DebugPort',
            'DebugObject', 'ProcessDebugFlags', 'ProtectedHandle', 'Int2d', 'TrapFlag',
            'ThreadHideFromDebugger', 'InstrumentationCallback', 'DbgUiRemoteBreakin')
    }
    @{
        signalId = 'LegacyStandaloneHeuristics'; scope = 'legacy-pe-only'; status = 'Unsupported'
        limitation = 'IDE names, scheduler delay and arbitrary data bytes do not establish attachment'
        checks = @('ParentDebugger', 'TickDelta', 'LoaderInt3')
    }
    @{ signalId = 'KernelDebugger'; scope = 'outside-user-mode'; status = 'Unsupported' }
}

$manifest = [ordered]@{
    version = 1; case = $Case; profile = $Profile; repeat = $Repeat
    limits = @{ probeSeconds = $probeSeconds; buildSeconds = $buildSeconds; perStreamChars = $logLimit; maxRepeat = 30 }
    host = $null; sourceSha256 = [ordered]@{}; tools = [ordered]@{}; build = @(); binaries = @{}; rows = $rows
}
$selected = if ($Case -eq 'Debugger') { $debuggerCases }
            elseif ($Case -eq 'Integrity') { @(@{ Id = 'Integrity' }) }
            elseif ($Case -eq 'Scheduling') { @(@{ Id = 'Scheduling' }) }
            elseif ($Case -eq 'Response') { $responseCases }
            elseif ($Case -eq 'Compatibility') { @(Get-CompatibilityCases $cleanOracle) }
            elseif ($Case -eq 'Instrumentation') { $instrumentationCases }
            else { @($cases | Where-Object { $Case -eq 'All' -or $_.Id -eq $Case }) }
$buildDir = $null
$script:labIde = $null
$setupReason = 'setup-unavailable'
$fixtureExample = if ($Case -eq 'Integrity') { 'integrity_lab' }
                  elseif ($Case -eq 'Instrumentation') { 'instrumentation_lab' }
                  elseif ($Case -eq 'Scheduling') { 'scheduling_lab' }
                  else { 'anti_analysis_lab' }
$fixtureSource = "crates/runtime/examples/$fixtureExample.rs"
try {
    if (!$IsWindows -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
        throw 'Windows x64 PowerShell is required'
    }
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 10
    $win = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $manifest.host = @{
        os = $os.Caption; build = "$($os.Version).$($win.UBR)"
        cpu = (Get-CimInstance Win32_Processor -OperationTimeoutSec 10 | Select-Object -First 1).Name
        powershell = $PSVersionTable.PSVersion.ToString(); architecture = 'x64'
    }
    foreach ($source in 'Cargo.lock', $fixtureSource, 'tests/windows/t6_debug_observer.c', 'tests/windows/anti_analysis.ps1', 'tests/windows/anti_analysis_process.cs') {
        $manifest.sourceSha256[$source] = (Get-FileHash -LiteralPath (Join-Path $root $source)).Hash.ToLowerInvariant()
    }
    if ($Case -eq 'Response') {
        if ($Profile -ne 'enforce') {
            $setupReason = 'response-requires-enforce'
            throw 'Response requires enforce'
        }
        if ($env:VMKEK_A07_ONLINE_CONFIG -and (Test-Path -LiteralPath $env:VMKEK_A07_ONLINE_CONFIG -PathType Leaf)) {
            $script:responseConfig = (Resolve-Path -LiteralPath $env:VMKEK_A07_ONLINE_CONFIG).Path
        }
        foreach ($source in 'crates/runtime/examples/support/response_online.rs',
            'crates/runtime/src/observations.rs', 'crates/runtime/src/observations/tests/response.rs',
            'crates/runtime/src/state.rs', 'crates/runtime/src/online.rs',
            'crates/runtime/src/online/tests/lifecycle.rs', 'crates/runtime/src/online/tests/lifecycle/response.rs',
            'crates/runtime/test_support/response_config.rs', 'crates/runtime/test_support/response_observer.rs',
            'crates/server/examples/r13_online.rs') {
            $manifest.sourceSha256[$source] = (Get-FileHash -LiteralPath (Join-Path $root $source)).Hash.ToLowerInvariant()
        }
    }
    if ($Case -eq 'Scheduling') {
        if ($Profile -ne 'observe') {
            $setupReason = 'scheduling-requires-observe'
            throw 'Scheduling measures observe and a dedicated mandatory enforce control'
        }
        foreach ($source in 'crates/runtime/src/observations.rs', 'crates/runtime/src/observations/scheduler.rs',
            'crates/runtime/src/online/stop_policy.rs', 'crates/runtime/src/state.rs') {
            $manifest.sourceSha256[$source] = (Get-FileHash -LiteralPath (Join-Path $root $source)).Hash.ToLowerInvariant()
        }
        $manifest.capabilities = @(@{
            scope = 'owned-Windows-x64-scheduler-fixture'; debuggerIntervalMs = 250; integrityIntervalMs = 500
            shutdownWaitMs = 100; maximumWorkers = 16; terminalNoticeSlotsPerRuntime = 1
            staleFixtureTtlMs = 650; startupBudgetMs = 50; admissionP95BudgetUs = 100
            detectionP95BudgetMs = 500; detectionMaxBudgetMs = 2000
        })
    }
    if ($Case -eq 'Integrity') {
        if ($Profile -ne 'observe') {
            $setupReason = 'integrity-requires-observe'
            throw 'Integrity is a measurement-only observe case'
        }
        foreach ($source in 'tests/windows/a04_integrity_fixture.c', 'crates/runtime/src/observations/windows.rs',
            'crates/runtime/src/observations/windows/pe_scope.rs') {
            $manifest.sourceSha256[$source] = (Get-FileHash -LiteralPath (Join-Path $root $source)).Hash.ToLowerInvariant()
        }
        $manifest.capabilities = @(@{
            signalId = 'CodeIntegrity'; scope = 'own-file-backed-immutable-rx'; build = $manifest.host.build
            diskBytesMax = 134217728; relocationDirectoryBytesMax = 4194304; layoutAndHeaderBytesMax = 4390912
            codeBytesPerRuleMax = 65536; ruleCountMax = 16; headerBytesMax = 65536
            fullBudgetMs = 500; incrementalBudgetMs = 100
            deadline = 'cooperative-between-synchronous-reads'
            unsupported = @('imports-and-loader-mutable-slots', 'base-relocation-targets', 'unsigned-or-unlisted-ranges')
        })
    }
    if ($Case -eq 'Instrumentation') {
        if ($Profile -ne 'observe') {
            $setupReason = 'instrumentation-requires-observe'
            throw 'Instrumentation is a measurement-only observe case'
        }
        if ($manifest.host.build -ne '10.0.26300.9974') {
            $setupReason = 'unsupported-os-build'
            throw 'Instrumentation matrix has no qualification for this Windows build'
        }
        foreach ($source in 'tests/windows/a05_owned_fixture.c', 'tests/windows/a05_agent.js',
            'tests/windows/a05_instrumentation.py', 'crates/runtime/src/observations/windows.rs',
            'crates/runtime/src/observations/windows/pe_scope.rs') {
            $manifest.sourceSha256[$source] = (Get-FileHash -LiteralPath (Join-Path $root $source)).Hash.ToLowerInvariant()
        }
        $manifest.capabilities = @(
            @{ signalId = 'CodeIntegrity'; scope = 'signed-own-image-prologue'; mode = 'observe'
                measuredBytes = 16; build = $manifest.host.build; classification = 'effect-based' }
            @{ signalId = 'ToolIdentity'; status = 'Unsupported'; limitation = 'Process names and versions are provenance only' }
            @{ signalId = 'OtherDBI'; status = 'Unsupported'; limitation = 'No qualified owned-fixture adapter in this matrix' }
            @{ signalId = 'StalkerWithCfgCet'; status = 'Unsupported'; limitation = 'Stock 16.6.6 qualification is limited to the compiler-default research fixture' }
        )
        $rows.Add(@{ id = 'FridaStalkerWithCfgCet'; profile = $Profile; iteration = $null; required = $false
            status = 'not-run'; classification = 'unsupported'; reason = 'stock-stalker-cfg-cet-unqualified' })
        foreach ($external in 'DynamoRIO', 'OtherDBI', 'StaticAnalysis') {
            $rows.Add(@{ id = $external; profile = $Profile; iteration = $null; required = $false
                status = 'not-run'; classification = 'unsupported'; reason = 'no-qualified-native-fixture-adapter' })
        }
    }
    if ($Case -eq 'Debugger') {
        $manifest.capabilities = @(Get-DebuggerCapabilities $manifest.host.build)
        if ($manifest.capabilities[0].status -ne 'supported') {
            $setupReason = 'unsupported-os-build'
            throw 'Debugger matrix has no qualification for this Windows build'
        }
    }
    if ($Case -eq 'Compatibility') {
        foreach ($source in 'tests/windows/a08_compatibility.ps1', 'tests/windows/a08_compatibility_fixture.c',
            'crates/runtime/examples/support/compatibility.rs') {
            $manifest.sourceSha256[$source] = (Get-FileHash -LiteralPath (Join-Path $root $source)).Hash.ToLowerInvariant()
        }
        $manifest.compatibility = Get-CompatibilityStand
        foreach ($external in $manifest.compatibility.notRun.Keys) {
            $rows.Add(@{ id = $external; profile = $Profile; iteration = $null; required = $false
                status = 'not-run'; reason = $manifest.compatibility.notRun[$external] })
        }
    }
    foreach ($tool in $tools.Keys) {
        if ($Case -ne 'All' -and $Case -ne $tool) { continue }
        $evidence = Get-ToolEvidence $tool
        $manifest.tools[$tool] = $evidence
        $rows.Add(@{ id = $tool; profile = $Profile; iteration = $null; required = $false; status = 'not-run'; reason = $evidence.reason })
    }
    if ($selected.Count) {
        Initialize-LabProcessLauncher $PSScriptRoot
        $cl = Get-Command cl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        $cargo = Get-Command cargo.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        $rustc = Get-Command rustc.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        $link = Get-Command link.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (!$cl -or !$cargo -or !$rustc -or !$link -or $env:VSCMD_ARG_TGT_ARCH -ne 'x64') {
            throw 'x64 Developer PowerShell, MSVC, linker and Rust 1.95.0 are required'
        }
        foreach ($tool in $cl, $cargo, $rustc, $link) {
            $manifest.tools[$tool.Name] = @{
                path = $tool.Source; version = (Get-Item -LiteralPath $tool.Source).VersionInfo.FileVersion
                sha256 = (Get-FileHash -LiteralPath $tool.Source).Hash.ToLowerInvariant()
            }
        }
        $manifest.host.sdk = $env:WindowsSDKVersion
        $buildDir = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ('vmkek-a02-build-' + [guid]::NewGuid().ToString('N')))
        $observer = Join-Path $buildDir.FullName 'a02-debug-observer.exe'
        $target = if ($CargoTargetDir) {
            (New-Item -ItemType Directory -Path $CargoTargetDir -Force).FullName
        } else { Join-Path $buildDir.FullName 'cargo-target' }
        $builtFixture = Join-Path $target "x86_64-pc-windows-msvc/release/examples/$fixtureExample.exe"
        $fixture = Join-Path $buildDir.FullName "$fixtureExample.exe"
        $version = Invoke-Bounded $rustc.Source @('+1.95.0', '-vV') $run 10 'rust-version' $null
        $manifest.build += $version
        if ($version.reason -or $version.exitCode -ne 0) { throw 'Rust 1.95.0 unavailable' }
        $cargoVersion = Invoke-Bounded $cargo.Source @('+1.95.0', '-V') $run 10 'cargo-version' $null
        $manifest.build += $cargoVersion
        if ($cargoVersion.reason -or $cargoVersion.exitCode -ne 0) { throw 'Cargo 1.95.0 unavailable' }
        $gadgetPath = $null
        $gadgetReason = 'pinned-gadget-unavailable'
        if ($Case -eq 'Instrumentation') {
            $python = if ($env:VMKEK_A05_PYTHON) {
                (Resolve-Path -LiteralPath $env:VMKEK_A05_PYTHON).Path
            } else {
                (Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
            }
            $controller = Join-Path $PSScriptRoot 'a05_instrumentation.py'
            $toolInfo = Invoke-Bounded $python @('-B', $controller, '--tool-info') $run $probeSeconds 'frida-version' $null
            $manifest.build += $toolInfo
            if ($toolInfo.reason -or $toolInfo.exitCode -ne 0) {
                $setupReason = 'stock-frida-unavailable'
                throw 'Stock Frida Python bindings unavailable'
            }
            $frida = [IO.File]::ReadAllText((Join-Path $run $toolInfo.stdout)) | ConvertFrom-Json
            if ($frida.fridaVersion -ne '16.6.6' -or
                $frida.fridaSha256 -ne '991cfa8b30c148713933cf82ccd8835220a9d3745dbc1c4cc3eda2aac9eac94a') {
                $setupReason = 'frida-version-unqualified'
                throw 'Expected stock Frida 16.6.6 Windows x64'
            }
            $manifest.tools.Frida = $frida
            if ($env:VMKEK_A05_GADGET -and (Test-Path -LiteralPath $env:VMKEK_A05_GADGET -PathType Leaf)) {
                $candidate = (Resolve-Path -LiteralPath $env:VMKEK_A05_GADGET).Path
                $gadgetSha = (Get-FileHash -LiteralPath $candidate).Hash.ToLowerInvariant()
                if ($gadgetSha -eq '77f6180bf06a93fcd64f3a7f41b4d11d8ab398bfa66c8915ed06505c093202bb') {
                    $gadgetPath = $candidate
                    $manifest.tools.Gadget = @{ version = '16.6.6'; sha256 = $gadgetSha; mode = 'local-script' }
                } else { $gadgetReason = 'unqualified-gadget-hash' }
            }
        }
        if ($Case -eq 'Compatibility') {
            $compatibilityDll = Join-Path $buildDir.FullName 'a08-compatibility.dll'
            $compileActivity = Invoke-Bounded $cl.Source @('/nologo', '/W4', '/WX', '/LD', '/guard:cf',
                (Join-Path $PSScriptRoot 'a08_compatibility_fixture.c'), "/Fe:$compatibilityDll",
                "/Fo:$($buildDir.FullName)/compatibility.obj", '/link', '/DYNAMICBASE', '/CETCOMPAT',
                'user32.lib', 'gdi32.lib', 'oleacc.lib', 'oleaut32.lib',
                "/IMPLIB:$($buildDir.FullName)/compatibility.lib") $run $buildSeconds 'compile-compatibility' $null
            $manifest.build += $compileActivity
            if ($compileActivity.reason -or $compileActivity.exitCode -ne 0) { throw 'Compatibility DLL build failed' }
        }
        $integrityDlls = @()
        if ($Case -eq 'Integrity') {
            foreach ($revision in 1, 2) {
                $dll = Join-Path $buildDir.FullName "integrity-$revision.dll"
                $compileDll = Invoke-Bounded $cl.Source @('/nologo', '/W4', '/WX', '/LD', '/guard:cf',
                    "/DVMKEK_A04_REVISION=$revision", (Join-Path $PSScriptRoot 'a04_integrity_fixture.c'),
                    "/Fo:$($buildDir.FullName)/integrity-$revision.obj", "/Fe:$dll", '/link',
                    '/DYNAMICBASE', '/BASE:0x0000000500000000', '/CETCOMPAT',
                    "/IMPLIB:$($buildDir.FullName)/integrity-$revision.lib") $run $buildSeconds "compile-dll-$revision" $null
                $manifest.build += $compileDll
                if ($compileDll.reason -or $compileDll.exitCode -ne 0) { throw 'Integrity DLL build failed' }
                $integrityDlls += $dll
            }
        } elseif ($Case -eq 'Instrumentation') {
            $instrumentationDll = Join-Path $buildDir.FullName 'a05-owned.dll'
            $compileDll = Invoke-Bounded $cl.Source @('/nologo', '/W4', '/WX', '/LD', '/Od', '/guard:cf',
                (Join-Path $PSScriptRoot 'a05_owned_fixture.c'), "/Fe:$instrumentationDll",
                "/Fo:$($buildDir.FullName)/a05-owned.obj", '/link', '/DYNAMICBASE', '/CETCOMPAT',
                "/IMPLIB:$($buildDir.FullName)/a05-owned.lib") $run $buildSeconds 'compile-instrumentation-dll' $null
            $manifest.build += $compileDll
            if ($compileDll.reason -or $compileDll.exitCode -ne 0) { throw 'Instrumentation DLL build failed' }
        } elseif ($Case -ne 'Scheduling') {
            $compileObserver = Invoke-Bounded $cl.Source @('/nologo', '/W4', '/WX', '/guard:cf',
                (Join-Path $PSScriptRoot 't6_debug_observer.c'), "/Fe:$observer", "/Fo:$($buildDir.FullName)/observer.obj", '/link', '/CETCOMPAT') $run $buildSeconds 'compile-observer' $null
            $manifest.build += $compileObserver
            if ($compileObserver.reason -or $compileObserver.exitCode -ne 0) { throw 'Observer build failed' }
        }
        $cargoArgs = @('+1.95.0', '--config', 'target.x86_64-pc-windows-msvc.rustflags=["-C","control-flow-guard=checks","-C","link-arg=/CETCOMPAT"]',
            'build', '--locked', '--release', '--target', 'x86_64-pc-windows-msvc', '-p', 'vmkek-runtime',
            '--example', $fixtureExample, '--manifest-path', (Join-Path $root 'Cargo.toml'), '--target-dir', $target)
        $compileFixture = Invoke-Bounded $cargo.Source $cargoArgs $run $buildSeconds 'compile-fixture' $null
        $manifest.build += $compileFixture
        if ($compileFixture.reason -or $compileFixture.exitCode -ne 0) { throw 'Fixture build failed' }
        Copy-Item -LiteralPath $builtFixture -Destination $fixture
        if ($Case -eq 'Instrumentation') {
            # Stock Stalker compatibility is a separate compiler-default fixture.
            $stalkerTarget = Join-Path $buildDir.FullName 'stalker-target'
            $stalkerFixture = Join-Path $buildDir.FullName 'instrumentation_lab_stalker.exe'
            $stalkerArgs = @('+1.95.0', 'build', '--locked', '--release', '--target', 'x86_64-pc-windows-msvc',
                '-p', 'vmkek-runtime', '--example', $fixtureExample, '--manifest-path', (Join-Path $root 'Cargo.toml'),
                '--target-dir', $stalkerTarget)
            $stalkerBuild = Invoke-Bounded $cargo.Source $stalkerArgs $run $buildSeconds 'compile-stalker-fixture' $null
            $manifest.build += $stalkerBuild
            if ($stalkerBuild.reason -or $stalkerBuild.exitCode -ne 0) { throw 'Stalker compatibility fixture build failed' }
            Copy-Item -LiteralPath (Join-Path $stalkerTarget 'x86_64-pc-windows-msvc/release/examples/instrumentation_lab.exe') -Destination $stalkerFixture
        }
        if ($Case -eq 'Response') {
            $testArgs = @('+1.95.0', '--config', 'target.x86_64-pc-windows-msvc.rustflags=["-C","control-flow-guard=checks","-C","link-arg=/CETCOMPAT"]',
                'test', '--no-run', '--locked', '--release', '--target', 'x86_64-pc-windows-msvc',
                '-p', 'vmkek-runtime', '--lib', '--manifest-path', (Join-Path $root 'Cargo.toml'), '--target-dir', $target)
            $compileTests = Invoke-Bounded $cargo.Source $testArgs $run $buildSeconds 'compile-response-tests' $null
            $manifest.build += $compileTests
            if ($compileTests.reason -or $compileTests.exitCode -ne 0) { throw 'Response tests build failed' }
            $buildLog = [IO.File]::ReadAllText((Join-Path $run $compileTests.stderr))
            $artifact = [regex]::Match($buildLog, '(?m)^\s*Executable unittests src[\\/]lib\.rs \((.+\.exe)\)\r?$')
            if (!$artifact.Success) { throw 'Response test executable missing' }
            $responseTests = Join-Path $buildDir.FullName 'response-tests.exe'
            Copy-Item -LiteralPath $artifact.Groups[1].Value -Destination $responseTests
        }
        $binaries = if ($Case -eq 'Integrity') { @($fixture) + $integrityDlls }
                    elseif ($Case -eq 'Instrumentation') { @($fixture, $instrumentationDll, $stalkerFixture) }
                    elseif ($Case -eq 'Scheduling') { @($fixture) }
                    elseif ($Case -eq 'Response') { @($observer, $fixture, $responseTests) }
                    elseif ($Case -eq 'Compatibility') { @($observer, $fixture, $compatibilityDll) }
                    else { @($observer, $fixture) }
        foreach ($binary in $binaries) {
            $manifest.binaries[(Split-Path -Leaf $binary)] = (Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
        }
        if ($CompatibilitySoak) {
            $manifest.soak = Invoke-CompatibilitySoak $selected
        } else {
            foreach ($definition in $selected) {
                $ideCase = $definition.Scenario -eq 'ide'
                if ($ideCase) {
                    $script:labIde = Start-LabIde $buildDir.FullName $IdeExecutable
                    $manifest.ide = Get-IdeEvidence
                }
                try {
                    foreach ($iteration in 1..$Repeat) {
                        if ($ideCase -and !$script:labIde) {
                            $rows.Add(@{ id = $definition.Id; iteration = $iteration; profile = $Profile; required = $true
                                status = 'not-run'; reason = 'isolated-ide-unavailable' })
                            continue
                        }
                        try {
                            if ($Case -eq 'Integrity') { $rows.Add((Invoke-IntegrityCase $iteration)) }
                            elseif ($Case -eq 'Instrumentation') { $rows.Add((Invoke-InstrumentationCase $definition.Id $iteration)) }
                            elseif ($Case -eq 'Scheduling') { $rows.Add((Invoke-SchedulingCase $iteration)) }
                            elseif ($Case -eq 'Response' -and $definition.Online -and !$script:responseConfig) {
                                $rows.Add(@{ id = $definition.Id; iteration = $iteration; profile = $Profile; runtimeProfile = 'Online'
                                    required = $true; status = 'not-run'; reason = 'private-live-online-config-missing' })
                            } elseif ($Case -eq 'Response' -and $definition.Boundary) {
                                $rows.Add((Invoke-ResponseBoundary $definition $iteration))
                            }
                            else { $rows.Add((Invoke-LabCase $definition $iteration)) }
                        }
                        catch { $rows.Add(@{ id = $definition.Id; iteration = $iteration; profile = $Profile; required = $true; status = 'failed'; reason = 'runner-error' }) }
                    }
                } finally {
                    if ($ideCase) { Stop-LabIde }
                }
                if ($manifest.cleanupError) {
                    $setupReason = 'ide-job-cleanup-failed'
                    throw 'Owned IDE cleanup could not be verified'
                }
            }
        }
    }
} catch {
    $manifest.setupError = $_.Exception.Message
    if (!$CompatibilitySoak) {
        foreach ($missing in Get-MissingCaseRows $selected $rows $setupReason) {
            $rows.Add($missing)
        }
    }
} finally {
    Stop-LabIde
    if ($null -ne $buildDir) {
        try {
            $tempRoot = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
            if ($buildDir.Parent.FullName -ne $tempRoot -or $buildDir.Name -notlike 'vmkek-a02-build-*' -or
                ($buildDir.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Temporary build path is outside the expected directory'
            }
            $buildDir.Delete($true)
        }
        catch { $manifest.cleanupError = 'temporary-build-cleanup-failed' }
    }
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $run 'manifest.json')
    Write-Output $run
}
if ($manifest.setupError -or $manifest.cleanupError -or @($rows | Where-Object { $_.status -eq 'failed' -or ($_.required -and $_.status -eq 'not-run') }).Count) { exit 1 }
exit 0
