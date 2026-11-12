function Get-CompatibilityCases([string] $Oracle) {
    $workloads = [ordered]@{
        Clean = 'compat_clean'
        IdeNoAttach = 'ide'
        ThreadCycleProfiling = 'compat_profile'
        OwnedAccessibility = 'compat_accessibility'
        OwnedWindowCapture = 'compat_capture'
        LayeredWindowApi = 'compat_overlay'
        LocalSeh = 'compat_seh'
        RepeatedCalls = 'compat_reentry'
        ParallelCalls = 'concurrent'
        CpuLoad = 'cpu_load'
        Aslr = 'compat_aslr'
        Acg = 'compat_acg'
    }
    foreach ($id in $workloads.Keys) {
        @{ Id = $id; Scenario = $workloads[$id]; Compatibility = $true; Args = @('--gated')
            Oracle = $Oracle; Attached = $false }
    }
}

function Get-CompatibilityStand {
    $defender = if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            @{
                mode = $status.AMRunningMode; service = $status.AMServiceEnabled
                antivirus = $status.AntivirusEnabled; realTime = $status.RealTimeProtectionEnabled
                engine = $status.AMEngineVersion; product = $status.AMProductVersion
                signatures = $status.AntivirusSignatureVersion
            }
        } catch { @{ reason = 'defender-state-query-unavailable' } }
    } else { @{ reason = 'defender-state-cmdlet-unavailable' } }
    $computer = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 10
    @{
        defender = $defender
        computer = @{ manufacturer = $computer.Manufacturer; model = $computer.Model; hypervisor = $computer.HypervisorPresent }
        exemptions = @()
        notRun = [ordered]@{
            DefenderActive = if ($defender.realTime) { 'no-dedicated-antivirus-activity-oracle' } else { 'real-time-protection-inactive-or-unverified' }
            CommercialEdr = 'no-qualified-product-and-owned-workload'
            GuestVm = 'no-isolated-guest-stand'
            SignedProductUpdate = 'no-isolated-signed-product-updater'
            ThirdPartyProfiler = 'no-isolated-external-profiler-session'
            ThirdPartyScreenCapture = 'no-owned-content-capture-adapter'
            CompositedOverlay = 'layered-window-api-only'
        }
    }
}

function Get-CompatibilityEvidence($Definition, [string] $Text, [string] $Oracle, $Mitigations) {
    $activity = [regex]::Match($Text, '(?m)^compatibility_activity=(\w+) output_checks=verified\r?$')
    $digest = [regex]::Match($Text, '(?m)^output_sha256=([0-9a-f]{64})\r?$')
    $identity = [regex]::Match($Oracle, '(?m)^compatibility_pid=(\d+) creation=([0-9a-f]{16})\r?$')
    $metrics = [regex]::Match($Text, '(?m)^profile_cycles=(\d+) profile_ns=(\d+)\r?$')
    $aslr = $Text -match '(?m)^aslr_dynamic_base=true aslr_displaced=true\r?$'
    $flags = @{}
    foreach ($entry in $Mitigations) {
        if ($entry.result -match '^flags=0x([0-9a-f]{8})$') {
            $flags[$entry.name] = [Convert]::ToUInt32($Matches[1], 16)
        }
    }
    $acg = ($flags.compat_ready_acg -band 1) -ne 0
    $acgExact = $flags.ContainsKey('compat_ready_acg') -and
        ($acg -eq ($Definition.Scenario -eq 'compat_acg')) -and ($flags.compat_ready_acg -band 2) -eq 0
    $scenario = switch ($Definition.Scenario) {
        'compat_profile' { $metrics.Success -and [long]$metrics.Groups[1].Value -gt 0 -and [long]$metrics.Groups[2].Value -gt 0 }
        'compat_aslr' { $aslr }
        default { $true }
    }
    $reference = 'f56198d1ef14d5c0527ea8d47b82a00aca18ff760bbb0f4cfeb98e37ac52d129'
    @{
        verified = ($activity.Groups[1].Value -ceq $Definition.Scenario -and
            $digest.Groups[1].Value -ceq $reference -and $identity.Success -and $scenario -and
            ($flags.cfg -band 1) -eq 1 -and ($flags.shadow_stack -band 1) -eq 1 -and $acgExact)
        workload = $activity.Groups[1].Value; outputSha256 = $digest.Groups[1].Value
        pid = $identity.Groups[1].Value; creationFiletime = $identity.Groups[2].Value
        cfg = ($flags.cfg -band 1) -ne 0; cetShadowStack = ($flags.shadow_stack -band 1) -ne 0
        acg = $acg; aslrDisplaced = $aslr
        profileCycles = $metrics.Groups[1].Value; profileNs = $metrics.Groups[2].Value
    }
}

function Get-CompatibilityClock {
    $clock = [Vmkek.Lab.CompatibilityClock]::Read()
    @{
        activeMs = [long]($clock[0] / 10000)
        elapsedMs = [long]($clock[1] / 10000)
        utcMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    }
}

function Assert-CompatibilityContinuity($First, $Previous, $Current) {
    $active = $Current.activeMs - $Previous.activeMs
    $elapsed = $Current.elapsedMs - $Previous.elapsedMs
    $wall = $Current.utcMs - $Previous.utcMs
    if ($active -lt 0 -or $elapsed -lt 0 -or $wall -lt 0 -or
        $elapsed -gt 95000 -or [Math]::Abs($elapsed - $active) -gt 2000 -or
        [Math]::Abs($elapsed - $wall) -gt 2000 -or
        [Math]::Abs(($Current.elapsedMs - $First.elapsedMs) - ($Current.activeMs - $First.activeMs)) -gt 15000 -or
        [Math]::Abs(($Current.elapsedMs - $First.elapsedMs) - ($Current.utcMs - $First.utcMs)) -gt 15000) {
        throw "Compatibility continuity lost (active=$active elapsed=$elapsed wall=$wall milliseconds)"
    }
}

function Invoke-CompatibilitySoak($Definitions) {
    Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
namespace Vmkek.Lab {
    public static class CompatibilityClock {
        [DllImport("api-ms-win-core-realtime-l1-1-0.dll")] static extern void QueryInterruptTimePrecise(out ulong time);
        [DllImport("api-ms-win-core-realtime-l1-1-0.dll")] static extern void QueryUnbiasedInterruptTimePrecise(out ulong time);
        [DllImport("kernel32.dll")] static extern uint SetThreadExecutionState(uint flags);
        [DllImport("kernel32.dll")] static extern bool GetSystemPowerStatus(out PowerStatus status);
        [StructLayout(LayoutKind.Sequential)]
        struct PowerStatus {
            public byte Ac;
            public byte Battery;
            public byte Charge;
            public byte Saver;
            public uint Remaining;
            public uint FullLife;
        }
        public static bool OnAcPower() {
            return GetSystemPowerStatus(out PowerStatus status) && status.Ac == 1 && status.Saver == 0;
        }
        public static bool PreventIdleSleep() { return SetThreadExecutionState(0x80000001) != 0; }
        public static bool ClearIdleSleepRequest() { return SetThreadExecutionState(0x80000000) != 0; }
        public static ulong[] Read() {
            QueryUnbiasedInterruptTimePrecise(out ulong active);
            QueryInterruptTimePrecise(out ulong elapsed);
            return new[] { active, elapsed };
        }
    }
}
"@
    if ($manifest.host.build -ne '10.0.26300.9974') { throw 'Soak is scoped to the pinned Windows build' }
    $lockPath = Join-Path (Split-Path -Parent $run) 'a08-soak.lock'
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $events = $null
    $power = $false
    try {
        if (![Vmkek.Lab.CompatibilityClock]::OnAcPower()) { throw 'AC power is required for the compatibility soak' }
        $power = [Vmkek.Lab.CompatibilityClock]::PreventIdleSleep()
        if (!$power) { throw 'Could not make the runner-scoped system power request' }
        $start = Get-CompatibilityClock
        $previous = $start
        $launches = 0
        $maxGapMs = 0
        $intervalMs = 55000
        $durationMs = 86400000
        $counts = [ordered]@{}
        $pinned = @{ host = $manifest.host; tools = $manifest.tools; sourceSha256 = $manifest.sourceSha256
            binaries = $manifest.binaries; stand = $manifest.compatibility; first = $start
            durationMs = $durationMs; intervalMs = $intervalMs; maximumGapMs = 95000; status = 'running'; acPower = $true; idleSleepRequest = 'thread-system-required' }
        $pinned | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $run 'soak-start.json')
        $events = [IO.StreamWriter]::new((Join-Path $run 'soak-events.jsonl'), $false)
        $events.AutoFlush = $true
        $processKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $profiles = @('observe', 'enforce')
        $observeDigest = $null
        do {
            $definition = $Definitions[[int][Math]::Floor($launches / 2) % $Definitions.Count]
            $Profile = $profiles[$launches % 2]
            $key = "$($definition.Id)/$Profile"
            if ($definition.Scenario -eq 'ide' -and $Profile -eq 'observe') {
                $ideDirectory = (New-Item -ItemType Directory -Path (Join-Path $buildDir.FullName "ide-$launches")).FullName
                $script:labIde = Start-LabIde $ideDirectory $IdeExecutable
                $observedIde = Get-IdeEvidence
                if (!$observedIde.verified) { throw 'Soak requires the isolated IDE' }
                if ($manifest.ide -and $observedIde.sha256 -cne $manifest.ide.sha256) {
                    throw 'IDE executable changed during soak'
                }
                $manifest.ide = $observedIde
            }
            $row = Invoke-LabCase $definition ($launches + 1)
            if ($definition.Scenario -eq 'ide' -and $Profile -eq 'enforce') {
                Stop-LabIde
                if ($manifest.cleanupError) { throw 'Soak IDE cleanup failed' }
            }
            $now = Get-CompatibilityClock
            $events.WriteLine((@{ row = $row; clock = $now } | ConvertTo-Json -Depth 12 -Compress))
            Assert-CompatibilityContinuity $start $previous $now
            if (![Vmkek.Lab.CompatibilityClock]::OnAcPower()) { throw 'AC power lost during soak' }
            if ($row.status -ne 'verified') { throw "Soak fixture $key failed ($($row.reason))" }
            if ($Profile -eq 'observe') { $observeDigest = $row.compatibility.outputSha256 }
            elseif ($observeDigest -cne $row.compatibility.outputSha256) { throw 'Observe/enforce output mismatch' }
            $identity = "$($row.compatibility.pid)/$($row.compatibility.creationFiletime)"
            if (!$processKeys.Add($identity)) { throw 'Duplicate owned process identity' }
            $counts[$key] = 1 + $counts[$key]
            $maxGapMs = [Math]::Max($maxGapMs, $now.elapsedMs - $previous.elapsedMs)
            $previous = $now
            $launches++
            $elapsed = $now.elapsedMs - $start.elapsedMs
            $finished = $elapsed -ge $durationMs -and ($now.activeMs - $start.activeMs) -ge $durationMs -and
                ($now.utcMs - $start.utcMs) -ge $durationMs
            if (!$finished) {
                if ($launches -ge 1600) { throw 'Soak iteration bound reached' }
                $wait = ($launches * $intervalMs) - $elapsed
                if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
            }
        } until ($finished)
        if ($launches -lt 1000 -or $counts.Count -ne ($Definitions.Count * 2) -or
            @($counts.Values | Where-Object { $_ -lt 30 }).Count) { throw 'Soak launch coverage insufficient' }
        $finalBinaries = @{}
        foreach ($path in $fixture, $observer, $compatibilityDll) {
            $name = Split-Path -Leaf $path
            $hash = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
            if ($hash -cne $manifest.binaries[$name]) { throw "Soak binary changed: $name" }
            $finalBinaries[$name] = $hash
        }
        @{ status = 'verified'; first = $start; last = $previous; launches = $launches; finalBinaries = $finalBinaries
            maxGapMs = $maxGapMs; counts = $counts; events = 'soak-events.jsonl' }
    } finally {
        if ($events) { $events.Dispose() }
        Stop-LabIde
        if ($power -and ![Vmkek.Lab.CompatibilityClock]::ClearIdleSleepRequest()) {
            $manifest.cleanupError = 'runner-power-request-clear-failed'
        }
        $lock.Dispose()
    }
}
