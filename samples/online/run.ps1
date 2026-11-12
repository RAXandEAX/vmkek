#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClientExe,
    [Parameter(Mandatory)][string]$WslWorkspace,
    [Parameter(Mandatory)][string]$FixtureExe,
    [Parameter(Mandatory)][string]$PostgresHome,
    [string]$Distribution = 'Ubuntu'
)

$ErrorActionPreference = 'Stop'
$client = (Resolve-Path -LiteralPath $ClientExe).Path
if ($Distribution -notmatch '^[A-Za-z0-9_.-]+$' -or
    @($WslWorkspace, $FixtureExe, $PostgresHome).Where({ -not $_.StartsWith('/') }).Count) {
    throw 'Supply an installed WSL distribution name and absolute Unix paths.'
}
$work = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\vmkek-r18-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $work
$acl.SetAccessRuleProtection($true, $false)
$rule = [Security.AccessControl.FileSystemAccessRule]::new(
    $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
)
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $work -AclObject $acl
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$fixtureRoot = $null
$scenarioError = $null
$cleanupErrors = [System.Collections.Generic.List[string]]::new()

function Start-Owned([string]$Program, [string[]]$Arguments) {
    $start = [System.Diagnostics.ProcessStartInfo]::new($Program)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($start)
    $processes.Add($process)
    return $process
}

function Wait-Marker([string]$Path, [System.Diagnostics.Process]$Process) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($Process.HasExited -or $watch.Elapsed.TotalSeconds -ge 12) {
            throw "Expected marker '$([IO.Path]::GetFileName($Path))' was not published."
        }
        Start-Sleep -Milliseconds 25
    }
}

function Touch([string]$Directory, [string]$Name) {
    [IO.File]::WriteAllBytes((Join-Path $Directory $Name), [byte[]]@())
}

function Start-Client([string]$Configuration, [string]$Hold = '', [string]$InputName = 'input.bin') {
    $arguments = @($Configuration, (Join-Path $work 'receipt-pin.sec1'), (Join-Path $work $InputName))
    if ($Hold) { $arguments += @('--hold', $Hold) }
    $process = Start-Owned $client $arguments
    return @{
        Process = $process
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
    }
}

function Finish-Client($Child, [int]$ExitCode, [string]$ExpectedError = '') {
    if (-not $Child.Process.WaitForExit(12000)) { throw 'Windows client timed out.' }
    $stdout = $Child.Stdout.GetAwaiter().GetResult().Trim()
    $stderr = $Child.Stderr.GetAwaiter().GetResult().Trim()
    if ($Child.Process.ExitCode -ne $ExitCode -or $stderr -ne $ExpectedError -or
        ($ExitCode -ne 0 -and $stdout.Length -ne 0)) {
        throw "Unexpected Windows exit $($Child.Process.ExitCode), stdout='$stdout', stderr='$stderr'."
    }
    return $stdout
}

function Read-Summary([string]$Line) {
    $pattern = '^online-ok generation=([0-9a-f]{32}) bytes=([0-9]+) sha256=([0-9a-f]{64}) scalar=-17 receipt=63$'
    if ($Line -notmatch $pattern -or [int]$Matches[2] -ne $inputSize -or $Matches[3] -ne $inputDigest) {
        throw "Windows buffer or receipt oracle mismatch: '$Line'."
    }
    $entry = $catalog[$Matches[1]]
    if ($null -eq $entry) { throw 'The returned generation is absent from the published catalog.' }
    return @{ Generation = $Matches[1]; Form = $entry[1]; Descriptor = $entry[2]; Program = $entry[3] }
}

try {
    $fixture = Start-Owned 'wsl.exe' @('-d', $Distribution, '--', 'bash', "$WslWorkspace/samples/online/run-fixture.sh", $FixtureExe, $PostgresHome)
    $fixtureError = $fixture.StandardError.ReadToEndAsync()
    $linuxPath = $fixture.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(12)).GetAwaiter().GetResult()
    if ($linuxPath -notmatch '^/tmp/vmkek-r18-[A-Za-z0-9]+$') { throw 'Unexpected fixture directory.' }
    $fixtureRoot = "\\wsl.localhost\$Distribution" + $linuxPath.Replace('/', '\')
    try { Wait-Marker (Join-Path $fixtureRoot 'ready') $fixture }
    catch {
        if ($fixture.HasExited) { throw "Fixture startup failed: $($fixtureError.GetAwaiter().GetResult())" }
        throw
    }
    foreach ($name in @('config.bin', 'foreign.bin', 'receipt-pin.sec1', 'input.bin', 'catalog.tsv')) {
        Copy-Item -LiteralPath (Join-Path $fixtureRoot $name) -Destination (Join-Path $work $name)
    }
    $config = Join-Path $work 'config.bin'
    $input = Get-Item -LiteralPath (Join-Path $work 'input.bin')
    $inputSize = $input.Length
    $inputDigest = (Get-FileHash -LiteralPath $input.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $catalog = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $work 'catalog.tsv')) {
        $entry = $line -split "\t"
        if ($entry.Length -ne 4 -or $catalog.ContainsKey($entry[0])) { throw 'Invalid fixture catalog.' }
        $catalog[$entry[0]] = $entry
    }

    $oldControl = (New-Item -ItemType Directory -Path (Join-Path $work 'old')).FullName
    $old = Start-Client $config $oldControl
    Wait-Marker (Join-Path $oldControl 'admitted') $old.Process
    $first = Read-Summary (Get-Content -Raw -LiteralPath (Join-Path $oldControl 'admitted')).Trim()
    $second = Read-Summary (Finish-Client (Start-Client $config) 0)
    if ($first.Form -ne 'Stack' -or $second.Form -ne 'Register' -or
        $first.Generation -eq $second.Generation -or $first.Descriptor -eq $second.Descriptor -or
        $first.Program -eq $second.Program) { throw 'The two launches did not use distinct Stack/Register packages.' }
    Write-Output "r18 clean forms=$($first.Form)/$($second.Form) bytes=$inputSize sha256=$inputDigest scalar=-17 receipt=63"
    Write-Output "r18 descriptors $($first.Descriptor) $($second.Descriptor)"
    Touch $oldControl 'retry'
    $null = Finish-Client $old 1 'online-vm status=3'
    Write-Output 'r18 prior session and package key denied'

    [IO.File]::WriteAllBytes((Join-Path $work 'oversize.bin'), [byte[]]::new(4097))
    $null = Finish-Client (Start-Client $config '' 'oversize.bin') 1 'sample input exceeds its file or size constraint'
    Write-Output 'r18 oversize input rejected before initialization'

    $null = Finish-Client (Start-Client (Join-Path $work 'foreign.bin')) 1 'online-init status=3'
    Write-Output 'r18 foreign device proof denied'

    $revokedControl = (New-Item -ItemType Directory -Path (Join-Path $work 'revoked')).FullName
    $revoked = Start-Client $config $revokedControl
    Wait-Marker (Join-Path $revokedControl 'admitted') $revoked.Process
    $third = Read-Summary (Get-Content -Raw -LiteralPath (Join-Path $revokedControl 'admitted')).Trim()
    Touch $fixtureRoot 'revoke'
    Wait-Marker (Join-Path $fixtureRoot 'revoked') $fixture
    Touch $revokedControl 'retry'
    $null = Finish-Client $revoked 1 'online-vm status=3'
    $null = Finish-Client (Start-Client $config) 1 'online-init status=3'
    Write-Output 'r18 revoke denied running and fresh clients'

    Touch $fixtureRoot 'restore'
    Wait-Marker (Join-Path $fixtureRoot 'restored') $fixture
    $restored = Read-Summary (Finish-Client (Start-Client $config) 0)
    if ($restored.Generation -in @($first.Generation, $second.Generation, $third.Generation)) {
        throw 'Restore reused a retired generation.'
    }
    Write-Output "r18 restore opened fresh generation=$($restored.Generation) descriptor=$($restored.Descriptor)"

    Touch $fixtureRoot 'stop'
    if (-not $fixture.WaitForExit(12000)) { throw 'Fixture shutdown timed out.' }
    if ($fixture.ExitCode -ne 0) {
        throw "Fixture shutdown failed: $($fixtureError.GetAwaiter().GetResult())"
    }
    $null = Finish-Client (Start-Client $config) 1 'online-init status=1'
    Write-Output 'r18 no server denied startup without output'
    Write-Output "r18 artifact_sha256=$((Get-FileHash -LiteralPath $client -Algorithm SHA256).Hash.ToLowerInvariant())"
} catch {
    $scenarioError = $_
} finally {
    try {
        if ($fixtureRoot -and (Test-Path -LiteralPath $fixtureRoot -PathType Container)) {
            Touch $fixtureRoot 'stop'
        }
    } catch {
        $cleanupErrors.Add("Could not signal fixture shutdown: $($_.Exception.Message)")
    }

    foreach ($process in $processes) {
        try {
            if (-not $process.HasExited -and -not $process.WaitForExit(12000)) {
                try {
                    $process.Kill()
                } catch {
                    if (-not $process.HasExited) { throw }
                }
                if (-not $process.WaitForExit(5000)) {
                    throw 'Owned child did not exit after termination.'
                }
            }
        } catch {
            $cleanupErrors.Add("Could not stop an owned child: $($_.Exception.Message)")
        }
        try {
            $process.Dispose()
        } catch {
            $cleanupErrors.Add("Could not dispose an owned child handle: $($_.Exception.Message)")
        }
    }

    foreach ($name in @('config.bin', 'foreign.bin')) {
        try {
            $path = Join-Path $work $name
            if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path }
        } catch {
            $cleanupErrors.Add("Could not remove '$name': $($_.Exception.Message)")
        }
    }
}

foreach ($cleanupError in $cleanupErrors) {
    Write-Warning "R18 cleanup: $cleanupError" -WarningAction Continue
}
if ($null -ne $scenarioError) {
    $PSCmdlet.ThrowTerminatingError($scenarioError)
}
if ($cleanupErrors.Count) {
    throw "R18 cleanup failed ($($cleanupErrors.Count) errors)."
}
