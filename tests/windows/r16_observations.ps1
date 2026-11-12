#requires -Version 7.0
param(
    [Parameter(Mandatory)] [string] $Executable,
    [string] $WorkDir,
    [switch] $SampleTiming,
    [switch] $BenignFiles
)
$ErrorActionPreference = 'Stop'
$Executable = (Get-Item -LiteralPath $Executable).FullName
if (!$WorkDir) {
    $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ('vmkek-r16-' + [Guid]::NewGuid().ToString('N'))
}
$null = New-Item -ItemType Directory -Path $WorkDir -Force
$observer = Join-Path $WorkDir 'r16-debug-observer.exe'
$source = Join-Path $PSScriptRoot 't6_debug_observer.c'
$compiler = (Get-Command cl.exe).Source
$envKeys = @('VMKEK_R16_EXPECT_DEBUG', 'VMKEK_R16_SAMPLE_TIMING', 'VMKEK_R16_BENIGN_FILE',
             'VMKEK_R16_BENIGN_EXPECTED', 'VMKEK_T6_READY', 'VMKEK_T6_RELEASE', 'VMKEK_T6_DEBUG_EXPECTED')
$saved = @{}
foreach ($name in $envKeys) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
}

function Run-Checked([string] $Label, [string] $Program, [string[]] $Parameters = @()) {
    & $Program @Parameters
    if ($LASTEXITCODE -ne 0) { throw "$Label exit $LASTEXITCODE" }
    Write-Output "pass $Label"
}

Push-Location -LiteralPath $WorkDir
try {
    & $compiler /nologo /W4 /WX /guard:cf $source "/Fe:$observer" /link /CETCOMPAT
    if ($LASTEXITCODE -ne 0) { throw "Debugger observer compile failed" }
    Write-Output "fixture_sha256=$((Get-FileHash -LiteralPath $Executable).Hash)"
    Write-Output "debug_observer_sha256=$((Get-FileHash -LiteralPath $observer).Hash)"
    Run-Checked 'direct clean' $Executable
    $env:VMKEK_R16_EXPECT_DEBUG = '1'
    Run-Checked 'startup debugger attached' $observer @($Executable)
    Remove-Item Env:VMKEK_R16_EXPECT_DEBUG
    Run-Checked 'gated clean' $observer @($Executable, '--gated')
    Run-Checked 'debugger attached after entry' $observer @($Executable, '--attach-after-ready')

    if ($BenignFiles) {
        $system = Join-Path $env:windir 'System32'
        foreach ($name in @('wpr.exe', 'Narrator.exe', 'Magnify.exe')) {
            $file = Join-Path $system $name
            if (!(Test-Path -LiteralPath $file -PathType Leaf)) {
                Write-Output "not-run file corpus $name"
                continue
            }
            $version = (Get-Item -LiteralPath $file).VersionInfo.FileVersion
            $env:VMKEK_R16_BENIGN_FILE = $file
            $env:VMKEK_R16_BENIGN_EXPECTED = (Get-FileHash -LiteralPath $file).Hash
            Run-Checked "benign file $name version=$version" $Executable
        }
        Remove-Item Env:VMKEK_R16_BENIGN_FILE,Env:VMKEK_R16_BENIGN_EXPECTED -ErrorAction SilentlyContinue
    }
    if ($SampleTiming) {
        $env:VMKEK_R16_SAMPLE_TIMING = '1'
        Run-Checked 'timing baseline' $Executable
        $workers = [Math]::Min(8, [Environment]::ProcessorCount)
        $jobs = @(1..$workers | ForEach-Object {
            Start-ThreadJob -ThrottleLimit $workers -ScriptBlock {
                $timer = [Diagnostics.Stopwatch]::StartNew()
                while ($timer.Elapsed.TotalSeconds -lt 5) { [Threading.Thread]::SpinWait(20000) }
            }
        })
        try {
            Start-Sleep -Milliseconds 300
            Write-Output "load_workers=$workers"
            Run-Checked 'timing with CPU load' $Executable
        } finally {
            $jobs | Wait-Job | Remove-Job
        }
    }
} finally {
    foreach ($name in $envKeys) {
        if ($null -eq $saved[$name]) {
            Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
        }
    }
    Pop-Location
}
