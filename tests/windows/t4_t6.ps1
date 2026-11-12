[CmdletBinding(DefaultParameterSetName = 'Windows')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Windows')]
    [string] $Protector,

    [Parameter(Mandatory, ParameterSetName = 'Wsl')]
    [string] $WslProtector,

    [Parameter(ParameterSetName = 'Wsl')]
    [string] $WslDistribution = 'Ubuntu',

    [ValidateSet('T4', 'T5', 'T5-Reentry', 'T5-CFG', 'T6')]
    [string[]] $Stage
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $Stage) { $Stage = @('T4', 'T5', 'T5-Reentry', 'T5-CFG', 'T6') }
$useWsl = $PSCmdlet.ParameterSetName -eq 'Wsl'
if (-not $useWsl) {
    $Protector = (Resolve-Path -LiteralPath $Protector).Path
}
$compiler = (Get-Command cl.exe -ErrorAction Stop).Source
$lab = Join-Path ([System.IO.Path]::GetTempPath()) ('vmkek-windows-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $lab | Out-Null
Write-Host "Lab files: $lab"
foreach ($file in @('t4_seh.c', 't5_threads.c', 't5_cfg.c', 't5_acg_probe.c', 't6_attach.c', 't6_debug_observer.c', 't6_global.c')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $lab
}
if ($useWsl) {
    $wslLab = wsl.exe -d $WslDistribution --exec wslpath -a $lab
    if ($LASTEXITCODE -ne 0) { throw 'Unable to resolve the lab directory from WSL' }
}

function Build-Fixture([string] $Source, [string] $Output, [string[]] $LinkFlags, [switch] $Leaf, [string[]] $CompileFlags = @()) {
    if ($Leaf) { $CompileFlags += '/DVMKEK_LEAF_ONLY' }
    & $compiler /nologo /W4 /WX /O1 /GS- /Zl @CompileFlags $Source "/Fe:$Output.exe" /link /nodefaultlib /entry:fixture_entry /subsystem:console /incremental:no /fixed /dynamicbase:no /highentropyva:no /guard:no kernel32.lib @LinkFlags
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed for $Output.exe" }
}

function Protect-Fixture([string] $Name, [string] $Export) {
    $options = @('--virtualize', $Export, '--seed', '7', '--windows-native')
    if ($useWsl) {
        wsl.exe -d $WslDistribution --exec $WslProtector protect "$wslLab/$Name.exe" -o "$wslLab/$Name-protected.exe" @options
    }
    else {
        $source = Join-Path $lab "$Name.exe"
        $output = Join-Path $lab "$Name-protected.exe"
        & $Protector protect $source -o $output @options
    }
    if ($LASTEXITCODE -ne 0) { throw "Protection failed for $Name.exe" }
}

function Invoke-LocalFixture([string] $Name) {
    $process = Start-Process -FilePath (Join-Path $lab "$Name.exe") -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            throw "$Name.exe timed out"
        }
        return $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
}

function Assert-FixtureStatus([string] $Name, [int] $Observed, [int] $Expected) {
    Write-Host ('{0} exit=0x{1:x8}' -f $Name, $Observed)
    if ($Observed -ne $Expected) {
        throw ('{0} expected exit 0x{1:x8}' -f $Name, $Expected)
    }
}

function Build-Seh {
    Set-Content -LiteralPath 'seh-ntdll.def' -Encoding ascii -Value @(
        'LIBRARY ntdll.dll', 'EXPORTS', '    __C_specific_handler'
    )
    $librarian = Join-Path (Split-Path -Parent $compiler) 'lib.exe'
    & $librarian /nologo /machine:x64 /def:seh-ntdll.def /out:seh-ntdll.lib
    if ($LASTEXITCODE -ne 0) { throw 'SEH handler import library creation failed' }
    Build-Fixture 't4_seh.c' 'seh' @('/cetcompat:no', 'seh-ntdll.lib')
}

function Test-Seh {
    Build-Seh
    Assert-FixtureStatus 'Clean original SEH' (Invoke-LocalFixture 'seh') 17
    Copy-Item -LiteralPath 'seh.exe' -Destination 'seh-leaf.exe'
    Protect-Fixture 'seh-leaf' 'fixture_unrelated_leaf'
    Assert-FixtureStatus 'Original SEH with unrelated leaf protected' (Invoke-LocalFixture 'seh-leaf-protected') 17
    Protect-Fixture 'seh' 'fixture_target'
    Assert-FixtureStatus 'Clean protected SEH' (Invoke-LocalFixture 'seh-protected') 17
}

function Test-Reentry {
    Build-Fixture 't5_threads.c' 'reentry' @('/cetcompat:no')
    Assert-FixtureStatus 'Clean original reentry' (Invoke-LocalFixture 'reentry') 17
    Protect-Fixture 'reentry' 'fixture_thread_target'
    Assert-FixtureStatus 'Clean protected reentry' (Invoke-LocalFixture 'reentry-protected') 17
}

function Test-Debug {
    $name = 'debug-leaf'
    Build-Fixture 't5_threads.c' $name @('/cetcompat:no') -Leaf
    Assert-FixtureStatus 'Clean original fixture' (Invoke-LocalFixture $name) 17
    Protect-Fixture $name 'fixture_thread_leaf'
    Assert-FixtureStatus 'Clean protected leaf' (Invoke-LocalFixture "$name-protected") 17
    & $compiler /nologo /W4 /WX t6_debug_observer.c /Fe:observe.exe
    if ($LASTEXITCODE -ne 0) { throw 'Debug observer compilation failed' }
    $observer = Join-Path $lab 'observe.exe'
    & $observer (Join-Path $lab "$name.exe")
    Assert-FixtureStatus 'Debug original fixture' $LASTEXITCODE 17
    & $observer (Join-Path $lab "$name-protected.exe")
    Assert-FixtureStatus 'Debug protected fixture' $LASTEXITCODE 0xdeb6
    Test-LateAttach $observer
    Test-NtGlobalFlag
}

function Test-LateAttach([string] $Observer) {
    Build-Fixture 't6_attach.c' 'late-attach' @('/cetcompat:no')
    Protect-Fixture 'late-attach' 'fixture_attach_leaf'
    $original = Join-Path $lab 'late-attach.exe'
    $protected = Join-Path $lab 'late-attach-protected.exe'

    & $Observer $original --gated
    Assert-FixtureStatus 'Gated clean original' $LASTEXITCODE 17
    & $Observer $protected --gated
    Assert-FixtureStatus 'Gated clean protected' $LASTEXITCODE 17
    & $Observer $original --attach-after-ready
    Assert-FixtureStatus 'Late debugger original' $LASTEXITCODE 17
    & $Observer $protected --attach-after-ready
    Assert-FixtureStatus 'Late debugger protected' $LASTEXITCODE 0xbad1
}

function Test-NtGlobalFlag {
    $link = @('/cetcompat:no', '/include:_load_config_used')
    Build-Fixture 't6_global.c' 'flags-clear' $link -CompileFlags @('/std:c11')
    Build-Fixture 't6_global.c' 'flags-set' $link -CompileFlags @('/std:c11', '/DVMKEK_GLOBAL_FLAGS=0x10')
    Assert-FixtureStatus 'Global flag clear original, no debugger' (Invoke-LocalFixture 'flags-clear') 17
    Assert-FixtureStatus 'Global flag set original, no debugger' (Invoke-LocalFixture 'flags-set') 17
    Protect-Fixture 'flags-clear' 'fixture_global_leaf'
    Protect-Fixture 'flags-set' 'fixture_global_leaf'
    Assert-FixtureStatus 'Global flag clear protected, no debugger' (Invoke-LocalFixture 'flags-clear-protected') 17
    Assert-FixtureStatus 'Global flag set protected, no debugger' (Invoke-LocalFixture 'flags-set-protected') 0xdeb6
}

function Test-ThreadsAndPolicies {
    Build-Fixture 't5_threads.c' 'threads' @('/cetcompat:no') -Leaf
    Assert-FixtureStatus 'Clean original threads' (Invoke-LocalFixture 'threads') 17
    Protect-Fixture 'threads' 'fixture_thread_leaf'
    Assert-FixtureStatus 'Clean protected threads' (Invoke-LocalFixture 'threads-protected') 17

    & $compiler /nologo /W4 /WX t5_acg_probe.c /Fe:t5_acg_probe.exe
    if ($LASTEXITCODE -ne 0) { throw 'Mitigation probe compilation failed' }
    $probe = Join-Path $lab 't5_acg_probe.exe'
    $threads = Join-Path $lab 'threads-protected.exe'
    Write-Host 'Protected threads with ACG'
    & $probe $threads --run
    Assert-FixtureStatus 'ACG probe' $LASTEXITCODE 0
    Write-Host 'Protected threads with process CFG'
    & $probe $threads --cfg --run
    Assert-FixtureStatus 'CFG probe' $LASTEXITCODE 0

    Build-Fixture 't5_threads.c' 'threads-cet' @('/cetcompat') -Leaf
    Write-Host 'Original CET-compatible threads with CET'
    & $probe (Join-Path $lab 'threads-cet.exe') --cet --run
    if ($LASTEXITCODE -eq 3) {
        Write-Warning 'CET shadow stacks could not be verified on this host. CET live acceptance remains open.'
        return
    }
    Assert-FixtureStatus 'Original CET probe' $LASTEXITCODE 0
    Protect-Fixture 'threads-cet' 'fixture_thread_leaf'
    Write-Host 'Protected CET-compatible threads with CET'
    & $probe (Join-Path $lab 'threads-cet-protected.exe') --cet --run
    Assert-FixtureStatus 'Protected CET probe' $LASTEXITCODE 0
}

function Invoke-CfgFixture([string] $Name, [switch] $Negative) {
    $previous = [Environment]::GetEnvironmentVariable('VMKEK_T5_CFG_NEGATIVE')
    try {
        $flag = if ($Negative) { '1' } else { $null }
        [Environment]::SetEnvironmentVariable('VMKEK_T5_CFG_NEGATIVE', $flag)
        return Invoke-LocalFixture $Name
    }
    finally {
        [Environment]::SetEnvironmentVariable('VMKEK_T5_CFG_NEGATIVE', $previous)
    }
}

function Test-GuardedCfg {
    $common = @('/entry:fixture_entry', '/subsystem:console', '/incremental:no',
                '/base:0x140000000', '/guard:cf', '/cetcompat:no', 'kernel32.lib')
    & $compiler /nologo /W4 /WX /O2 /GS- /MD /guard:cf t5_cfg.c /Fe:cfg-fixed.exe /link @common /fixed /dynamicbase:no /highentropyva:no
    if ($LASTEXITCODE -ne 0) { throw 'Fixed CFG control compilation failed' }
    & $compiler /nologo /W4 /WX /O2 /GS- /MD /guard:cf /DVMKEK_REQUIRE_ASLR t5_cfg.c /Fe:cfg.exe /link @common /dynamicbase
    if ($LASTEXITCODE -ne 0) { throw 'Relocatable CFG fixture compilation failed' }

    Assert-FixtureStatus 'Fixed CFG valid call' (Invoke-CfgFixture 'cfg-fixed') 17
    Write-Host ('Fixed CFG negative control exit=0x{0:x8}' -f (Invoke-CfgFixture 'cfg-fixed' -Negative))
    Assert-FixtureStatus 'Original instrumented CFG valid call' (Invoke-CfgFixture 'cfg') 17
    Assert-FixtureStatus 'Original instrumented CFG rejects invalid target' (Invoke-CfgFixture 'cfg' -Negative) 0xc0000409
    Protect-Fixture 'cfg' 'fixture_cfg_target'
    Assert-FixtureStatus 'Protected instrumented CFG valid call' (Invoke-CfgFixture 'cfg-protected') 17
    Assert-FixtureStatus 'Protected instrumented CFG rejects invalid target' (Invoke-CfgFixture 'cfg-protected' -Negative) 0xc0000409
}

$checks = @{
    'T4' = { Test-Seh }
    'T5' = { Test-ThreadsAndPolicies }
    'T5-Reentry' = { Test-Reentry }
    'T5-CFG' = { Test-GuardedCfg }
    'T6' = { Test-Debug }
}
$failures = [System.Collections.Generic.List[string]]::new()
Push-Location -LiteralPath $lab
try {
    foreach ($item in $Stage) {
        try {
            & $checks[$item]
        }
        catch {
            $failures.Add("$item $($_.Exception.Message)")
        }
    }
}
finally {
    Pop-Location
}
if ($failures.Count -ne 0) {
    throw ($failures -join [Environment]::NewLine)
}
