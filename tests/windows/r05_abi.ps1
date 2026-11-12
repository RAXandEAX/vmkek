[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) 'vmkek-r05-abi'),
    [string]$VcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$null = New-Item -ItemType Directory -Force -Path $BuildDirectory
$build = (Resolve-Path $BuildDirectory).Path
$binary = Join-Path $build 'x86_64-pc-windows-msvc\release'
$vars = @{
    VMK_R05_SOURCE = $source
    VMK_R05_VCVARS = (Resolve-Path $VcVars).Path
    VMK_R05_BINARY = $binary
    CARGO_TARGET_DIR = $build
}
$previous = @{}
foreach ($key in $vars.Keys) {
    $previous[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
    [Environment]::SetEnvironmentVariable($key, $vars[$key], 'Process')
}

try {
    $commands = @(
        'call "%VMK_R05_VCVARS%"',
        'pushd "%VMK_R05_SOURCE%"',
        'cargo build --locked --release -p vmkek-runtime --target x86_64-pc-windows-msvc',
        'cargo run --locked --release -p vmkek-runtime --target x86_64-pc-windows-msvc --example r05_fixture -- "%VMK_R05_BINARY%"',
        'cl /nologo /W4 /WX /std:c11 /I include /c tests\windows\r05_abi.c /Fo"%VMK_R05_BINARY%\r05_c.obj"',
        'cl /nologo /W4 /WX /TP /std:c++17 /I include /c tests\windows\r05_abi.c /Fo"%VMK_R05_BINARY%\r05_cpp.obj"',
        'link /nologo /OUT:"%VMK_R05_BINARY%\r05_c.exe" "%VMK_R05_BINARY%\r05_c.obj" "%VMK_R05_BINARY%\vmkek_runtime.dll.lib" bcrypt.lib',
        'link /nologo /OUT:"%VMK_R05_BINARY%\r05_cpp.exe" "%VMK_R05_BINARY%\r05_cpp.obj" "%VMK_R05_BINARY%\vmkek_runtime.dll.lib" bcrypt.lib'
    )
    & cmd.exe /d /c ($commands -join ' && ')
    if ($LASTEXITCODE -ne 0) {
        throw "R05 MSVC build failed with exit code $LASTEXITCODE"
    }

    $exports = & cmd.exe /d /c 'call "%VMK_R05_VCVARS%" && dumpbin /exports "%VMK_R05_BINARY%\vmkek_runtime.dll"'
    if ($LASTEXITCODE -ne 0) {
        throw "R05 dumpbin failed with exit code $LASTEXITCODE"
    }
    $expected = @('vmk_cancel', 'vmk_initialize', 'vmk_invoke', 'vmk_shutdown')
    $actual = @($exports | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\w+)(?:\s+=\s+\w+)?\s*$') { $Matches[1] }
    } | Sort-Object)
    if (($actual -join ',') -ne ($expected -join ',')) {
        throw "Unexpected DLL exports $($actual -join ', ')"
    }
    Write-Output "DLL exports $($actual -join ', ')"

    $descriptor = Join-Path $binary 'r05_descriptor.bin'
    $program = Join-Path $binary 'r05_program.bin'
    foreach ($name in @('r05_c.exe', 'r05_cpp.exe')) {
        & (Join-Path $binary $name) $descriptor $program
        if ($LASTEXITCODE -ne 0) {
            throw "$name failed with exit code $LASTEXITCODE"
        }
    }
    Get-FileHash (Join-Path $binary 'vmkek_runtime.dll')
} finally {
    foreach ($key in $vars.Keys) {
        [Environment]::SetEnvironmentVariable($key, $previous[$key], 'Process')
    }
}
