[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) 'vmkek-r07-abi'),
    [string]$VcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$null = New-Item -ItemType Directory -Force -Path $BuildDirectory
$build = (Resolve-Path $BuildDirectory).Path
$binary = Join-Path $build 'x86_64-pc-windows-msvc\release'
$vars = @{
    VMK_R07_SOURCE = $source
    VMK_R07_VCVARS = (Resolve-Path $VcVars).Path
    VMK_R07_BINARY = $binary
    CARGO_TARGET_DIR = $build
}
$previous = @{}
foreach ($key in $vars.Keys) {
    $previous[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
    [Environment]::SetEnvironmentVariable($key, $vars[$key], 'Process')
}

try {
    $commands = @(
        'call "%VMK_R07_VCVARS%"',
        'pushd "%VMK_R07_SOURCE%"',
        'cargo build --locked --release -p vmkek-runtime --target x86_64-pc-windows-msvc',
        'cargo run --locked --release -p vmkek-runtime --target x86_64-pc-windows-msvc --example r07_fixture -- "%VMK_R07_BINARY%"',
        'cl /nologo /W4 /WX /std:c11 /I include /c tests\windows\r07_abi.c /Fo"%VMK_R07_BINARY%\r07_abi.obj"',
        'link /nologo /OUT:"%VMK_R07_BINARY%\r07_abi.exe" "%VMK_R07_BINARY%\r07_abi.obj" "%VMK_R07_BINARY%\vmkek_runtime.dll.lib" bcrypt.lib'
    )
    & cmd.exe /d /c ($commands -join ' && ')
    if ($LASTEXITCODE -ne 0) {
        throw "R07 MSVC build failed with exit code $LASTEXITCODE"
    }

    $exports = & cmd.exe /d /c 'call "%VMK_R07_VCVARS%" && dumpbin /exports "%VMK_R07_BINARY%\vmkek_runtime.dll"'
    if ($LASTEXITCODE -ne 0) {
        throw "R07 dumpbin failed with exit code $LASTEXITCODE"
    }
    $expected = @('vmk_cancel', 'vmk_initialize', 'vmk_invoke', 'vmk_shutdown')
    $actual = @($exports | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\w+)(?:\s+=\s+\w+)?\s*$') { $Matches[1] }
    } | Sort-Object)
    if (($actual -join ',') -ne ($expected -join ',')) {
        throw "Unexpected DLL exports $($actual -join ', ')"
    }
    Write-Output "DLL exports $($actual -join ', ')"

    $module = Join-Path $binary 'r07_module.bin'
    $stack = Join-Path $binary 'r07_stack.bin'
    $register = Join-Path $binary 'r07_register.bin'
    $mixed = Join-Path $binary 'r07_mixed.bin'
    $program = Join-Path $binary 'r07_abi.exe'
    & $program $module $stack $register $mixed
    if ($LASTEXITCODE -ne 0) {
        throw "R07 ABI sample failed with exit code $LASTEXITCODE"
    }
    Get-FileHash (Join-Path $binary 'vmkek_runtime.dll'),$program
} finally {
    foreach ($key in $vars.Keys) {
        [Environment]::SetEnvironmentVariable($key, $previous[$key], 'Process')
    }
}
