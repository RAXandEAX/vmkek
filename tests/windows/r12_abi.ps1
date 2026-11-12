[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RuntimeDll,
    [string]$BuildDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) 'vmkek-r12-native-abi'),
    [string]$Config,
    [string]$BadTrustConfig,
    [switch]$LiveTimeout,
    [switch]$LiveCancellation,
    [switch]$SingleContext,
    [string]$VcVars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dll = (Resolve-Path $RuntimeDll).Path
$BuildDirectory = Join-Path $BuildDirectory ([Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Force -Path $BuildDirectory
$work = (Resolve-Path $BuildDirectory).Path
$exe = Join-Path $work 'r12_abi.exe'
$curve = [Security.Cryptography.ECCurve+NamedCurves]::nistP256
$signer = [Security.Cryptography.ECDsa]::Create($curve)
$other = [Security.Cryptography.ECDsa]::Create($curve)

function New-Install([string]$Name, [bool]$CopyImage) {
    $path = Join-Path $work $Name
    $null = New-Item -ItemType Directory -Force -Path $path
    if ($CopyImage) {
        Copy-Item -LiteralPath $dll -Destination (Join-Path $path 'vmkek_runtime.dll') -Force
    }
    return $path
}

function Write-Signature([string]$Directory, [Security.Cryptography.ECDsa]$Key, [uint32]$Maximum = 2) {
    $file = Join-Path $Directory 'vmkek_runtime.dll'
    $digest = [Convert]::FromHexString((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash)
    $metadata = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($metadata)
    try {
        $writer.Write([byte[]](86,77,75,68,76,76,49,0))
        $writer.Write([uint16]1)
        $writer.Write([uint16]0x8664)
        $writer.Write([uint32]1)
        $writer.Write($Maximum)
        $writer.Write([uint64](Get-Item -LiteralPath $file).Length)
        $writer.Write($digest)
        $record = $metadata.ToArray()
    } finally {
        $writer.Dispose()
    }
    $domain = [Text.Encoding]::ASCII.GetBytes('vmkek.runtime.v1.windows-dll-signature')
    $message = [byte[]]($domain + [byte]0 + $record)
    $signature = $Key.SignData($message, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    if ($record.Length -ne 60 -or $signature.Length -ne 64) {
        throw 'Unexpected DLL signature fixture format'
    }
    [IO.File]::WriteAllBytes("$file.sig", [byte[]]($record + $signature))
}

function Invoke-Case([string]$Name, [object[]]$Arguments) {
    & $exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "R12 case '$Name' failed with exit code $LASTEXITCODE"
    }
    Write-Output "r12 case $Name passed"
}

function Write-TimeoutConfig([string]$Original, [string]$Destination, [int]$Port) {
    $bytes = [IO.File]::ReadAllBytes($Original)
    $copy = $null
    try {
        # R12 owned fixture format places its first variable field here.
        $offset = 338
        if ($bytes.Length -lt $offset + 4 -or [Text.Encoding]::ASCII.GetString($bytes, 0, 6) -ne 'VMKR12') {
            throw 'Unexpected R12 fixture configuration'
        }
        $oldSize = [BitConverter]::ToUInt32($bytes, $offset)
        $tail = $offset + 4 + $oldSize
        if ($oldSize -eq 0 -or $oldSize -gt 64 -or $tail -ge $bytes.Length) {
            throw 'Invalid fixture endpoint field'
        }
        $endpoint = [Text.Encoding]::ASCII.GetBytes("127.0.0.1:$Port")
        $copy = [byte[]]::new($bytes.Length - $oldSize + $endpoint.Length)
        [Array]::Copy($bytes, $copy, $offset)
        [Array]::Copy([BitConverter]::GetBytes([uint32]$endpoint.Length), 0, $copy, $offset, 4)
        [Array]::Copy($endpoint, 0, $copy, $offset + 4, $endpoint.Length)
        [Array]::Copy($bytes, $tail, $copy, $offset + 4 + $endpoint.Length, $bytes.Length - $tail)
        [IO.File]::WriteAllBytes($Destination, $copy)
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        if ($copy) { [Array]::Clear($copy, 0, $copy.Length) }
    }
}

try {
    $point = $signer.ExportParameters($false).Q
    $pin = [byte[]](@(4) + $point.X + $point.Y)
    $pinText = ($pin | ForEach-Object { '0x{0:x2}' -f $_ }) -join ', '
    [IO.File]::WriteAllText((Join-Path $work 'r12_test_pin.h'), "static const unsigned char r12_vendor_pin[65] = {$pinText};")
    $env:VMK_R12_SOURCE = $source
    $env:VMK_R12_WORK = $work
    $env:VMK_R12_VCVARS = (Resolve-Path $VcVars).Path
    $commands = @(
        'call "%VMK_R12_VCVARS%"',
        'pushd "%VMK_R12_WORK%"',
        'cl /nologo /W4 /WX /std:c11 /guard:cf /I "%VMK_R12_SOURCE%\include" /I "%VMK_R12_SOURCE%\crates\runtime\windows" /I "%VMK_R12_WORK%" /c "%VMK_R12_SOURCE%\tests\windows\r12_abi.c" /For12_abi.obj',
        'cl /nologo /W4 /WX /std:c11 /guard:cf /I "%VMK_R12_SOURCE%\include" /c "%VMK_R12_SOURCE%\crates\runtime\windows\bootstrap.c" /For12_bootstrap.obj',
        'link /nologo /guard:cf /CETCOMPAT /DYNAMICBASE /NXCOMPAT /OUT:r12_abi.exe r12_abi.obj r12_bootstrap.obj bcrypt.lib'
    )
    & cmd.exe /d /c ($commands -join ' && ')
    if ($LASTEXITCODE -ne 0) {
        throw "R12 C build failed with exit code $LASTEXITCODE"
    }

    $valid = New-Install 'valid' $true
    Write-Signature $valid $signer
    $unsigned = New-Install 'unsigned' $true
    $missing = New-Install 'missing' $false
    $wrongVendor = New-Install 'wrong-vendor' $true
    Write-Signature $wrongVendor $other
    $version = New-Install 'incompatible' $true
    Write-Signature $version $signer 1
    $damaged = New-Install 'damaged' $true
    Write-Signature $damaged $signer
    $image = Join-Path $damaged 'vmkek_runtime.dll'
    $bytes = [IO.File]::ReadAllBytes($image)
    $bytes[-1] = $bytes[-1] -bxor 1
    [IO.File]::WriteAllBytes($image, $bytes)
    $machine = New-Install 'machine' $true
    $image = Join-Path $machine 'vmkek_runtime.dll'
    $bytes = [IO.File]::ReadAllBytes($image)
    $pe = [BitConverter]::ToInt32($bytes, 60)
    $bytes[$pe + 4] = 0x4c
    $bytes[$pe + 5] = 1
    [IO.File]::WriteAllBytes($image, $bytes)
    Write-Signature $machine $signer
    $reparse = Join-Path $work 'junction'
    $null = New-Item -ItemType Junction -Path $reparse -Target $work

    Invoke-Case 'signed' @('load', $valid, '0')
    Invoke-Case 'missing' @('load', $missing, '1')
    Invoke-Case 'unsigned' @('load', $unsigned, '1')
    Invoke-Case 'wrong-vendor' @('load', $wrongVendor, '6')
    Invoke-Case 'tampered-image' @('load', $damaged, '6')
    Invoke-Case 'signed-wrong-pe-machine' @('load', $machine, '6')
    Invoke-Case 'unsupported-version' @('load', $version, '5')
    Invoke-Case 'relative-directory' @('load', 'valid', '10')
    Invoke-Case 'intermediate-reparse' @('load', (Join-Path $reparse 'valid'), '1')
    Invoke-Case 'preloaded-other-path' @('preloaded', $valid, '3', (Join-Path $unsigned 'vmkek_runtime.dll'))
    $marker = "$exe.local"
    [IO.File]::WriteAllBytes($marker, [byte[]]@())
    try {
        Invoke-Case 'inert-executable-redirection-marker' @('load', $valid, '3')
    } finally {
        Remove-Item -LiteralPath $marker
    }
    Push-Location -LiteralPath $unsigned
    try {
        Invoke-Case 'cwd-unsigned-decoy' @('load', $valid, '0')
    } finally {
        Pop-Location
    }
    if ($Config) {
        $configPath = (Resolve-Path $Config).Path
        if ($SingleContext) {
            Invoke-Case 'online-v2-single-context' @('quota-one', $valid, $configPath)
        } elseif ($LiveCancellation) {
            Invoke-Case 'online-v2-threads-cancel' @('cancel', $valid, $configPath)
        } else {
            Invoke-Case 'online-v2-threads' @('online', $valid, $configPath, '0', '0')
        }
    }
    if ($BadTrustConfig) {
        Invoke-Case 'wrong-package-signer' @('online', $valid, (Resolve-Path $BadTrustConfig).Path, '6', '0')
    }
    if ($LiveTimeout) {
        if (!$Config) { throw '-LiveTimeout requires -Config' }
        $stall = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $timeoutPath = Join-Path $work 'timeout-config.bin'
        try {
            $stall.Start()
            Write-TimeoutConfig $configPath $timeoutPath $stall.LocalEndpoint.Port
            $watch = [Diagnostics.Stopwatch]::StartNew()
            Invoke-Case 'online-timeout' @('online', $valid, $timeoutPath, '1', '0')
            $watch.Stop()
            if ($watch.Elapsed.TotalSeconds -lt 4 -or $watch.Elapsed.TotalSeconds -gt 7) {
                throw "R12 timeout outside expected range ($($watch.Elapsed.TotalSeconds) s)"
            }
            Write-Output "r12 bounded TLS timeout ms=$($watch.ElapsedMilliseconds)"
        } finally {
            $stall.Stop()
            if (Test-Path -LiteralPath $timeoutPath) {
                Remove-Item -LiteralPath $timeoutPath
            }
        }
    }
    Write-Output "r12 artifacts $work"
    Get-FileHash -LiteralPath $dll, $exe
} finally {
    $signer.Dispose()
    $other.Dispose()
}
