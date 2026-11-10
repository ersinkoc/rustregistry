[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][string]$Checksums,
    [Parameter(Mandatory)][ValidatePattern('^0\.\d+\.\d+$')][string]$Version,
    [switch]$Launch
)

$ErrorActionPreference = 'Stop'
$zip = Get-Item -LiteralPath $Archive
$archiveName = "RustRegistry-$Version-windows-x64.zip"
if ($zip.Name -cne $archiveName) { throw "Expected $archiveName." }
$expected = @{}
foreach ($line in Get-Content -LiteralPath $Checksums) {
    if ($line -cnotmatch '^([a-f0-9]{64})  ([A-Za-z0-9.-]+)$' -or $expected.ContainsKey($Matches[2])) {
        throw 'Invalid or duplicate SHA-256 entry.'
    }
    $expected[$Matches[2]] = $Matches[1]
}
if ($expected.Count -ne 2 -or -not $expected.ContainsKey($archiveName) -or
    -not $expected.ContainsKey('rustregistry.exe')) {
    throw 'Expected one checksum each for the ZIP and executable.'
}
if ((Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash -ne $expected[$archiveName]) {
    throw 'ZIP checksum mismatch.'
}

$folder = [IO.Directory]::CreateTempSubdirectory('RustRegistry-verify-').FullName
try {
    $bundle = [IO.Compression.ZipFile]::OpenRead($zip.FullName)
    try {
        $entries = @($bundle.Entries | ForEach-Object FullName)
        $required = @('LICENSE', 'README.txt', 'rustregistry.exe', 'THIRD-PARTY-NOTICES.txt')
        if ($entries.Count -ne $required.Count -or (Compare-Object $entries $required -CaseSensitive)) {
            throw 'Unexpected files in the portable bundle.'
        }
    }
    finally {
        $bundle.Dispose()
    }
    [IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $folder)
    $binary = Get-Item -LiteralPath (Join-Path $folder 'rustregistry.exe')
    if ((Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash -ne $expected[$binary.Name]) {
        throw 'Executable checksum mismatch.'
    }
    if ($binary.VersionInfo.ProductVersion -ne $Version -or $binary.VersionInfo.ProductName -ne 'RustRegistry') {
        throw 'Executable version or product name mismatch.'
    }
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($binary.FullName))
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Expected a Windows executable.' }
        $reader.BaseStream.Position = 0x3c
        $reader.BaseStream.Position = $reader.ReadUInt32()
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw 'Expected a Windows x64 executable.'
        }
    }
    finally {
        $reader.Dispose()
    }
    $notices = Get-Content -LiteralPath (Join-Path $folder 'THIRD-PARTY-NOTICES.txt') -Raw
    if ($notices -notmatch '(?m)^gpui \S+ ' -or $notices -notmatch '(?m)^gpui-component \S+ ') {
        throw 'The bundle is missing GPUI dependency notices.'
    }

    if ($Launch) {
        & (Join-Path $PSScriptRoot 'smoke-windows-startup.ps1') -Executable $binary.FullName
    }
    Write-Output "Verified $archiveName, both SHA-256 hashes, PE metadata, and package contents."
}
finally {
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath($folder)
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'RustRegistry-verify-*') {
        throw 'Unexpected verification extraction path.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
