[CmdletBinding()]
param(
    [string]$Executable = 'target/x86_64-pc-windows-msvc/release/rustregistry.exe',
    [string]$OutputDirectory = 'target/portable',
    [string]$CargoAbout = 'cargo-about'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
if ($version -notmatch '^0\.\d+\.\d+$') { throw 'Invalid release version.' }
$binary = Get-Item -LiteralPath $Executable
if ($binary.VersionInfo.ProductVersion -ne $version -or $binary.VersionInfo.ProductName -ne 'RustRegistry') {
    throw "Expected a RustRegistry $version executable."
}

$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$archive = Join-Path $output "RustRegistry-$version-windows-x64.zip"
$checksums = Join-Path $output 'SHA256SUMS.txt'
if ((Test-Path -LiteralPath $archive) -or (Test-Path -LiteralPath $checksums)) {
    throw 'Choose a fresh output directory for the release package.'
}

$staging = [IO.Directory]::CreateTempSubdirectory('RustRegistry-package-').FullName
try {
    $executableCopy = Join-Path $staging 'rustregistry.exe'
    $licenseCopy = Join-Path $staging 'LICENSE'
    $readme = Join-Path $staging 'README.txt'
    $notices = Join-Path $staging 'THIRD-PARTY-NOTICES.txt'
    Copy-Item -LiteralPath $binary.FullName -Destination $executableCopy
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $licenseCopy
    @"
RustRegistry $version for Windows x64

Extract the ZIP and run rustregistry.exe. Select Run scan to inspect the
registry. Supported changes require review and create verified backups.

Keep the backups-v1 and operations-v1 folders together under
%LOCALAPPDATA%\dev.rustregistry.desktop when upgrading.

Project: https://github.com/ersinkoc/rustregistry
Release: https://github.com/ersinkoc/rustregistry/releases/tag/v$version
License: MIT. See LICENSE and THIRD-PARTY-NOTICES.txt.
"@ | Set-Content -LiteralPath $readme -Encoding utf8

    $licenseArguments = @(
        'about', 'generate', '--locked', '--fail', '--target', 'x86_64-pc-windows-msvc',
        '--manifest-path', (Join-Path $root 'crates/registry-desktop/Cargo.toml'),
        '--config', (Join-Path $PSScriptRoot 'windows-licenses.toml'),
        '--output-file', $notices, (Join-Path $PSScriptRoot 'windows-licenses.hbs')
    )
    & $CargoAbout @licenseArguments
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $notices)) {
        throw 'Could not generate third-party notices.'
    }

    Compress-Archive -LiteralPath @($executableCopy, $licenseCopy, $readme, $notices) -DestinationPath $archive
    $manifest = foreach ($file in @($archive, $executableCopy)) {
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($file))"
    }
    $manifest | Set-Content -LiteralPath $checksums -Encoding ascii
    Get-Item -LiteralPath $archive, $checksums
}
finally {
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath($staging)
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'RustRegistry-package-*') {
        throw 'Unexpected package staging path.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
