param(
    [Parameter(Mandatory = $true)][ValidateSet('create', 'inspect', 'cleanup', 'verify')][string]$Action,
    [ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ($Action -eq 'verify' -and -not $Token) { $Token = '99999999-9999-4999-8999-999999999999' }
if ([Guid]::ParseExact($Token, 'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($Action -in @('create','cleanup') -and -not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Creating or removing the owned HKLM fixtures requires an explicitly elevated test session.' }
$workspace = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$fixtureRoot = Join-Path $workspace '.temp_files\shared-dll-fixtures'
$fixtureDirectory = [IO.Path]::GetFullPath((Join-Path $fixtureRoot $Token))
if (-not $fixtureDirectory.StartsWith($fixtureRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid fixture directory.' }
$descriptorPath = Join-Path $fixtureRoot "$Token.json"
$existingPath = Join-Path $fixtureDirectory "RustRegistry-E2E-SharedDLL-$Token-existing.dll"
$marker = "RustRegistry owned inert DLL fixture $Token. Never load this file."
$zeroPath = Join-Path ([IO.Path]::GetTempPath()) "RustRegistry-E2E-SharedDLL-$Token-zero.dll"
$positivePath = Join-Path ([IO.Path]::GetTempPath()) "RustRegistry-E2E-SharedDLL-$Token-positive.dll"
$malformedPath = Join-Path ([IO.Path]::GetTempPath()) "RustRegistry-E2E-SharedDLL-$Token-malformed.dll"
$windowsPath = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) "RustRegistry-E2E-SharedDLL-$Token-protected.dll"
$keyPath = 'Software\Microsoft\Windows\CurrentVersion\SharedDLLs'
foreach ($path in @($zeroPath, $positivePath, $malformedPath, $windowsPath)) { if (Test-Path -LiteralPath $path) { throw 'A missing-target fixture unexpectedly exists.' } }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Microsoft.Win32;
public static class SharedDllFixtureReader {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="RegOpenKeyExW")]
    private static extern int OpenKey(IntPtr parent, string name, uint options, uint access, out SafeRegistryHandle key);
    public static RegistryKey Open(bool view64, bool write) {
        RegistryView view=view64 ? RegistryView.Registry64 : RegistryView.Registry32;
            SafeRegistryHandle handle;
            // Use the predefined HKLM handle directly; RegistryKey.Handle on a base
            // key can request broader access than a read-only verifier needs.
            int code=OpenKey(new IntPtr(unchecked((int)0x80000002)),@"Software\Microsoft\Windows\CurrentVersion\SharedDLLs",8,0x20019u|(view64?0x100u:0x200u)|(write?2u:0u),out handle);
            if(code!=0) { if(handle!=null) handle.Dispose(); throw new InvalidOperationException("Cannot open existing SharedDLLs key: "+code); }
            return RegistryKey.FromHandle(handle,view);
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="RegQueryValueExW")]
    private static extern int Query(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, [Out] byte[] data, ref uint size);
    public static string Read(SafeRegistryHandle key, string name, out uint type) {
        uint size=0; int code=Query(key,name,IntPtr.Zero,out type,null,ref size);
        if(code!=0 || size>262144) throw new InvalidOperationException("Cannot size registry value: "+code);
        byte[] data=new byte[size]; code=Query(key,name,IntPtr.Zero,out type,data,ref size);
        if(code!=0 || size>data.Length) throw new InvalidOperationException("Cannot read complete registry value: "+code);
        return Convert.ToBase64String(data,0,(int)size);
    }
}
'@
function Controls($View) {
    if ($View -eq '32') { return @([ordered]@{ name=$zeroPath; kind=4; bytes='AAAAAA==' }) }
    @(
        [ordered]@{ name=$zeroPath; kind=4; bytes='AAAAAA==' },
        [ordered]@{ name=$positivePath; kind=4; bytes='AgAAAA==' },
        [ordered]@{ name=$existingPath; kind=4; bytes='AAAAAA==' },
        [ordered]@{ name=$malformedPath; kind=1; bytes='MAAAAA==' },
        [ordered]@{ name=$windowsPath; kind=4; bytes='AAAAAA==' }
    )
}
function Read-Value($Key, $Name) {
    if ($Key.GetValueNames() -notcontains $Name) { return [ordered]@{ name=$Name; present=$false; kind=$null; bytes=$null } }
    [uint32]$kind = 0
    $data = [SharedDllFixtureReader]::Read($Key.Handle, $Name, [ref]$kind)
    [ordered]@{ name=$Name; present=$true; kind=$kind; bytes=$data }
}
function Read-State($Key, $View) {
    $controls = @(Controls $View)
    $ownedNames = @($controls | ForEach-Object { $_.name })
    $others = @($Key.GetValueNames() | Sort-Object | Where-Object { $_ -notin $ownedNames } | ForEach-Object { Read-Value $Key $_ })
    $raw = ConvertTo-Json -InputObject $others -Depth 6 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $fingerprint = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($raw))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
    [ordered]@{ view=$View; security=$Key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections); unrelatedSHA256=$fingerprint; owned=@($controls | ForEach-Object { Read-Value $Key $_.name }) }
}
function With-Views([scriptblock]$Work) {
    foreach ($view in @('64','32')) {
            $key = [SharedDllFixtureReader]::Open(($view -eq '64'), ($Action -in @('create','cleanup')))
        try {
            if ($null -eq $key -or $key.SubKeyCount -ne 0) { throw 'An existing flat SharedDLLs key is required. Keys are never recreated or reconfigured.' }
            if ($key.GetValueNames() -contains 'SymbolicLinkValue') {
                [uint32]$linkKind = 0
                [void][SharedDllFixtureReader]::Read($key.Handle, 'SymbolicLinkValue', [ref]$linkKind)
                if ($linkKind -eq 6) { throw 'A SharedDLLs registry link will not be followed.' }
            }
            & $Work $key $view
        } finally { if ($key) { $key.Dispose() } }
    }
}
if ($Action -eq 'verify') {
    $states = @(With-Views { param($key,$view) $state = Read-State $key $view; [ordered]@{ view=$view; entries=$key.ValueCount; rawReaderVerified=$true } })
    [ordered]@{ readOnly=$true; views=$states } | ConvertTo-Json -Depth 4 -Compress
    exit
}
if ($Action -eq 'create') {
    if (Test-Path -LiteralPath $descriptorPath) { throw 'Fixture descriptor already exists.' }
    if (Test-Path -LiteralPath $fixtureDirectory) { throw 'Fixture directory already exists.' }
    $baseline = @(With-Views {
        param($key,$view)
        $state = Read-State $key $view
        if (@($state.owned | Where-Object present).Count) { throw 'Shared DLL fixture name collision.' }
        $state
    })
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $descriptor = [ordered]@{ token=$Token; ownerSid=$identity.User.Value; existingPath=$existingPath; baseline=$baseline }
    $data = [Text.Encoding]::UTF8.GetBytes(($descriptor | ConvertTo-Json -Depth 8 -Compress))
    $file = [IO.File]::Open($descriptorPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($data,0,$data.Length); $file.Flush($true) } finally { $file.Dispose() }
    New-Item -ItemType Directory -Path $fixtureDirectory | Out-Null
    [IO.File]::WriteAllText($existingPath, $marker, [Text.UTF8Encoding]::new($false))
    With-Views {
        param($key,$view)
        foreach ($control in @(Controls $view)) {
            $kind = if ($control.kind -eq 4) { [Microsoft.Win32.RegistryValueKind]::DWord } else { [Microsoft.Win32.RegistryValueKind]::String }
            $value = if ($control.kind -eq 4) { if ($control.name -eq $positivePath) { 2 } else { 0 } } else { '0' }
            $key.SetValue($control.name,$value,$kind)
        }
    }
}
if (-not (Test-Path -LiteralPath $descriptorPath)) { throw 'Owned fixture descriptor is missing.' }
$descriptor = Get-Content -LiteralPath $descriptorPath -Raw | ConvertFrom-Json
if ($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $identity.User.Value -or $descriptor.existingPath -cne $existingPath) { throw 'Shared DLL fixture ownership mismatch.' }
if (-not [IO.File]::Exists($existingPath) -or [IO.File]::ReadAllText($existingPath) -cne $marker) { throw 'The owned inert file changed; it will not be modified or deleted.' }
$states = @(With-Views {
    param($key,$view)
    $state = Read-State $key $view
    $baseline = @($descriptor.baseline | Where-Object view -eq $view)[0]
    if ($state.security -cne $baseline.security -or $state.unrelatedSHA256 -cne $baseline.unrelatedSHA256) { throw 'Unrelated SharedDLLs values or permissions changed. No unrelated data will be restored or overwritten.' }
    $state
})
if ($Action -eq 'cleanup') {
    # Validate all owned values before deleting any; no permissions or unrelated values are changed.
    foreach ($state in $states) {
        foreach ($value in $state.owned) {
            $expected = @(Controls $state.view | Where-Object name -eq $value.name)[0]
            if ($value.present -and ($value.kind -ne $expected.kind -or $value.bytes -cne $expected.bytes)) { throw 'An owned value changed unexpectedly. Cleanup stopped.' }
        }
    }
    With-Views { param($key,$view) foreach ($control in @(Controls $view)) { $key.DeleteValue($control.name,$false) } }
    $states = @(With-Views { param($key,$view) Read-State $key $view })
    if (@($states | ForEach-Object owned | Where-Object present).Count) { throw 'Owned SharedDLLs values remain.' }
    Remove-Item -LiteralPath $existingPath
    Remove-Item -LiteralPath $fixtureDirectory
}
[ordered]@{ token=$Token; zeroPath=$zeroPath; existingFile=$Action -ne 'cleanup'; views=$states } | ConvertTo-Json -Depth 9 -Compress
