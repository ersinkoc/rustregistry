param(
    [Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if ([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$descriptorDirectory=Join-Path $workspace '.temp_files\registered-app-fixtures'
$descriptorPath=Join-Path $descriptorDirectory "$Token.json"
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
$rootPath='Software\RegisteredApplications'
$capRoot="Software\RustRegistryE2E-$Token"
$kinds=@('MissingOne','MissingTwo','Found','Malformed')
$names=@($kinds | ForEach-Object { "RustRegistry-E2E-Registration-$Token-$_" })
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RegisteredApplicationFixtureReader {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]
    private static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out] byte[] data,ref uint size);
    public static string Read(SafeRegistryHandle key,string name,out uint type) {
        uint size=0;int code=Query(key,name,IntPtr.Zero,out type,null,ref size);
        if(code!=0||size>262144) throw new InvalidOperationException("Cannot size registry value: "+code);
        byte[] data=new byte[size];code=Query(key,name,IntPtr.Zero,out type,data,ref size);
        if(code!=0||size>data.Length) throw new InvalidOperationException("Cannot read registry value: "+code);
        return Convert.ToBase64String(data,0,(int)size);
    }
}
'@
function Read-Value($key,$name) {
    if ($key.GetValueNames() -notcontains $name) { return [ordered]@{name=$name;present=$false;kind=$null;bytes=$null} }
    [uint32]$kind=0
    $bytes=[RegisteredApplicationFixtureReader]::Read($key.Handle,$name,[ref]$kind)
    [ordered]@{name=$name;present=$true;kind=$kind;bytes=$bytes}
}
function Read-State($key) {
    $others=@($key.GetValueNames() | Sort-Object | Where-Object { $_ -notin $names } | ForEach-Object { Read-Value $key $_ })
    $raw=ConvertTo-Json -InputObject $others -Depth 5 -Compress
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $fingerprint=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($raw))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    [ordered]@{security=$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);subkeys=@($key.GetSubKeyNames() | Sort-Object);unrelatedSHA256=$fingerprint;owned=@($names | ForEach-Object { Read-Value $key $_ })}
}
function Expected($kind) {
    if ($kind -eq 'Malformed') { return [ordered]@{kind=4;bytes='BwAAAA=='} }
    [ordered]@{kind=1;bytes=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("$capRoot\$kind\Capabilities"+[char]0))}
}
try {
    $key=$base.OpenSubKey($rootPath,($Action -ne 'inspect'))
    if (-not $key) { throw 'An existing current-user RegisteredApplications root is required. It is never recreated.' }
    try {
        if ($Action -eq 'create') {
            if (Test-Path -LiteralPath $descriptorPath) { throw 'Owned fixture descriptor collision.' }
            $collision=$base.OpenSubKey($capRoot)
            if ($collision) { $collision.Dispose(); throw 'Owned Capabilities root collision.' }
            foreach ($name in $names) { if ($key.GetValueNames() -contains $name) { throw 'Owned registration name collision.' } }
            $baseline=Read-State $key
            New-Item -ItemType Directory -Path $descriptorDirectory -Force | Out-Null
            $descriptor=[ordered]@{token=$Token;ownerSid=$owner;capRoot=$capRoot;baseline=$baseline}
            $bytes=[Text.Encoding]::UTF8.GetBytes(($descriptor | ConvertTo-Json -Depth 8 -Compress))
            $stream=[IO.File]::Open($descriptorPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
            $caps=$base.CreateSubKey($capRoot)
            try { $caps.SetValue('OwnedFixture',$Token,[Microsoft.Win32.RegistryValueKind]::String) } finally { $caps.Dispose() }
            $found=$base.CreateSubKey("$capRoot\Found\Capabilities")
            try { $found.SetValue('ApplicationName','Owned registration control',[Microsoft.Win32.RegistryValueKind]::String) } finally { $found.Dispose() }
            foreach ($kind in $kinds) {
                $name="RustRegistry-E2E-Registration-$Token-$kind"
                if ($kind -eq 'Malformed') { $key.SetValue($name,7,[Microsoft.Win32.RegistryValueKind]::DWord) }
                else { $key.SetValue($name,"$capRoot\$kind\Capabilities",[Microsoft.Win32.RegistryValueKind]::String) }
            }
        }
        if (-not (Test-Path -LiteralPath $descriptorPath)) { throw 'Owned fixture descriptor is missing.' }
        $descriptor=Get-Content -LiteralPath $descriptorPath -Raw | ConvertFrom-Json
        if ($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $owner -or $descriptor.capRoot -cne $capRoot) { throw 'Fixture identity mismatch.' }
        $state=Read-State $key
        if ($state.security -cne $descriptor.baseline.security -or $state.unrelatedSHA256 -cne $descriptor.baseline.unrelatedSHA256 -or (ConvertTo-Json -InputObject $state.subkeys -Compress) -cne (ConvertTo-Json -InputObject @($descriptor.baseline.subkeys) -Compress)) { throw 'Unrelated registrations, root permissions, or child names changed. No unrelated data will be restored or overwritten.' }
        $caps=$base.OpenSubKey($capRoot)
        if (-not $caps) { throw 'Owned Capabilities control is missing.' }
        try {
            if ($caps.GetValue('OwnedFixture') -cne $Token -or $caps.ValueCount -ne 1 -or $caps.SubKeyCount -ne 1 -or $caps.GetSubKeyNames()[0] -cne 'Found') { throw 'Owned Capabilities identity or structure changed.' }
            $found=$caps.OpenSubKey('Found'); try { if ($found.ValueCount -ne 0 -or $found.SubKeyCount -ne 1 -or $found.GetSubKeyNames()[0] -cne 'Capabilities') { throw 'Owned control structure changed.' } } finally { $found.Dispose() }
            $found=$caps.OpenSubKey('Found\Capabilities'); try { if ($found.ValueCount -ne 1 -or $found.SubKeyCount -ne 0 -or $found.GetValue('ApplicationName') -cne 'Owned registration control') { throw 'Owned Capabilities metadata changed.' } } finally { $found.Dispose() }
            $capSecurity=$caps.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)
        } finally { $caps.Dispose() }
        foreach ($kind in $kinds) {
            $name="RustRegistry-E2E-Registration-$Token-$kind"
            $current=Read-Value $key $name
            $expected=Expected $kind
            if ($current.present -and ($current.kind -ne $expected.kind -or $current.bytes -cne $expected.bytes)) { throw 'An owned value changed unexpectedly. Cleanup stopped.' }
            if ($kind -in @('Found','Malformed') -and -not $current.present) { throw 'A read-only control was removed.' }
        }
        if ($Action -eq 'cleanup') {
            foreach ($name in $names) { $key.DeleteValue($name,$false) }
            foreach ($suffix in @('\Found\Capabilities','\Found','')) { $base.DeleteSubKey("$capRoot$suffix",$true) }
            $state=Read-State $key
        }
        [ordered]@{token=$Token;state=$state;capabilitiesControl=($Action -ne 'cleanup');capabilitiesSecurity=$capSecurity} | ConvertTo-Json -Depth 8 -Compress
    } finally { $key.Dispose() }
} finally { $base.Dispose() }
