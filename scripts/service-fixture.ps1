param(
    [Parameter(Mandatory = $true)][ValidateSet('prepare', 'create-elevated', 'inspect', 'cleanup', 'verify')][string]$Action,
    [ValidatePattern('^[a-f0-9-]{36}$')][string]$Token,
    [string]$OwnerSid,
    [string]$TargetDirectory,
    [string]$ResultPath
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ($Action -ne 'verify' -and [Guid]::ParseExact($Token, 'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$name = "RustRegistry-E2E-Service-$Token"
$controlName = "$name-Control"
$displayName = "RustRegistry E2E service $Token"
$rootPath = 'SYSTEM\CurrentControlSet\Services'
$fixtureDirectory = [System.IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) '.temp_files\service-fixtures'))
trap {
    if ($Action -eq 'create-elevated' -and $Token -match '^[a-f0-9-]{36}$') {
        $failureLog = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) '.temp_files\service-fixtures') "$Token.error.txt"
        try {($_ | Out-String) | Set-Content -LiteralPath $failureLog -Encoding UTF8} catch {}
    }
    break
}
if ($Action -eq 'prepare') {
    $OwnerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $TargetDirectory = [System.IO.Path]::GetTempPath().TrimEnd('\')
    New-Item -ItemType Directory -Path $fixtureDirectory -Force | Out-Null
    $ResultPath = Join-Path $fixtureDirectory "$Token.json"
    if (Test-Path -LiteralPath $ResultPath) { throw 'The fixture descriptor already exists.' }
    Set-Content -LiteralPath (Join-Path $fixtureDirectory "$Token.error.txt") -Value 'The elevated helper did not report an error.' -Encoding UTF8
    $arguments = @('-NoProfile', '-NonInteractive', '-File', ('"' + $PSCommandPath + '"'), '-Action', 'create-elevated', '-Token', $Token, '-OwnerSid', $OwnerSid, '-TargetDirectory', ('"' + $TargetDirectory + '"'), '-ResultPath', ('"' + $ResultPath + '"'))
    # This is an explicit test-setup action, never invoked automatically by the app or smoke suite.
    $helper = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    if ($helper.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $ResultPath)) {
        $failureLog = Join-Path $fixtureDirectory "$Token.error.txt"
        if (Test-Path -LiteralPath $failureLog) { throw (Get-Content -LiteralPath $failureLog -Raw) }
        throw "The approved fixture setup did not complete (helper exit $($helper.ExitCode))."
    }
    Get-Content -LiteralPath $ResultPath -Raw
    exit 0
}
if ($Action -in @('create-elevated','verify')) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RustRegistryServiceFixture {
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenSCManager(IntPtr machine, IntPtr database, uint access);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateService(IntPtr manager, string name, string display, uint access, uint type, uint start, uint error, string binary, IntPtr group, IntPtr tag, IntPtr dependencies, string account, IntPtr password);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenService(IntPtr manager, string name, uint access);
 [DllImport("advapi32.dll", SetLastError=true)] public static extern bool CloseServiceHandle(IntPtr handle);
 [DllImport("advapi32.dll", SetLastError=true)] public static extern bool DeleteService(IntPtr handle);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
 [DllImport("advapi32.dll", SetLastError=true)] public static extern bool SetServiceObjectSecurity(IntPtr service, uint info, IntPtr descriptor);
 [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr pointer);
}
'@
}
if ($Action -eq 'verify') {
    $manager = [RustRegistryServiceFixture]::OpenSCManager([IntPtr]::Zero, [IntPtr]::Zero, 1)
    if ($manager -eq [IntPtr]::Zero) { throw "Read-only local SCM connection failed (Windows error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))." }
    [void][RustRegistryServiceFixture]::CloseServiceHandle($manager)
    'Read-only native fixture ABI check passed. No service was created or changed.'
    exit 0
}
if ($Action -eq 'create-elevated') {
    if ($OwnerSid -notmatch '^S-1-5-21-[0-9-]+$') { throw 'A specific local caller SID is required.' }
    $resolvedResult = [System.IO.Path]::GetFullPath($ResultPath)
    if ($resolvedResult -cne (Join-Path $fixtureDirectory "$Token.json")) { throw 'Unexpected fixture descriptor path.' }
    $TargetDirectory = [System.IO.Path]::GetFullPath($TargetDirectory)
    if ($TargetDirectory -notmatch '^[A-Za-z]:\\' -or $TargetDirectory.StartsWith($env:SystemRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'A local temporary directory outside Windows is required.' }

    $manager = [RustRegistryServiceFixture]::OpenSCManager([IntPtr]::Zero, [IntPtr]::Zero, 3)
    if ($manager -eq [IntPtr]::Zero) { throw "Administrator SCM create access is unavailable (Windows error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))." }
    $created = @()
    $success = $false
    try {
        foreach ($variant in @(@{ Name = $name; Display = $displayName; Start = 3; Suffix = '' }, @{ Name = $controlName; Display = "$displayName control"; Start = 4; Suffix = '-Control' })) {
            $existing = [RustRegistryServiceFixture]::OpenService($manager, $variant.Name, 1)
            if ($existing -ne [IntPtr]::Zero) { [void][RustRegistryServiceFixture]::CloseServiceHandle($existing); throw 'Service fixture name collision.' }
            if ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -ne 1060) { throw 'The fixture name could not be verified absent.' }
            $target = Join-Path $TargetDirectory ("RustRegistryMissing-Service-$Token" + $variant.Suffix + '.exe')
            if (Test-Path -LiteralPath $target) { throw 'The fixture executable unexpectedly exists.' }
            $service = [RustRegistryServiceFixture]::CreateService($manager, $variant.Name, $variant.Display, 0xF01FF, 16, $variant.Start, 0, ('"' + $target + '"'), [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, 'NT AUTHORITY\LocalService', [IntPtr]::Zero)
            if ($service -eq [IntPtr]::Zero) { throw "Cannot create the owned service fixture (Windows error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))." }
            $created += $service
            $descriptor = [IntPtr]::Zero
            $descriptorSize = [uint32]0
            try {
                # Only these owned, never-started fixtures delegate query/configure/delete to the caller.
                $sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x3000f;;;$OwnerSid)"
                if (-not [RustRegistryServiceFixture]::ConvertStringSecurityDescriptorToSecurityDescriptor($sddl, 1, [ref]$descriptor, [ref]$descriptorSize)) { throw 'Cannot build the fixture-only security descriptor.' }
                if (-not [RustRegistryServiceFixture]::SetServiceObjectSecurity($service, 4, $descriptor)) { throw 'Cannot delegate fixture-only configuration access.' }
            } finally { if ($descriptor -ne [IntPtr]::Zero) { [void][RustRegistryServiceFixture]::LocalFree($descriptor) } }
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$rootPath\$($variant.Name)", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ReadKey -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($null -eq $key) { throw 'Owned service registry metadata is unavailable.' }
            try {
                if ($key.GetValue('DisplayName') -cne $variant.Display) { throw 'Service ownership marker mismatch.' }
                $paths = @('') + @($key.GetSubKeyNames())
                foreach ($childPath in $paths) {
                    if ($childPath -ne '' -and $childPath -ne 'Security') { throw 'Unexpected child key in the new fixture.' }
                    $child = if ($childPath -eq '') { $key } else { $key.OpenSubKey($childPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ReadKey -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions) }
                    try {
                        $acl = $child.GetAccessControl()
                        $identity = [System.Security.Principal.SecurityIdentifier]::new($OwnerSid)
                        $rule = [System.Security.AccessControl.RegistryAccessRule]::new($identity, [System.Security.AccessControl.RegistryRights]::ReadKey, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
                        $acl.AddAccessRule($rule)
                        $child.SetAccessControl($acl)
                    } finally { if ($childPath -ne '') { $child.Dispose() } }
                }
            } finally { $key.Dispose() }
        }
        [ordered]@{ token = $Token; name = $name; controlName = $controlName; displayName = $displayName; ownerSid = $OwnerSid; neverStarted = $true } | ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding UTF8
        $success = $true
    } finally {
        foreach ($handle in $created) { if (-not $success) { [void][RustRegistryServiceFixture]::DeleteService($handle) }; [void][RustRegistryServiceFixture]::CloseServiceHandle($handle) }
        [void][RustRegistryServiceFixture]::CloseServiceHandle($manager)
    }
    exit 0
}
function Read-Values($Key) {
    @($Key.GetValueNames() | Sort-Object { $_.ToLowerInvariant() } | ForEach-Object {
        [ordered]@{ name = $_; kind = $Key.GetValueKind($_).ToString(); value = $Key.GetValue($_, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    })
}
function Read-Security($Key) {
    $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group
    $Key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)
}
$results = @()
foreach ($serviceName in @($name, $controlName)) {
    $expectedDisplay = if ($serviceName -eq $name) { $displayName } else { "$displayName control" }
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        if ($Action -eq 'cleanup') { continue }
        throw 'The approved owned service fixture does not exist.'
    }
    if ($service.DisplayName -cne $expectedDisplay -or $service.Status.ToString() -ne 'Stopped') { throw 'Unexpected fixture identity or state. No service was modified.' }
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$rootPath\$serviceName")
    try {
        if ($key.GetValue('ObjectName') -ne 'NT AUTHORITY\LocalService' -or $key.GetValue('ImagePath') -notmatch ('RustRegistryMissing-Service-' + [regex]::Escape($Token) + '(-Control)?\.exe"$') -or $key.GetValue('DisplayName') -cne $expectedDisplay -or $key.GetValue('Start') -notin @(3,4) -or @($key.GetSubKeyNames() | Where-Object { $_ -ne 'Security' }).Count -ne 0) { throw 'Unexpected service fixture registry metadata.' }
        $child = $key.OpenSubKey('Security')
        try { $securityValues = if ($null -eq $child) { $null } else { @(Read-Values $child) } } finally { if ($null -ne $child) { $child.Dispose() } }
        $serviceSecurity = & (Join-Path $env:SystemRoot 'System32\sc.exe') sdshow $serviceName
        if ($LASTEXITCODE -ne 0) { throw 'Cannot read fixture service permissions.' }
        $sddl = ($serviceSecurity | Where-Object { $_.Trim() -match '^[OGDS]:' }) -join ''
        $results += [ordered]@{ name = $serviceName; displayName = $expectedDisplay; startMode = $service.StartType.ToString(); state = $service.Status.ToString(); account = $key.GetValue('ObjectName'); path = $key.GetValue('ImagePath'); values = @(Read-Values $key); securityValues = $securityValues; registrySecurity = Read-Security $key; serviceSecurity = $sddl.Trim() }
    } finally { $key.Dispose(); $service.Dispose() }
    if ($Action -eq 'cleanup') {
        & (Join-Path $env:SystemRoot 'System32\sc.exe') delete $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot remove the owned service fixture.' }
    }
}
if ($Action -eq 'cleanup') {
    foreach ($serviceName in @($name,$controlName)) {
        if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { throw 'Owned service deletion is pending; no other cleanup was attempted.' }
    }
    [ordered]@{ exists = $false } | ConvertTo-Json -Compress
} else { [ordered]@{ token = $Token; services = $results } | ConvertTo-Json -Depth 12 -Compress }
