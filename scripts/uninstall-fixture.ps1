param(
    [Parameter(Mandatory = $true)][ValidateSet('create', 'inspect', 'cleanup')][string]$Action,
    [Parameter(Mandatory = $true)][ValidatePattern('^RustRegistry-E2E-Uninstall-[a-f0-9-]{36}$')][string]$Name
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$token = $Name.Substring(27, 36)
if ([Guid]::ParseExact($token, 'D').ToString('D') -cne $token) { throw 'Invalid fixture identifier.' }
$rootKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall', $true)
if ($null -eq $rootKey) { throw 'The existing current-user Uninstall root is required.' }
try {
    if ($Action -eq 'create') {
        $existing = $rootKey.OpenSubKey($Name)
        if ($null -ne $existing) { $existing.Dispose(); throw 'Fixture name collision.' }
        $folder = Join-Path ([System.IO.Path]::GetTempPath()) "RustRegistryMissing-install-$token"
        $uninstaller = Join-Path ([System.IO.Path]::GetTempPath()) "RustRegistryMissing-uninstall-$token.exe"
        if ((Test-Path -LiteralPath $folder) -or (Test-Path -LiteralPath $uninstaller)) { throw 'A fixture target unexpectedly exists.' }
        $key = $rootKey.CreateSubKey($Name)
        try {
            $key.SetValue('RustRegistryFixture', $token, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('DisplayName', "RustRegistry E2E Uninstall $token", [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('DisplayVersion', '0.0.0-test', [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('Publisher', 'RustRegistry E2E fixture', [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('InstallLocation', $folder, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('UninstallString', ('"' + $uninstaller + '" /remove'), [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('QuietUninstallString', ('"' + $uninstaller + '" /quiet'), [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('CustomBinary', [byte[]]@(0, 255, 1, 0), [Microsoft.Win32.RegistryValueKind]::Binary)
        } finally { $key.Dispose() }
    }
    $key = $rootKey.OpenSubKey($Name)
    if ($null -eq $key) {
        if ($Action -eq 'cleanup') { @{ exists = $false } | ConvertTo-Json -Compress; exit 0 }
        throw 'The owned fixture is missing.'
    }
    try {
        if ($key.GetValue('RustRegistryFixture') -cne $token) { throw 'Fixture ownership mismatch.' }
        $names = @($key.GetValueNames())
        if ($Action -eq 'cleanup') {
            $unknown = @($names | Where-Object { $_ -notin @('RustRegistryFixture','DisplayName','DisplayVersion','Publisher','InstallLocation','UninstallString','QuietUninstallString','CustomBinary','SystemComponent') })
            if ($unknown.Count -gt 0 -or $key.SubKeyCount -ne 0) { throw 'Unexpected fixture data. Cleanup stopped.' }
            $result = @{ exists = $false }
        } else {
            $values = @($names | Sort-Object { $_.ToLowerInvariant() } | ForEach-Object {
                [ordered]@{ name = $_; kind = $key.GetValueKind($_).ToString(); value = $key.GetValue($_, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
            })
            $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group
            $result = [ordered]@{ exists = $true; displayName = $key.GetValue('DisplayName'); marker = $token; values = $values; hidden = ($key.GetValue('SystemComponent', 0) -eq 1); children = $key.SubKeyCount; security = $key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections) }
        }
    } finally { $key.Dispose() }
    if ($Action -eq 'cleanup') { $rootKey.DeleteSubKey($Name, $true) }
    $result | ConvertTo-Json -Depth 8 -Compress
} finally { $rootKey.Dispose() }
