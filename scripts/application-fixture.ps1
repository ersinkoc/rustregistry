param(
    [Parameter(Mandatory = $true)][ValidateSet('create', 'inspect', 'cleanup')][string]$Action,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token,
    [Parameter(Mandatory = $true)][string]$FoundTarget
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ([Guid]::ParseExact($Token, 'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$FoundTarget = [System.IO.Path]::GetFullPath($FoundTarget)
if (-not [System.IO.File]::Exists($FoundTarget) -or [System.IO.Path]::GetExtension($FoundTarget) -ine '.exe' -or $FoundTarget.Contains('"')) { throw 'An existing executable is required for the read-only control.' }
$missing = Join-Path ([System.IO.Path]::GetTempPath()) "RustRegistryMissing-Application-$Token.exe"
if (Test-Path -LiteralPath $missing) { throw 'Missing-target fixture unexpectedly exists.' }
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
$results = @()
try {
    foreach ($kind in @('Missing', 'Found', 'Delegated', 'Hidden')) {
        $name = "RustRegistry-E2E-App-$Token-$kind.exe"
        $path = "Software\Classes\Applications\$name"
        $target = if ($kind -eq 'Found') { $FoundTarget } else { $missing }
        $expected = '"' + $target + '" "%1"'
        if ($Action -eq 'create') {
            $collision = $baseKey.OpenSubKey($path)
            if ($null -ne $collision) { $collision.Dispose(); throw 'Application fixture collision.' }
            $command = $baseKey.CreateSubKey("$path\shell\open\command")
            try {
                $command.SetValue('', $expected, [Microsoft.Win32.RegistryValueKind]::ExpandString)
                if ($kind -eq 'Delegated') { $command.SetValue('DelegateExecute', '{11111111-1111-4111-8111-111111111111}', [Microsoft.Win32.RegistryValueKind]::String) }
            } finally { $command.Dispose() }
            if ($kind -eq 'Hidden') { $hiddenKey = $baseKey.OpenSubKey($path, $true); try { $hiddenKey.SetValue('NoOpenWith', '', [Microsoft.Win32.RegistryValueKind]::String) } finally { $hiddenKey.Dispose() } }
        }
        $key = $baseKey.OpenSubKey($path)
        if ($null -eq $key) {
            if ($Action -eq 'cleanup') { $results += @{ name = $name; exists = $false }; continue }
            throw 'Owned application fixture is missing.'
        }
        try {
            $command = $key.OpenSubKey('shell\open\command')
            if ($null -eq $command) { throw 'Owned application command is missing.' }
            try {
                if ($command.GetValue('', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $expected -or $command.GetValueKind('') -ne [Microsoft.Win32.RegistryValueKind]::ExpandString -or $command.SubKeyCount -ne 0) { throw 'Application fixture ownership mismatch.' }
                $allowed = if ($kind -eq 'Delegated') { @('', 'DelegateExecute') } else { @('') }
                if (@($command.GetValueNames() | Where-Object { $_ -notin $allowed }).Count -or $command.ValueCount -ne $allowed.Count) { throw 'Unexpected fixture values.' }
                if ($kind -eq 'Delegated' -and $command.GetValue('DelegateExecute') -cne '{11111111-1111-4111-8111-111111111111}') { throw 'Delegated fixture mismatch.' }
                $hidden = $key.GetValueNames() -contains 'NoOpenWith'
                if (@($key.GetValueNames() | Where-Object { $_ -ine 'NoOpenWith' }).Count) { throw 'Unexpected application root metadata.' }
                if ($hidden -and ($key.GetValueKind('NoOpenWith') -ne [Microsoft.Win32.RegistryValueKind]::String -or $key.GetValue('NoOpenWith') -cne '')) { throw 'Unexpected application visibility flag.' }
                $parts = @('', 'shell', 'shell\open')
                $security = @()
                foreach ($part in $parts) {
                    $parent = if ($part -eq '') { $baseKey.OpenSubKey($path) } else { $key.OpenSubKey($part) }
                    try {
                        if ($parent.ValueCount -ne $(if ($part -eq '' -and $hidden) { 1 } else { 0 }) -or $parent.SubKeyCount -ne 1) { throw 'Unexpected application fixture structure.' }
                        $security += $parent.GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                    } finally { $parent.Dispose() }
                }
                $security += $command.GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                $results += [ordered]@{ name = $name; exists = $Action -ne 'cleanup'; command = $expected; commandKind = $command.GetValueKind('').ToString(); noOpenWith = $hidden; delegated = $kind -eq 'Delegated'; security = $security }
            } finally { $command.Dispose() }
        } finally { $key.Dispose() }
        if ($Action -eq 'cleanup') {
            foreach ($suffix in @('\shell\open\command', '\shell\open', '\shell', '')) { $baseKey.DeleteSubKey("$path$suffix", $true) }
        }
    }
} finally { $baseKey.Dispose() }
@{ applications = $results } | ConvertTo-Json -Depth 8 -Compress
