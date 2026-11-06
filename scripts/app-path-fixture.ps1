param(
    [Parameter(Mandatory = $true)][ValidateSet('create', 'inspect', 'cleanup')][string]$Action,
    [Parameter(Mandatory = $true)][ValidatePattern('^RustRegistry-E2E-[a-f0-9-]{36}\.exe$')][string]$Name
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$basePath = 'Software\Microsoft\Windows\CurrentVersion\App Paths'
$token = $Name.Substring(17, 36)
$parsed = [Guid]::ParseExact($token, 'D')
if ($parsed.ToString('D') -cne $token) { throw 'Invalid fixture identifier.' }
$rootKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($basePath, $true)
if ($null -eq $rootKey) { throw 'The existing current-user App Paths location is required for this fixture.' }
try {
    if ($Action -eq 'create') {
        $existing = $rootKey.OpenSubKey($Name)
        if ($null -ne $existing) { $existing.Dispose(); throw 'A fixture name collision was detected.' }
        $target = Join-Path ([System.IO.Path]::GetTempPath()) ("RustRegistryMissing-$token.exe")
        if (Test-Path -LiteralPath $target) { throw 'The fixture target unexpectedly exists.' }
        $fixtureKey = $rootKey.CreateSubKey($Name)
        try {
            $fixtureKey.SetValue('RustRegistryFixture', $token, [Microsoft.Win32.RegistryValueKind]::String)
            $fixtureKey.SetValue('', $target, [Microsoft.Win32.RegistryValueKind]::String)
            $fixtureKey.SetValue('Path', '%TEMP%\RustRegistryFixture', [Microsoft.Win32.RegistryValueKind]::ExpandString)
            $fixtureKey.SetValue('UseUrl', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        } finally { $fixtureKey.Dispose() }
    }
    $fixtureKey = $rootKey.OpenSubKey($Name)
    if ($null -eq $fixtureKey) {
        if ($Action -eq 'cleanup') { @{ exists = $false } | ConvertTo-Json -Compress; exit 0 }
        throw 'The owned fixture key is missing.'
    }
    try {
        if ($fixtureKey.GetValue('RustRegistryFixture') -cne $token) { throw 'Fixture ownership did not match; no cleanup is allowed.' }
        $names = @($fixtureKey.GetValueNames())
        $unknown = @($names | Where-Object { $_ -notin @('', 'Path', 'UseUrl', 'RustRegistryFixture') })
        if ($Action -eq 'cleanup' -and ($unknown.Count -gt 0 -or $fixtureKey.SubKeyCount -ne 0)) { throw 'Unexpected data in the owned fixture. Cleanup stopped.' }
        if ($Action -eq 'cleanup') { $result = @{ exists = $false } }
        else {
          $value = $fixtureKey.GetValue('', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
          $result = [ordered]@{
            exists = $true
            value = $value
            kind = $(if ($names -contains '') { $fixtureKey.GetValueKind('').ToString() } else { $null })
            metadataPath = $fixtureKey.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            pathKind = $fixtureKey.GetValueKind('Path').ToString()
            useUrl = $fixtureKey.GetValue('UseUrl')
            marker = $fixtureKey.GetValue('RustRegistryFixture')
            valueCount = $fixtureKey.ValueCount
            children = $fixtureKey.SubKeyCount
          }
        }
    } finally { $fixtureKey.Dispose() }
    if ($Action -eq 'cleanup') { $rootKey.DeleteSubKey($Name, $true) }
    $result | ConvertTo-Json -Compress
} finally { $rootKey.Dispose() }
