param(
    [Parameter(Mandatory=$true)][ValidateSet('create','cleanup')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token,
    [Parameter(Mandatory=$true)][string]$Executable,
    [ValidateRange(1,65535)][int]$Port=1,
    [string]$UserDataFolder
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if ([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token) { throw 'Invalid owned policy identifier.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The explicit elevated test session is required.' }
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$Executable=[IO.Path]::GetFullPath($Executable)
$ownedDirectory=Join-Path $workspace ".temp_files\elevated-executables\$Token"
$aliasName="RustRegistry-E2E-WebView-$Token.exe"
if ($Executable -cne (Join-Path $ownedDirectory $aliasName) -or -not [IO.File]::Exists($Executable)) { throw 'Only the uniquely named owned test executable supports a policy override.' }
$descriptorPath=Join-Path $workspace ".temp_files\webview-policy-$Token.json"
$baseKey=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
$policyRoot='Software\Policies\Microsoft\Edge\WebView2'
$created=@()
try {
    if ($Action -eq 'create') {
        $UserDataFolder=[IO.Path]::GetFullPath($UserDataFolder)
        if (-not $UserDataFolder.StartsWith((Join-Path $workspace '.temp_files')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'The test profile must stay inside the ignored workspace directory.' }
        if (Test-Path -LiteralPath $descriptorPath) { throw 'The owned WebView2 policy descriptor already exists.' }
        $settings=@(
            [ordered]@{ key="$policyRoot\AdditionalBrowserArguments"; value="--remote-debugging-port=$Port --remote-debugging-address=127.0.0.1" },
            [ordered]@{ key="$policyRoot\UserDataFolder"; value=$UserDataFolder }
        )
        # Preflight every owned value before creating any override. No wildcard,
        # production executable, existing value, or access rule is ever changed.
        foreach ($setting in $settings) {
            $key=$baseKey.OpenSubKey($setting.key)
            if ($key) { try { if ($key.GetValueNames() -contains $aliasName) { throw 'Owned test policy name collision.' } } finally { $key.Dispose() } }
        }
        $parts=$policyRoot.Split('\')
        $path=''
        foreach ($part in $parts) {
            $path=if ($path) { "$path\$part" } else { $part }
            $key=$baseKey.OpenSubKey($path)
            if ($key) { $key.Dispose() } else { $created+=$path }
        }
        foreach ($setting in $settings) { $key=$baseKey.OpenSubKey($setting.key); if ($key) { $key.Dispose() } else { $created+=$setting.key } }
        $descriptor=[ordered]@{ token=$Token; executable=$Executable; aliasName=$aliasName; ownerSid=$identity.User.Value; settings=$settings; createdKeys=$created }
        $bytes=[Text.Encoding]::UTF8.GetBytes(($descriptor | ConvertTo-Json -Depth 7 -Compress))
        $stream=[IO.File]::Open($descriptorPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        foreach ($setting in $settings) { $key=$baseKey.CreateSubKey($setting.key); try { $key.SetValue($aliasName,$setting.value,[Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() } }
        [ordered]@{ created=$true; aliasName=$aliasName; port=$Port } | ConvertTo-Json -Compress
    } else {
        if (-not (Test-Path -LiteralPath $descriptorPath)) { [ordered]@{ cleaned=$true; existed=$false } | ConvertTo-Json -Compress; exit }
        $descriptor=Get-Content -LiteralPath $descriptorPath -Raw | ConvertFrom-Json
        if ($descriptor.token -cne $Token -or $descriptor.executable -cne $Executable -or $descriptor.aliasName -cne $aliasName -or $descriptor.ownerSid -cne $identity.User.Value -or $descriptor.settings.Count -ne 2) { throw 'Owned test policy identity mismatch.' }
        if ($descriptor.cleaned -eq $true) { [ordered]@{ cleaned=$true; existed=$false; aliasName=$aliasName } | ConvertTo-Json -Compress; exit }
        foreach ($setting in $descriptor.settings) {
            if ($setting.key -notin @("$policyRoot\AdditionalBrowserArguments","$policyRoot\UserDataFolder")) { throw 'Unexpected policy scope.' }
            $key=$baseKey.OpenSubKey($setting.key)
            if ($key) { try { if ($key.GetValueNames() -contains $aliasName) { if ($key.GetValueKind($aliasName) -ne [Microsoft.Win32.RegistryValueKind]::String -or $key.GetValue($aliasName) -cne $setting.value) { throw 'Owned test override changed. Cleanup stopped.' } } } finally { $key.Dispose() } }
        }
        foreach ($setting in $descriptor.settings) { $key=$baseKey.OpenSubKey($setting.key,$true); if ($key) { try { $key.DeleteValue($aliasName,$false) } finally { $key.Dispose() } } }
        foreach ($createdKey in @($descriptor.createdKeys | Sort-Object Length -Descending)) {
            if ($createdKey -notin @('Software\Policies\Microsoft\Edge',$policyRoot,"$policyRoot\AdditionalBrowserArguments","$policyRoot\UserDataFolder")) { continue }
            $key=$baseKey.OpenSubKey($createdKey)
            if ($key) { try { $empty=$key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0 } finally { $key.Dispose() }; if ($empty) { $baseKey.DeleteSubKey($createdKey,$false) } }
        }
        $descriptor | Add-Member -NotePropertyName cleaned -NotePropertyValue $true -Force
        [IO.File]::WriteAllText($descriptorPath,($descriptor | ConvertTo-Json -Depth 7 -Compress),[Text.UTF8Encoding]::new($false))
        [ordered]@{ cleaned=$true; existed=$true; aliasName=$aliasName } | ConvertTo-Json -Compress
    }
} finally { $baseKey.Dispose() }
