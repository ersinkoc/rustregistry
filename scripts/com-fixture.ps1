param(
    [Parameter(Mandatory = $true)][ValidateSet('create', 'inspect', 'cleanup')][string]$Action,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token,
    [ValidateSet('InprocServer32', 'InprocHandler32', 'LocalServer32')][string]$ServerKind = 'InprocServer32'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ([Guid]::ParseExact($Token, 'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$clsid = '{' + $Token + '}'
$displayName = "RustRegistry E2E COM $Token"
if ($ServerKind -ne 'InprocServer32') { $displayName += " $ServerKind" }
$missingDll = Join-Path ([System.IO.Path]::GetTempPath()) "RustRegistryMissing-COM-$Token.dll"
if ($ServerKind -eq 'LocalServer32') { $missingDll = [System.IO.Path]::ChangeExtension($missingDll, '.exe') }
if (Test-Path -LiteralPath $missingDll) { throw 'The fixture target unexpectedly exists.' }
function Read-Values($Key) {
    @($Key.GetValueNames() | Sort-Object { $_.ToLowerInvariant() } | ForEach-Object {
        [ordered]@{ name = $_; kind = $Key.GetValueKind($_).ToString(); value = $Key.GetValue($_, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    })
}
function Read-Security($Key) {
    $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group
    $Key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)
}
$views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
$results = @()
foreach ($view in $views) {
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
    try {
        $root = $baseKey.OpenSubKey('Software\Classes\CLSID', $true)
        if ($null -eq $root) { throw "The existing $view current-user CLSID root is required." }
        try {
            if ($Action -eq 'create') {
                $existing = $root.OpenSubKey($clsid)
                if ($null -ne $existing) { $existing.Dispose(); throw 'COM fixture name collision.' }
                $class = $root.CreateSubKey($clsid)
                try {
                    $class.SetValue('', $displayName, [Microsoft.Win32.RegistryValueKind]::String)
                    $server = $class.CreateSubKey($ServerKind)
                    try {
                        $command = if ($ServerKind -eq 'LocalServer32') { '"' + $missingDll + '" /Embedding' } else { '%TEMP%\RustRegistryMissing-COM-' + $Token + '.dll' }
                        $server.SetValue('', $command, [Microsoft.Win32.RegistryValueKind]::ExpandString)
                        if ($ServerKind -eq 'InprocServer32') { $server.SetValue('ThreadingModel', 'Both', [Microsoft.Win32.RegistryValueKind]::String) }
                    } finally { $server.Dispose() }
                } finally { $class.Dispose() }
            }
            $class = $root.OpenSubKey($clsid)
            if ($null -eq $class) {
                if ($Action -eq 'cleanup') { $results += @{ exists = $false; view = $view.ToString() }; continue }
                throw 'The owned COM fixture is missing.'
            }
            try {
                if ($class.GetValue('') -cne $displayName) { throw 'COM fixture ownership mismatch.' }
                $server = $class.OpenSubKey($ServerKind)
                if ($null -eq $server) { throw 'The owned DLL mapping key is missing.' }
                try {
                    if ($Action -eq 'cleanup') {
                        $unknownClass = @($class.GetValueNames() | Where-Object { $_ -ne '' })
                        $allowedValues = if ($ServerKind -eq 'InprocServer32') { @('', 'ThreadingModel') } else { @('') }
                        $unknownServer = @($server.GetValueNames() | Where-Object { $_ -notin $allowedValues })
                        if ($unknownClass.Count -or $unknownServer.Count -or $class.SubKeyCount -ne 1 -or $server.SubKeyCount -ne 0 -or ($ServerKind -eq 'InprocServer32' -and $server.GetValue('ThreadingModel') -cne 'Both')) { throw 'Unexpected COM fixture metadata. Cleanup stopped.' }
                        $results += @{ exists = $false; view = $view.ToString() }
                    } else {
                        $results += [ordered]@{ exists = $true; view = $view.ToString(); clsid = $clsid; displayName = $displayName; classValues = @(Read-Values $class); serverValues = @(Read-Values $server); classSecurity = Read-Security $class; serverSecurity = Read-Security $server }
                    }
                } finally { $server.Dispose() }
            } finally { $class.Dispose() }
            if ($Action -eq 'cleanup') {
                $root.DeleteSubKey("$clsid\$ServerKind", $true)
                $root.DeleteSubKey($clsid, $true)
            }
        } finally { $root.Dispose() }
    } finally { $baseKey.Dispose() }
}
[ordered]@{ clsid = $clsid; displayName = $displayName; views = $results } | ConvertTo-Json -Depth 8 -Compress
