param(
    [Parameter(Mandatory = $true)][ValidateSet('create', 'inspect', 'cleanup')][string]$Action,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ([Guid]::ParseExact($Token, 'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$extension = '.rr' + $Token.Replace('-', '')
$progid = "RustRegistry.E2E.Missing.$Token"
$keep = "RustRegistry.E2E.Keep.$Token"
$root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Classes', $true)
if ($null -eq $root) { throw 'The existing current-user Classes root is required.' }
function Read-Values($Key) {
    @($Key.GetValueNames() | Sort-Object { $_.ToLowerInvariant() } | ForEach-Object {
        [ordered]@{ name = $_; kind = $Key.GetValueKind($_).ToString(); value = $Key.GetValue($_, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    })
}
function Read-Security($Key) {
    $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group
    $Key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)
}
try {
    if ($Action -eq 'create') {
        $existing = $root.OpenSubKey($extension)
        if ($null -ne $existing) { $existing.Dispose(); throw 'Fixture extension collision.' }
        $key = $root.CreateSubKey($extension)
        try {
            $key.SetValue('RustRegistryFixture', $Token, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('', $keep, [Microsoft.Win32.RegistryValueKind]::String)
            $list = $key.CreateSubKey('OpenWithProgids')
            try {
                $list.SetValue($progid, [byte[]]@(), [Microsoft.Win32.RegistryValueKind]::None)
                $list.SetValue($keep, '', [Microsoft.Win32.RegistryValueKind]::String)
            } finally { $list.Dispose() }
        } finally { $key.Dispose() }
    }
    $key = $root.OpenSubKey($extension)
    if ($null -eq $key) {
        if ($Action -eq 'cleanup') { @{ exists = $false } | ConvertTo-Json -Compress; exit 0 }
        throw 'The owned fixture is missing.'
    }
    try {
        if ($key.GetValue('RustRegistryFixture') -cne $Token) { throw 'Fixture ownership mismatch.' }
        $list = $key.OpenSubKey('OpenWithProgids')
        if ($null -eq $list) { throw 'Owned suggestion list missing.' }
        try {
            if ($Action -eq 'cleanup') {
                $unexpectedExtension = @($key.GetValueNames() | Where-Object { $_ -notin @('', 'RustRegistryFixture') })
                $unexpectedSuggestions = @($list.GetValueNames() | Where-Object { $_ -notin @($progid, $keep) })
                if ($unexpectedExtension.Count -or $unexpectedSuggestions.Count -or $list.SubKeyCount -ne 0 -or $key.SubKeyCount -ne 1 -or $key.GetValue('') -cne $keep) { throw 'Unexpected fixture metadata. Cleanup stopped.' }
                $result = @{ exists = $false }
            } else {
                $choice = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\UserChoice")
                try { $choicePresent = $null -ne $choice } finally { if ($null -ne $choice) { $choice.Dispose() } }
                $result = [ordered]@{ exists = $true; extension = $extension; progid = $progid; marker = $Token; values = @(Read-Values $list); extensionValues = @(Read-Values $key); security = Read-Security $list; extensionSecurity = Read-Security $key; userChoicePresent = $choicePresent }
            }
        } finally { $list.Dispose() }
    } finally { $key.Dispose() }
    if ($Action -eq 'cleanup') {
        $root.DeleteSubKey("$extension\OpenWithProgids", $true)
        $root.DeleteSubKey($extension, $true)
    }
    $result | ConvertTo-Json -Depth 8 -Compress
} finally { $root.Dispose() }
