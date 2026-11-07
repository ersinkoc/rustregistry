param(
    [Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$fixtureRoot=Join-Path $workspace '.temp_files\type-library-fixtures'
$fixtureDirectory=[IO.Path]::GetFullPath((Join-Path $fixtureRoot $Token))
if(-not $fixtureDirectory.StartsWith($fixtureRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid owned fixture directory.' }
$descriptorPath=Join-Path $fixtureRoot "$Token.json"
$existingFile=Join-Path $fixtureDirectory 'owned-existing.tlb'
$marker="RustRegistry owned inert type library $Token. Never load this file."
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rootPath='Software\Classes\TypeLib'
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
$fixtures=@()
foreach($kind in @('One','Two','Found','Complex','Windows')) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Token-$kind")) } finally { $sha.Dispose() }
    $id=[Guid]::new([byte[]]$digest[0..15]).ToString('B')
    $extension=if($kind -eq 'Two') {'.olb'} else {'.tlb'}
    $path=Join-Path ([IO.Path]::GetTempPath()) "RustRegistry-E2E-TypeLib-$Token-$kind$extension"
    if($kind -eq 'Found') { $path=$existingFile }
    elseif($kind -eq 'Windows') { $path=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) "RustRegistry-E2E-TypeLib-$Token.tlb" }
    if($kind -ne 'Found' -and (Test-Path -LiteralPath $path)) { throw 'A missing target unexpectedly exists.' }
    $fixtures+=[ordered]@{kind=$kind;id=$id;name="RustRegistry E2E TypeLib $Token $kind";path=$path}
}
$ids=@($fixtures | ForEach-Object { $_.id })
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class TypeLibraryFixtureReader {
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
function Read-Values($key) {
    @($key.GetValueNames() | Sort-Object | ForEach-Object {
        [uint32]$kind=0
        $bytes=[TypeLibraryFixtureReader]::Read($key.Handle,$_ ,[ref]$kind)
        [ordered]@{name=$_;kind=$kind;bytes=$bytes}
    })
}
function Read-Tree($key,$path='',$depth=0) {
    if($depth -gt 4 -or $key.SubKeyCount -gt 16 -or $key.ValueCount -gt 16) { throw 'Unexpected owned type library structure.' }
    [ordered]@{path=$path;values=@(Read-Values $key);security=$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)}
    foreach($child in @($key.GetSubKeyNames() | Sort-Object)) {
        $next=$key.OpenSubKey($child)
        try { Read-Tree $next $(if($path){"$path\$child"}else{$child}) ($depth+1) } finally { $next.Dispose() }
    }
}
function Read-Views {
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,$view)
        try {
            $root=$base.OpenSubKey($rootPath)
            if(-not $root) { throw 'An existing current-user TypeLib root is required.' }
            try {
                $owned=@(foreach($fixture in $fixtures) {
                    $library=$root.OpenSubKey($fixture.id)
                    if($library) { try { [ordered]@{id=$fixture.id;kind=$fixture.kind;exists=$true;nodes=@(Read-Tree $library)} } finally { $library.Dispose() } }
                    else { [ordered]@{id=$fixture.id;kind=$fixture.kind;exists=$false;nodes=@()} }
                })
                [ordered]@{view=$view.ToString();rootSecurity=$root.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);rootValues=@(Read-Values $root);unrelatedLibraryNames=@($root.GetSubKeyNames() | Sort-Object | Where-Object { $_ -notin $ids });libraries=$owned}
            } finally { $root.Dispose() }
        } finally { $base.Dispose() }
    }
}
if($Action -eq 'create') {
    if((Test-Path -LiteralPath $descriptorPath) -or (Test-Path -LiteralPath $fixtureDirectory)) { throw 'Owned fixture collision.' }
    $baseline=@(Read-Views)
    if(@($baseline.libraries | Where-Object { $_.exists }).Count -ne 0) { throw 'Owned type library identifier collision.' }
    $machine=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try { foreach($fixture in $fixtures) { $key=$machine.OpenSubKey("$rootPath\$($fixture.id)"); if($key) { $key.Dispose();throw 'Machine type library collision.' } } } finally { $machine.Dispose() }
    New-Item -ItemType Directory -Path $fixtureDirectory | Out-Null
    $descriptor=[ordered]@{token=$Token;ownerSid=$owner;baseline=$baseline;originalViews=$null}
    [IO.File]::WriteAllText($descriptorPath,($descriptor | ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($existingFile,$marker,[Text.UTF8Encoding]::new($false))
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $root=$base.OpenSubKey($rootPath,$true)
        try { foreach($fixture in $fixtures) {
            $library=$root.CreateSubKey($fixture.id)
            try {
                $library.SetValue('',$fixture.name,[Microsoft.Win32.RegistryValueKind]::String)
                foreach($version in @('1.0')+$(if($fixture.kind -eq 'Complex'){@('2.0')}else{@()})) {
                    $versionKey=$library.CreateSubKey($version)
                    try {
                        $versionKey.SetValue('',$fixture.name,[Microsoft.Win32.RegistryValueKind]::String)
                        foreach($item in @(@{key='FLAGS';value='0'},@{key='HELPDIR';value=$fixtureDirectory},@{key='0\win32';value="%RUSTREGISTRY_DO_NOT_RESOLVE%\$Token.dll"},@{key='0\win64';value=$fixture.path})) {
                            $key=$versionKey.CreateSubKey($item.key)
                            try { $kind=if($item.key -like '*win*' -and $fixture.kind -ne 'Two'){[Microsoft.Win32.RegistryValueKind]::ExpandString}else{[Microsoft.Win32.RegistryValueKind]::String}; $key.SetValue('',$item.value,$kind) } finally { $key.Dispose() }
                        }
                    } finally { $versionKey.Dispose() }
                }
            } finally { $library.Dispose() }
        } } finally { $root.Dispose() }
    } finally { $base.Dispose() }
    $descriptor.originalViews=@(Read-Views)
    [IO.File]::WriteAllText($descriptorPath,($descriptor | ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
}
if(-not (Test-Path -LiteralPath $descriptorPath)) { throw 'Owned fixture descriptor is missing.' }
$descriptor=Get-Content -LiteralPath $descriptorPath -Raw | ConvertFrom-Json
if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $owner -or $descriptor.originalViews.Count -ne 2) { throw 'Owned fixture identity or setup is incomplete.' }
if(-not [IO.File]::Exists($existingFile) -or [IO.File]::ReadAllText($existingFile) -cne $marker) { throw 'The owned inert file changed; cleanup stopped.' }
$views=@(Read-Views)
foreach($view in $views) {
    $baseline=$descriptor.baseline | Where-Object { $_.view -ceq $view.view }
    if($view.rootSecurity -cne $baseline.rootSecurity -or (ConvertTo-Json -InputObject $view.rootValues -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject @($baseline.rootValues) -Depth 6 -Compress) -or (ConvertTo-Json -InputObject $view.unrelatedLibraryNames -Compress) -cne (ConvertTo-Json -InputObject @($baseline.unrelatedLibraryNames) -Compress)) { throw 'Unrelated TypeLib root values, names, or permissions changed. No unrelated data will be overwritten.' }
}
if($Action -eq 'cleanup') {
    foreach($view in $views) {
        $original=$descriptor.originalViews | Where-Object { $_.view -ceq $view.view }
        foreach($library in $view.libraries) {
            if(-not $library.exists) { throw 'An owned library key disappeared unexpectedly.' }
            $expected=($original.libraries | Where-Object { $_.id -ceq $library.id }) | ConvertTo-Json -Depth 12 | ConvertFrom-Json
            if($library.kind -in @('One','Two')) {
                $leaf=$library.nodes | Where-Object { $_.path -ceq '1.0\0\win64' }
                if($leaf -and $leaf.values.Count -eq 0) { ($expected.nodes | Where-Object { $_.path -ceq '1.0\0\win64' }).values=@() }
            }
            if(($library | ConvertTo-Json -Depth 12 -Compress) -cne ($expected | ConvertTo-Json -Depth 12 -Compress)) { throw 'Owned library metadata or permissions changed unexpectedly. Cleanup stopped.' }
        }
    }
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
    try {
        $root=$base.OpenSubKey($rootPath,$true)
        try { foreach($library in $views[0].libraries) { foreach($node in @($library.nodes | Sort-Object { $_.path.Length } -Descending)) { $path=if($node.path){"$($library.id)\$($node.path)"}else{$library.id}; $root.DeleteSubKey($path,$true) } } } finally { $root.Dispose() }
    } finally { $base.Dispose() }
    Remove-Item -LiteralPath $existingFile
    [IO.Directory]::Delete($fixtureDirectory,$false)
    $views=@(Read-Views)
}
[ordered]@{token=$Token;fixtures=$fixtures;existingFile=($Action -ne 'cleanup');views=$views} | ConvertTo-Json -Depth 12 -Compress
