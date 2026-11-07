param([Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-create','conflict-remove')][string]$Action,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token)
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid fixture identifier.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent));$directory=Join-Path $workspace '.temp_files\icon-fixtures';$descriptorPath=Join-Path $directory "$Token.json";$files=Join-Path $directory "$Token-files"
if(-not [IO.Path]::GetFullPath($files).StartsWith($workspace+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture files escaped the workspace.'}
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
$command='"'+(Join-Path $env:SystemRoot 'System32\notepad.exe')+'" "%1" %*'
$fixtures=@(foreach($kind in @('One','Two','Found','Resource','Complex','Empty')){[ordered]@{kind=$kind;name="RustRegistry-E2E-Icon-$Token-$kind.exe";path=$(if($kind -eq 'Resource'){Join-Path $files 'container.dll,0'}else{Join-Path $files "$kind.ico"})}})
$names=@($fixtures|ForEach-Object{$_.name})
function Base($view){[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::$view)}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class IconFixtureReader {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]
    private static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out] byte[] data,ref uint size);
    public static string Read(SafeRegistryHandle key,string name,out uint type){uint size=0;int code=Query(key,name,IntPtr.Zero,out type,null,ref size);if(code!=0||size>262144)throw new InvalidOperationException("Cannot size value: "+code);byte[] data=new byte[size];code=Query(key,name,IntPtr.Zero,out type,data,ref size);if(code!=0||size>data.Length)throw new InvalidOperationException("Cannot read value: "+code);return Convert.ToBase64String(data,0,(int)size);}
}
'@
function Security($key){$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)}
function Values($key){@($key.GetValueNames()|Sort-Object|ForEach-Object{[uint32]$kind=0;$bytes=[IconFixtureReader]::Read($key.Handle,$_ ,[ref]$kind);[ordered]@{name=$_;kind=$kind;bytes=$bytes}})}
function Tree($key,$path='',$depth=0){if($depth -gt 4 -or $key.ValueCount -gt 8 -or $key.SubKeyCount -gt 4){throw 'Unexpected owned application tree.'};[ordered]@{path=$path;values=@(Values $key);security=Security $key};foreach($name in @($key.GetSubKeyNames()|Sort-Object)){$child=$key.OpenSubKey($name);try{Tree $child $(if($path){"$path\$name"}else{$name}) ($depth+1)}finally{$child.Dispose()}}}
function Views{foreach($view in @('Registry64','Registry32')){$base=Base $view;try{$root=$base.OpenSubKey('Software\Classes\Applications');if(-not $root){throw 'Existing Applications root is required.'};try{$applications=@(foreach($fixture in $fixtures){$key=$root.OpenSubKey($fixture.name);if($key){try{[ordered]@{kind=$fixture.kind;name=$fixture.name;exists=$true;nodes=@(Tree $key)}}finally{$key.Dispose()}}else{[ordered]@{kind=$fixture.kind;name=$fixture.name;exists=$false;nodes=@()}}});[ordered]@{view=$view;rootSecurity=Security $root;rootValues=@(Values $root);otherNames=@($root.GetSubKeyNames()|Sort-Object|Where-Object{$_ -notin $names});applications=$applications}}finally{$root.Dispose()}}finally{$base.Dispose()}}}
function Check-Roots($views,$baseline){foreach($view in $views){$before=$baseline|Where-Object{$_.view -ceq $view.view};foreach($property in @('rootSecurity','rootValues','otherNames')){if((ConvertTo-Json -InputObject $view.$property -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $before.$property -Depth 6 -Compress)){throw 'Unrelated application registrations changed. Cleanup will not overwrite them.'}}}}
function Marker($kind){"RustRegistry owned icon $Token $owner $kind"}
if($Action -eq 'create'){
    if((Test-Path -LiteralPath $descriptorPath) -or (Test-Path -LiteralPath $files)){throw 'Owned fixture collision.'}
    $baseline=@(Views);if(@($baseline.applications|Where-Object{$_.exists}).Count -ne 0){throw 'Owned registry fixture collision.'}
    New-Item -ItemType Directory -Path $files -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $files 'ownership.txt'),(Marker 'directory'),[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $files 'Found.ico'),(Marker 'Found'),[Text.UTF8Encoding]::new($false))
    $descriptor=[ordered]@{token=$Token;ownerSid=$owner;baseline=$baseline;originalViews=$null};[IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 14 -Compress),[Text.UTF8Encoding]::new($false))
    $base=Base 'Registry64';try{$root=$base.OpenSubKey('Software\Classes\Applications',$true);try{foreach($fixture in $fixtures){$key=$root.CreateSubKey($fixture.name);try{$key.SetValue('FriendlyAppName',"RustRegistry icon fixture $Token $($fixture.kind)",[Microsoft.Win32.RegistryValueKind]::String);if($fixture.kind -eq 'Two'){$key.SetValue('NoOpenWith','',[Microsoft.Win32.RegistryValueKind]::String)};$leaf=$key.CreateSubKey('DefaultIcon');try{if($fixture.kind -ne 'Empty'){$leaf.SetValue('',$fixture.path,$(if($fixture.kind -eq 'One'){[Microsoft.Win32.RegistryValueKind]::ExpandString}else{[Microsoft.Win32.RegistryValueKind]::String}))}}finally{$leaf.Dispose()};$leaf=$key.CreateSubKey('shell\open\command');try{$leaf.SetValue('',$command,[Microsoft.Win32.RegistryValueKind]::ExpandString);if($fixture.kind -eq 'Complex'){$leaf.SetValue('DelegateExecute','{11111111-1111-4111-8111-111111111111}',[Microsoft.Win32.RegistryValueKind]::String)}}finally{$leaf.Dispose()}}finally{$key.Dispose()}}}finally{$root.Dispose()}}finally{$base.Dispose()}
    $descriptor.originalViews=@(Views);[IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 14 -Compress),[Text.UTF8Encoding]::new($false))
}else{$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json;if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $owner -or $descriptor.originalViews.Count -ne 2){throw 'Owned fixture identity mismatch.'}}
if((Get-Content -LiteralPath (Join-Path $files 'ownership.txt') -Raw) -cne (Marker 'directory') -or (Get-Content -LiteralPath (Join-Path $files 'Found.ico') -Raw) -cne (Marker 'Found')){throw 'Owned file marker changed.'}
$one=Join-Path $files 'One.ico'
if($Action -eq 'conflict-create'){if(Test-Path -LiteralPath $one){throw 'Owned icon conflict already exists.'};[IO.File]::WriteAllText($one,(Marker 'One'),[Text.UTF8Encoding]::new($false))}
if($Action -eq 'conflict-remove'){if((Get-Content -LiteralPath $one -Raw) -cne (Marker 'One')){throw 'Owned icon conflict changed.'};Remove-Item -LiteralPath $one}
$views=@(Views);Check-Roots $views $descriptor.baseline
if($Action -eq 'cleanup'){
    foreach($view in $views){$original=$descriptor.originalViews|Where-Object{$_.view -ceq $view.view};foreach($application in $view.applications){$expected=($original.applications|Where-Object{$_.name -ceq $application.name})|ConvertTo-Json -Depth 14|ConvertFrom-Json;if($application.kind -in @('One','Two')){$leaf=$application.nodes|Where-Object{$_.path -ceq 'DefaultIcon'};if($leaf -and $leaf.values.Count -eq 0){($expected.nodes|Where-Object{$_.path -ceq 'DefaultIcon'}).values=@()}};if(($application|ConvertTo-Json -Depth 14 -Compress) -cne ($expected|ConvertTo-Json -Depth 14 -Compress)){throw 'Owned application metadata or permissions changed. Cleanup stopped.'}}}
    if(Test-Path -LiteralPath $one){throw 'Remove the owned conflict before cleanup.'}
    $base=Base 'Registry64';try{$root=$base.OpenSubKey('Software\Classes\Applications',$true);try{foreach($app in $views[0].applications){foreach($node in @($app.nodes|Sort-Object{$_.path.Length} -Descending)){$path=if($node.path){"$($app.name)\$($node.path)"}else{$app.name};$root.DeleteSubKey($path,$true)}}}finally{$root.Dispose()}}finally{$base.Dispose()}
    Remove-Item -LiteralPath (Join-Path $files 'Found.ico');Remove-Item -LiteralPath (Join-Path $files 'ownership.txt');Remove-Item -LiteralPath $files
    $views=@(Views);Check-Roots $views $descriptor.baseline
}
[ordered]@{token=$Token;search=$Token;fixtures=$fixtures;views=$views;oneFileExists=(Test-Path -LiteralPath $one)}|ConvertTo-Json -Depth 14 -Compress
