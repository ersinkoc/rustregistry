param([Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-create','conflict-remove')][string]$Action,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token)
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid fixture identifier.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent));$directory=Join-Path $workspace '.temp_files\menu-fixtures';$descriptorPath=Join-Path $directory "$Token.json";$files=Join-Path $directory "$Token-files"
if(-not [IO.Path]::GetFullPath($files).StartsWith($workspace+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture files escaped the workspace.'}
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
$fixtures=@(foreach($kind in @('One','Two','Found','Delegated','Hidden','Protected','Empty')){$location=if($kind -eq 'Two'){'directory_background'}else{'files'};$verb="RR.$($Token.Replace('-','')).$kind";if($kind -eq 'Protected'){$verb="Windows.$verb"};[ordered]@{kind=$kind;location=$location;verb=$verb;name=$verb;file=(Join-Path $files "$kind.exe");command=('"'+(Join-Path $files "$kind.exe")+'" "%1" %*')}})
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
public static class MenuFixtureRegistry {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]
    private static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out] byte[] data,ref uint size);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyExW")]
    private static extern int Open(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle key);
    public static RegistryKey Child(RegistryKey parent,string name,RegistryView view,bool write){
        SafeRegistryHandle handle;int code=Open(parent.Handle,name,8,0x20019u|(write?6u:0u)|(view==RegistryView.Registry64?0x100u:0x200u),out handle);
        if(code==2){if(handle!=null)handle.Dispose();return null;}if(code!=0){if(handle!=null)handle.Dispose();throw new InvalidOperationException("Cannot open registry component: "+code);}
        RegistryKey key=RegistryKey.FromHandle(handle,view);uint size=0,type;code=Query(handle,"SymbolicLinkValue",IntPtr.Zero,out type,null,ref size);
        if((code==0&&type==6)||(code!=0&&code!=2)){key.Dispose();throw new InvalidOperationException("Untrusted or inaccessible registry link metadata.");}return key;
    }
    public static string Read(SafeRegistryHandle key,string name,out uint type){uint size=0;int code=Query(key,name,IntPtr.Zero,out type,null,ref size);if(code!=0||size>262144)throw new InvalidOperationException("Cannot size value: "+code);byte[] data=new byte[size];code=Query(key,name,IntPtr.Zero,out type,data,ref size);if(code!=0||size>data.Length)throw new InvalidOperationException("Cannot read value: "+code);return Convert.ToBase64String(data,0,(int)size);}
}
'@
$script:created=@()
function Parts($location){if($location -ceq 'files'){@('*','shell')}elseif($location -ceq 'directory_background'){@('Directory','Background','shell')}else{throw 'Invalid fixed menu location.'}}
function Open-Path($hive,$view,$parts,$write=$false,$create=$false){
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive,[Microsoft.Win32.RegistryView]::$view)
    try{$key=$base.OpenSubKey('Software\Classes',$write)}finally{$base.Dispose()}
    if(-not $key){throw 'The existing Classes root is required.'}
    $relative=@()
    try{foreach($part in $parts){$relative+=@($part);$child=[MenuFixtureRegistry]::Child($key,$part,[Microsoft.Win32.RegistryView]::$view,$write);if(-not $child){if(-not $create){$key.Dispose();return $null};$made=$key.CreateSubKey($part);$made.Dispose();$script:created+=@(($relative -join '\'));$child=[MenuFixtureRegistry]::Child($key,$part,[Microsoft.Win32.RegistryView]::$view,$write);if(-not $child){throw 'Created menu component is missing.'}};$key.Dispose();$key=$child};return $key}catch{$key.Dispose();throw}
}
function Security($key){$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)}
function Values($key){@($key.GetValueNames()|Sort-Object|ForEach-Object{[uint32]$kind=0;$bytes=[MenuFixtureRegistry]::Read($key.Handle,$_ ,[ref]$kind);[ordered]@{name=$_;kind=$kind;bytes=$bytes}})}
function Tree($key,$view,$path='',$depth=0){if($depth -gt 3 -or $key.ValueCount -gt 8 -or $key.SubKeyCount -gt 4){throw 'Unexpected owned menu tree.'};[ordered]@{path=$path;values=@(Values $key);security=Security $key};foreach($name in @($key.GetSubKeyNames()|Sort-Object)){$child=[MenuFixtureRegistry]::Child($key,$name,[Microsoft.Win32.RegistryView]::$view,$false);try{Tree $child $view $(if($path){"$path\$name"}else{$name}) ($depth+1)}finally{$child.Dispose()}}}
function Views{foreach($view in @('Registry64','Registry32')){
    $roots=@(foreach($location in @('files','directory_background')){
        $root=Open-Path 'CurrentUser' $view (Parts $location);$machine=Open-Path 'LocalMachine' $view (Parts $location)
        try{$owned=@($fixtures|Where-Object{$_.location -ceq $location});$menus=@(foreach($fixture in $owned){$key=if($root){[MenuFixtureRegistry]::Child($root,$fixture.verb,[Microsoft.Win32.RegistryView]::$view,$false)}else{$null};if($key){try{[ordered]@{kind=$fixture.kind;verb=$fixture.verb;exists=$true;nodes=@(Tree $key $view)}}finally{$key.Dispose()}}else{[ordered]@{kind=$fixture.kind;verb=$fixture.verb;exists=$false;nodes=@()}}});[ordered]@{location=$location;exists=($null -ne $root);security=$(if($root){Security $root}else{$null});values=@(if($root){Values $root});otherNames=@(if($root){$root.GetSubKeyNames()|Sort-Object|Where-Object{$_ -notin $owned.verb}});machineExists=($null -ne $machine);machineValues=@(if($machine){Values $machine});machineSecurity=$(if($machine){Security $machine}else{$null});machineNames=@(if($machine){$machine.GetSubKeyNames()|Sort-Object});menus=$menus}}finally{if($root){$root.Dispose()};if($machine){$machine.Dispose()}}
    });[ordered]@{view=$view;roots=$roots}
}}
function Check-Roots($views,$baseline){foreach($view in $views){$before=$baseline|Where-Object{$_.view -ceq $view.view};foreach($current in $view.roots){$previous=$before.roots|Where-Object{$_.location -ceq $current.location};foreach($property in @('values','otherNames','machineExists','machineValues','machineSecurity','machineNames')){$left=$current.$property;$right=$previous.$property;if($property -in @('values','otherNames','machineValues','machineNames')){$left=@($left|Where-Object{$null -ne $_});$right=@($right|Where-Object{$null -ne $_})};if((ConvertTo-Json -InputObject $left -Depth 8 -Compress) -cne (ConvertTo-Json -InputObject $right -Depth 8 -Compress)){throw 'Unrelated menu/root metadata changed. No unrelated data will be overwritten.'}};if($previous.exists -and ($current.security -cne $previous.security -or -not $current.exists)){throw 'Existing root permissions or presence changed.'}}}}
function Marker($kind){"RustRegistry owned menu $Token $owner $kind"}
if($Action -eq 'create'){
    if((Test-Path -LiteralPath $descriptorPath) -or (Test-Path -LiteralPath $files)){throw 'Owned fixture collision.'}
    $baseline=@(Views);if(@($baseline.roots.menus|Where-Object{$_.exists}).Count -ne 0){throw 'Owned registry fixture collision.'}
    New-Item -ItemType Directory -Path $files -Force|Out-Null;[IO.File]::WriteAllText((Join-Path $files 'ownership.txt'),(Marker 'directory'),[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $files 'Found.exe'),(Marker 'Found'),[Text.UTF8Encoding]::new($false))
    $descriptor=[ordered]@{token=$Token;ownerSid=$owner;baseline=$baseline;originalViews=$null;created=@()};[IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 16 -Compress),[Text.UTF8Encoding]::new($false))
    foreach($fixture in $fixtures){$root=Open-Path 'CurrentUser' 'Registry64' (Parts $fixture.location) $true $true;try{$key=$root.CreateSubKey($fixture.verb);try{$key.SetValue('MUIVerb',"RustRegistry test menu $Token $($fixture.kind)",[Microsoft.Win32.RegistryValueKind]::String);$key.SetValue('Icon','C:\Preserved\menu.exe,0',[Microsoft.Win32.RegistryValueKind]::String);$key.SetValue('Extended','',[Microsoft.Win32.RegistryValueKind]::String);if($fixture.kind -eq 'Hidden'){$key.SetValue('ProgrammaticAccessOnly','',[Microsoft.Win32.RegistryValueKind]::String)};$command=$key.CreateSubKey('command');try{if($fixture.kind -ne 'Empty'){$command.SetValue('',$fixture.command,$(if($fixture.kind -eq 'One'){[Microsoft.Win32.RegistryValueKind]::ExpandString}else{[Microsoft.Win32.RegistryValueKind]::String}))};if($fixture.kind -eq 'Delegated'){$command.SetValue('DelegateExecute','{11111111-1111-4111-8111-111111111111}',[Microsoft.Win32.RegistryValueKind]::String)}}finally{$command.Dispose()}}finally{$key.Dispose()}}finally{$root.Dispose()}}
    $descriptor.created=@($script:created|Select-Object -Unique);$descriptor.originalViews=@(Views);[IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 16 -Compress),[Text.UTF8Encoding]::new($false))
}else{$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json;if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $owner -or $descriptor.originalViews.Count -ne 2){throw 'Owned fixture identity mismatch.'}}
if((Get-Content -LiteralPath (Join-Path $files 'ownership.txt') -Raw) -cne (Marker 'directory') -or (Get-Content -LiteralPath (Join-Path $files 'Found.exe') -Raw) -cne (Marker 'Found')){throw 'Owned file marker changed.'}
$one=Join-Path $files 'One.exe'
if($Action -eq 'conflict-create'){if(Test-Path -LiteralPath $one){throw 'Owned executable conflict already exists.'};[IO.File]::WriteAllText($one,(Marker 'One'),[Text.UTF8Encoding]::new($false))}
if($Action -eq 'conflict-remove'){if((Get-Content -LiteralPath $one -Raw) -cne (Marker 'One')){throw 'Owned executable conflict changed.'};Remove-Item -LiteralPath $one}
$views=@(Views);Check-Roots $views $descriptor.baseline
if($Action -eq 'cleanup'){
    foreach($view in $views){$original=$descriptor.originalViews|Where-Object{$_.view -ceq $view.view};foreach($current in $view.roots){$previous=$original.roots|Where-Object{$_.location -ceq $current.location};foreach($menu in $current.menus){$expected=($previous.menus|Where-Object{$_.verb -ceq $menu.verb})|ConvertTo-Json -Depth 16|ConvertFrom-Json;if($menu.kind -in @('One','Two')){$values=@(($menu.nodes|Where-Object{$_.path -ceq ''}).values|Where-Object{$_.name -ieq 'ProgrammaticAccessOnly'});if($values.Count -eq 1 -and $values[0].kind -eq 1 -and $values[0].bytes -ceq 'AAA='){($expected.nodes|Where-Object{$_.path -ceq ''}).values=@(@(($expected.nodes|Where-Object{$_.path -ceq ''}).values)+$values|Sort-Object name)}};if(($menu|ConvertTo-Json -Depth 16 -Compress) -cne ($expected|ConvertTo-Json -Depth 16 -Compress)){throw 'Owned command, metadata, visibility or permissions changed. Cleanup stopped.'}}}}
    if(Test-Path -LiteralPath $one){throw 'Remove the owned conflict before cleanup.'}
    foreach($fixture in $fixtures){$root=Open-Path 'CurrentUser' 'Registry64' (Parts $fixture.location) $true;try{$root.DeleteSubKey("$($fixture.verb)\command",$true);$root.DeleteSubKey($fixture.verb,$true)}finally{$root.Dispose()}}
    foreach($relative in @($descriptor.created|Sort-Object Length -Descending)){$parts=@($relative.Split('\'));$leaf=$parts[-1];$parentParts=if($parts.Count -gt 1){@($parts[0..($parts.Count-2)])}else{@()};$parent=Open-Path 'CurrentUser' 'Registry64' $parentParts $true;try{$key=[MenuFixtureRegistry]::Child($parent,$leaf,[Microsoft.Win32.RegistryView]::Registry64,$false);try{if(-not $key -or $key.SubKeyCount -ne 0 -or $key.ValueCount -ne 0){throw 'An owned created root is no longer empty. It will not be removed.'}}finally{if($key){$key.Dispose()}};$parent.DeleteSubKey($leaf,$true)}finally{$parent.Dispose()}}
    Remove-Item -LiteralPath (Join-Path $files 'Found.exe');Remove-Item -LiteralPath (Join-Path $files 'ownership.txt');Remove-Item -LiteralPath $files;$views=@(Views);Check-Roots $views $descriptor.baseline
}
[ordered]@{token=$Token;search=$Token.Replace('-','');fixtures=$fixtures;views=$views;oneFileExists=(Test-Path -LiteralPath $one)}|ConvertTo-Json -Depth 16 -Compress
