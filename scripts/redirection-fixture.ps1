param(
    [Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-create','conflict-remove')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid fixture identifier.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$directory=Join-Path $workspace '.temp_files\redirection-fixtures'
$descriptorPath=Join-Path $directory "$Token.json"
$ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$search=$Token.Replace('-','').Substring(0,24)
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
public static class RedirectionFixtureRegistry {
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
function Id($kind){$sha=[Security.Cryptography.SHA256]::Create();try{$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Token-$kind"));[Guid]::new([byte[]]$digest[0..15]).ToString('B')}finally{$sha.Dispose()}}
function Root($hive,$view,$write=$false){$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive,[Microsoft.Win32.RegistryView]::$view);$classes=$null;try{$classes=$base.OpenSubKey('Software\Classes',$false);if(-not $classes){throw 'The fixed Classes root is required.'};$key=[RedirectionFixtureRegistry]::Child($classes,'CLSID',[Microsoft.Win32.RegistryView]::$view,$write);if(-not $key){throw 'Existing CLSID roots are required.'};return $key}finally{if($classes){$classes.Dispose()};$base.Dispose()}}
function Child($key,$name,$view,$write=$false){[RedirectionFixtureRegistry]::Child($key,$name,[Microsoft.Win32.RegistryView]::$view,$write)}
function Values($key){@($key.GetValueNames()|Sort-Object|ForEach-Object{[uint32]$kind=0;$bytes=[RedirectionFixtureRegistry]::Read($key.Handle,$_ ,[ref]$kind);[ordered]@{name=$_;kind=$kind;bytes=$bytes}})}
function Security($key){$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)}
function Tree($key,$view,$path='',$depth=0){if($depth -gt 2 -or $key.ValueCount -gt 4 -or $key.SubKeyCount -gt 3){throw 'Unexpected owned class tree.'};[ordered]@{path=$path;values=@(Values $key);security=Security $key};foreach($name in @($key.GetSubKeyNames()|Sort-Object)){$leaf=Child $key $name $view;try{Tree $leaf $view $(if($path){"$path\$name"}else{$name}) ($depth+1)}finally{$leaf.Dispose()}}}
if($Action -eq 'create'){
    if(Test-Path -LiteralPath $descriptorPath){throw 'Owned fixture collision.'}
    $machine=Root 'LocalMachine' 'Registry64';$user=Root 'CurrentUser' 'Registry64';$user32=Root 'CurrentUser' 'Registry32'
    try{$machineTarget=$null;foreach($id in @($machine.GetSubKeyNames()|Sort-Object)){if($id -notmatch '^\{[a-fA-F0-9-]{36}\}$' -or $id -eq '{00000000-0000-0000-0000-000000000000}'){continue};$one=Child $user $id 'Registry64';$two=Child $user32 $id 'Registry32';try{if(-not $one -and -not $two){$machineTarget=$id;break}}finally{if($one){$one.Dispose()};if($two){$two.Dispose()}}};if(-not $machineTarget){throw 'A read-only machine class control is required.'}}finally{$machine.Dispose();$user.Dispose();$user32.Dispose()}
}else{$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json;if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $ownerSid){throw 'Owned fixture identity mismatch.'};$machineTarget=$descriptor.machineTarget}
$fixtures=@(foreach($kind in @('One','Two','Found32','Found64','Machine','Complex','Malformed','Empty','WrongType','Self','Counterpart','ReadOnly32')){$own=Id "owner-$kind";$target=if($kind -eq 'Machine'){$machineTarget}elseif($kind -eq 'Self'){$own}else{Id "target-$kind"};[ordered]@{kind=$kind;owner=$own;target=$target;name="RustRegistry $search $kind";view=$(if($kind -eq 'ReadOnly32'){'Registry32'}else{'Registry64'})}})
$names=@($fixtures.owner);$targetIds=@($fixtures|Where-Object{$_.kind -notin @('Machine','Self')}|ForEach-Object{$_.target});$managed=@($names+$targetIds)
function Views{foreach($view in @('Registry64','Registry32')){$root=Root 'CurrentUser' $view;$machine=Root 'LocalMachine' $view;try{
    $classes=@(foreach($fixture in $fixtures){$key=Child $root $fixture.owner $view;try{[ordered]@{kind=$fixture.kind;owner=$fixture.owner;exists=($null -ne $key);nodes=@(if($key){Tree $key $view})}}finally{if($key){$key.Dispose()}}})
    $targets=@(foreach($fixture in @($fixtures|Where-Object{$_.kind -notin @('Machine','Self')})){$key=Child $root $fixture.target $view;try{[ordered]@{kind=$fixture.kind;target=$fixture.target;exists=($null -ne $key);nodes=@(if($key){Tree $key $view})}}finally{if($key){$key.Dispose()}}})
    $control=Child $machine $machineTarget $view;try{[ordered]@{view=$view;rootValues=@(Values $root);rootSecurity=Security $root;otherIds=@($root.GetSubKeyNames()|Sort-Object|Where-Object{$_ -notin $managed});machineRootValues=@(Values $machine);machineRootSecurity=Security $machine;machineIds=@($machine.GetSubKeyNames()|Sort-Object);machineControlExists=($null -ne $control);machineControlValues=@(if($control){Values $control});machineControlSecurity=$(if($control){Security $control}else{$null});classes=$classes;targets=$targets}}finally{if($control){$control.Dispose()}}
}finally{$root.Dispose();$machine.Dispose()}}}
function Check-Roots($views,$baseline){foreach($current in $views){$previous=$baseline|Where-Object{$_.view -ceq $current.view};foreach($property in @('rootValues','rootSecurity','otherIds','machineRootValues','machineRootSecurity','machineIds','machineControlExists','machineControlValues','machineControlSecurity')){if((ConvertTo-Json -InputObject $current.$property -Depth 8 -Compress) -cne (ConvertTo-Json -InputObject $previous.$property -Depth 8 -Compress)){throw 'Unrelated class-root or machine metadata changed. Nothing unrelated will be overwritten.'}}}}
if($Action -eq 'create'){
    foreach($hive in @('CurrentUser','LocalMachine')){foreach($view in @('Registry64','Registry32')){$root=Root $hive $view;try{foreach($id in $managed){$key=Child $root $id $view;if($key){$key.Dispose();throw 'Owned class or target collision.'}}}finally{$root.Dispose()}}}
    $baseline=@(Views);$descriptor=[ordered]@{token=$Token;ownerSid=$ownerSid;machineTarget=$machineTarget;baseline=$baseline;originalViews=$null};New-Item -ItemType Directory -Path $directory -Force|Out-Null;[IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 16 -Compress),[Text.UTF8Encoding]::new($false))
    foreach($fixture in $fixtures){$root=Root 'CurrentUser' $fixture.view $true;try{$key=$root.CreateSubKey($fixture.owner);try{$key.SetValue('',$fixture.name,[Microsoft.Win32.RegistryValueKind]::String);$leaf=$key.CreateSubKey('TreatAs');try{if($fixture.kind -ne 'Empty'){$leaf.SetValue('',$(if($fixture.kind -eq 'Malformed'){'%CLSID%'}else{$fixture.target}),$(if($fixture.kind -eq 'WrongType'){[Microsoft.Win32.RegistryValueKind]::ExpandString}else{[Microsoft.Win32.RegistryValueKind]::String}))}}finally{$leaf.Dispose()};if($fixture.kind -eq 'Complex'){$auto=$key.CreateSubKey('AutoTreatAs');try{$auto.SetValue('',$fixture.target,[Microsoft.Win32.RegistryValueKind]::String)}finally{$auto.Dispose()}}}finally{$key.Dispose()}}finally{$root.Dispose()}}
    foreach($kind in @('Found32','Found64')){$f=$fixtures|Where-Object{$_.kind -ceq $kind};$view=if($kind -eq 'Found32'){'Registry32'}else{'Registry64'};$root=Root 'CurrentUser' $view $true;try{$key=$root.CreateSubKey($f.target);try{$key.SetValue('',"RustRegistry $Token target $kind",[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}finally{$root.Dispose()}}
    $f=$fixtures|Where-Object{$_.kind -eq 'Counterpart'};$root=Root 'CurrentUser' 'Registry32' $true;try{$key=$root.CreateSubKey($f.owner);try{$key.SetValue('',"RustRegistry $Token 32-bit counterpart",[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}finally{$root.Dispose()}
    $descriptor.originalViews=@(Views);[IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 16 -Compress),[Text.UTF8Encoding]::new($false))
}
if($descriptor.originalViews.Count -ne 2){throw 'Owned fixture setup is incomplete.'}
$one=$fixtures|Where-Object{$_.kind -eq 'One'}
if($Action -in @('conflict-create','conflict-remove')){$root=Root 'CurrentUser' 'Registry32' $true;try{$key=Child $root $one.target 'Registry32';if($Action -eq 'conflict-create'){if($key){$key.Dispose();throw 'Owned target conflict already exists.'};$key=$root.CreateSubKey($one.target);try{$key.SetValue('',"RustRegistry $Token conflict",[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}else{if(-not $key){throw 'Owned conflict is missing.'};try{if($key.SubKeyCount -ne 0 -or $key.ValueCount -ne 1 -or $key.GetValue('') -cne "RustRegistry $Token conflict"){throw 'Owned conflict changed.'}}finally{$key.Dispose()};$root.DeleteSubKey($one.target,$true)}}finally{$root.Dispose()}}
$views=@(Views);Check-Roots $views $descriptor.baseline
if($Action -eq 'cleanup'){
    foreach($current in $views){$original=$descriptor.originalViews|Where-Object{$_.view -ceq $current.view};if(($current.targets|ConvertTo-Json -Depth 16 -Compress) -cne ($original.targets|ConvertTo-Json -Depth 16 -Compress)){throw 'Owned target controls changed. Cleanup stopped.'};foreach($class in $current.classes){$expected=($original.classes|Where-Object{$_.owner -ceq $class.owner})|ConvertTo-Json -Depth 16|ConvertFrom-Json;if($current.view -ceq 'Registry64' -and $class.kind -in @('One','Two')){$actual=@(($class.nodes|Where-Object{$_.path -ceq 'TreatAs'}).values);if($actual.Count -eq 0){($expected.nodes|Where-Object{$_.path -ceq 'TreatAs'}).values=@()}};if(($class|ConvertTo-Json -Depth 16 -Compress) -cne ($expected|ConvertTo-Json -Depth 16 -Compress)){throw 'Owned class metadata, values or permissions changed. Cleanup stopped.'}}}
    foreach($view in @('Registry64','Registry32')){$root=Root 'CurrentUser' $view $true;try{$snapshot=$views|Where-Object{$_.view -ceq $view};foreach($class in @($snapshot.classes|Where-Object{$_.exists})){$key=Child $root $class.owner $view $true;try{foreach($name in @($key.GetSubKeyNames())){$key.DeleteSubKey($name,$true)}}finally{$key.Dispose()};$root.DeleteSubKey($class.owner,$true)};foreach($target in @($snapshot.targets|Where-Object{$_.exists})){$root.DeleteSubKey($target.target,$true)}}finally{$root.Dispose()}}
    $views=@(Views);Check-Roots $views $descriptor.baseline
}
[ordered]@{token=$Token;search=$search;fixtures=$fixtures;views=$views}|ConvertTo-Json -Depth 16 -Compress
