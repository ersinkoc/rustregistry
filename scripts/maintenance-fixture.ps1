param([Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-create','conflict-remove','history-inspect')][string]$Action,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid fixture identifier.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$directory=Join-Path $workspace '.temp_files\maintenance-fixtures'
$descriptorPath=Join-Path $directory "$Token.json"
$folder=Join-Path $directory $Token
$ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$search=$Token.Replace('-','').Substring(0,24)
$cachePath='Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
public static class MaintenanceFixtureRegistry {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyExW")] static extern int Open(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle key);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")] static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out] byte[] data,ref uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegSetValueExW")] static extern int Set(SafeRegistryHandle key,string name,uint reserved,uint type,byte[] data,uint size);
 public static RegistryKey Child(RegistryKey parent,string name,RegistryView view,bool write,bool classesAlias){SafeRegistryHandle handle;int code=Open(parent.Handle,name,classesAlias?0u:8u,0x20019u|(write?2u:0u)|(view==RegistryView.Registry64?0x100u:0x200u),out handle);if(code==2){if(handle!=null)handle.Dispose();return null;}if(code!=0){if(handle!=null)handle.Dispose();throw new InvalidOperationException("Cannot open registry component: "+code);}RegistryKey key=RegistryKey.FromHandle(handle,view);return key;}
 public static object Raw(RegistryKey key,string name){uint type,size=0;int code=Query(key.Handle,name,IntPtr.Zero,out type,null,ref size);if(code!=0||size>262144)throw new InvalidOperationException("Cannot size registry value: "+code);byte[] data=new byte[size];code=Query(key.Handle,name,IntPtr.Zero,out type,data,ref size);if(code!=0||size!=data.Length)throw new InvalidOperationException("Registry value changed while reading.");return new {name=name,type=type,data=Convert.ToBase64String(data)};}
 public static void Put(RegistryKey key,string name,uint type,byte[] data){int code=Set(key.Handle,name,0,type,data,(uint)data.Length);if(code!=0)throw new InvalidOperationException("Cannot create owned fixture value: "+code);}
}
'@
function Root([string]$path,[string]$view,[bool]$write){$rv=[Microsoft.Win32.RegistryView]::$view;$key=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,$rv);foreach($part in $path.Split('\')){try{$next=[MaintenanceFixtureRegistry]::Child($key,$part,$rv,($write -and $part -ceq $path.Split('\')[-1]),($part -ceq 'Classes' -and $path.StartsWith('Software\Classes\')))}finally{$key.Dispose()};if(-not $next){return $null};$key=$next;if($key.GetValueNames() -contains 'SymbolicLinkValue'){$key.Dispose();throw ('Registry link at '+$view+' '+$part+' is outside fixture scope.')}};return $key}
function Snapshot([string]$path,[string]$view){$key=Root $path $view $false;if(-not $key){return [ordered]@{view=$view;exists=$false;acl=$null;children=@();values=@()}};try{$names=@($key.GetValueNames());[Array]::Sort($names,[StringComparer]::OrdinalIgnoreCase);$children=@($key.GetSubKeyNames());[Array]::Sort($children,[StringComparer]::OrdinalIgnoreCase);[ordered]@{view=$view;exists=$true;acl=$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);children=$children;values=@(foreach($name in $names){[MaintenanceFixtureRegistry]::Raw($key,$name)})}}finally{$key.Dispose()}}
function Views {foreach($view in @('Registry64','Registry32')){Snapshot $cachePath $view}}
function Equal($a,$b){($a|ConvertTo-Json -Depth 12 -Compress) -ceq ($b|ConvertTo-Json -Depth 12 -Compress)}
function Assert-Preserved($before,$after){
 if($before.acl -cne $after.acl -or -not(Equal $before.children $after.children)){throw 'Cache permissions or child keys changed.'}
 $actual=@{};foreach($v in $after.values){$actual[$v.name]=$v}
 foreach($v in $before.values){if(-not $actual.ContainsKey($v.name) -or -not(Equal $v $actual[$v.name])){throw 'A pre-existing unrelated cache value was removed or changed.'}}
}
if($Action -ceq 'history-inspect'){[ordered]@{roots=@(foreach($name in @('RunMRU','TypedPaths')){[ordered]@{name=$name;snapshot=(Snapshot "Software\Microsoft\Windows\CurrentVersion\Explorer\$name" 'Registry64')}})}|ConvertTo-Json -Depth 12 -Compress;exit}
if($Action -ceq 'create'){
 if(Test-Path -LiteralPath $descriptorPath){throw 'Owned fixture descriptor already exists.'}
 New-Item -ItemType Directory -Path $directory -Force|Out-Null
 if(Test-Path -LiteralPath $folder){throw 'Owned fixture folder already exists.'}
 $baseline=@(Views);if(@($baseline|Where-Object{-not $_.exists -or $_.children.Count}).Count){throw 'An existing flat MUI cache key is required.'}
 New-Item -ItemType Directory -Path $folder|Out-Null
 $existing=Join-Path $folder "$search-existing.exe";[IO.File]::WriteAllBytes($existing,[byte[]]@())
 $fixtures=@(
  [ordered]@{kind='One';item=(Join-Path $folder "$search-one.exe");suffixes=@('.FriendlyAppName','.ApplicationCompany');type=1},
  [ordered]@{kind='Two';item=(Join-Path $folder "$search-two.exe");suffixes=@('.FriendlyAppName','.ApplicationCompany');type=1},
  [ordered]@{kind='Existing';item=$existing;suffixes=@('.FriendlyAppName');type=1},
  [ordered]@{kind='Windows';item=(Join-Path ([Environment]::GetFolderPath('Windows')) "$search-protected.exe");suffixes=@('.FriendlyAppName');type=1},
  [ordered]@{kind='Complex';item=(Join-Path $folder "$search-complex.exe");suffixes=@('.FriendlyAppName','.FutureField');type=1},
  [ordered]@{kind='Malformed';item=(Join-Path $folder "$search-malformed.exe");suffixes=@('.FriendlyAppName');type=4},
  [ordered]@{kind='Network';item="\\rustregistry-$search\offline\$search-network.exe";suffixes=@('.FriendlyAppName');type=1},
  [ordered]@{kind='Relative';item="$search-relative.exe";suffixes=@('.FriendlyAppName');type=1}
 )
 $names=@(foreach($f in $fixtures){foreach($suffix in $f.suffixes){$f.item+$suffix}})
 if(@($baseline[0].values|Where-Object{$names -icontains $_.name}).Count){throw 'Owned cache names already exist.'}
 $descriptor=[ordered]@{token=$Token;ownerSid=$ownerSid;search=$search;folder=$folder;fixtures=$fixtures;names=$names;baseline=$baseline;original=$null}
 $descriptor|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 $key=Root $cachePath 'Registry64' $true
 try{foreach($f in $fixtures){foreach($suffix in $f.suffixes){$text=if($f.kind -ceq 'One' -and $suffix -ceq '.ApplicationCompany'){''}else{"Owned $search $($f.kind)"};$data=if($f.type -eq 4){[BitConverter]::GetBytes([uint32]17)}else{[Text.Encoding]::Unicode.GetBytes($text+[char]0+[char]0)};[MaintenanceFixtureRegistry]::Put($key,($f.item+$suffix),$f.type,$data)}}}finally{$key.Dispose()}
 $descriptor.original=@(Views);$descriptor|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{
 if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned descriptor is missing.'}
 $descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json
 if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $ownerSid -or $descriptor.folder -cne $folder){throw 'Owned fixture identity does not match.'}
 $fixtures=$descriptor.fixtures;$names=$descriptor.names
}
$views=@(Views)
foreach($view in $views){$baseline=$descriptor.baseline|Where-Object{$_.view -ceq $view.view};Assert-Preserved $baseline $view}
if($Action -in @('conflict-create','conflict-remove')){
 $one=($fixtures|Where-Object{$_.kind -ceq 'One'}).item
 if([IO.Path]::GetFullPath($one).Substring(0,$folder.Length+1) -cne ($folder+'\')){throw 'Owned conflict path escaped its fixture folder.'}
 if($Action -ceq 'conflict-create'){if(Test-Path -LiteralPath $one){throw 'Conflict target already exists.'};[IO.File]::WriteAllBytes($one,[byte[]]@())}else{if(-not(Test-Path -LiteralPath $one) -or (Get-Item -LiteralPath $one).Length -ne 0){throw 'Owned inert conflict target changed.'};Remove-Item -LiteralPath $one}
}
if($Action -ceq 'cleanup'){
 $protected=@(foreach($view in $views){[ordered]@{view=$view.view;acl=$view.acl;children=$view.children;values=@($view.values|Where-Object{$names -inotcontains $_.name})}})
 foreach($view in $views){$original=$descriptor.original|Where-Object{$_.view -ceq $view.view};foreach($f in $fixtures){$fixtureNames=@($f.suffixes|ForEach-Object{$f.item+$_});$actual=@($view.values|Where-Object{$fixtureNames -icontains $_.name});$expected=@($original.values|Where-Object{$names -icontains $_.name -and $_.name.StartsWith($f.item+'.',[StringComparison]::OrdinalIgnoreCase)});if($f.kind -in @('One','Two') -and $actual.Count -eq 0){continue};if(-not(Equal $actual $expected)){throw 'Owned fixture values changed unexpectedly; cleanup stopped.'}}}
 $key=Root $cachePath 'Registry64' $true;try{foreach($name in $names){$key.DeleteValue($name,$false)}}finally{$key.Dispose()}
 foreach($file in @(Get-ChildItem -LiteralPath $folder -File)){if($file.Name -notin @("$search-existing.exe","$search-one.exe") -or $file.Length -ne 0){throw 'Unknown fixture file; cleanup stopped.'};Remove-Item -LiteralPath $file.FullName}
 if(@(Get-ChildItem -LiteralPath $folder).Count){throw 'Owned folder is not empty.'};Remove-Item -LiteralPath $folder
 $views=@(Views);foreach($view in $views){$baseline=$protected|Where-Object{$_.view -ceq $view.view};Assert-Preserved $baseline $view;if(@($view.values|Where-Object{$names -icontains $_.name}).Count){throw 'Owned cache values remain after cleanup.'}}
}
[ordered]@{token=$Token;search=$search;fixtures=$fixtures;views=$views}|ConvertTo-Json -Depth 12 -Compress
