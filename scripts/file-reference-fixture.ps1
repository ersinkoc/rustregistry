param(
 [Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-file-create','conflict-file-remove','conflict-font-create','conflict-font-remove')][string]$Action,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token,
 [ValidateSet('font','h64','h32','w64','w32')][string]$Slot='font'
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid fixture identifier.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$directory=Join-Path $workspace '.temp_files\file-reference-fixtures'
$descriptorPath=Join-Path $directory "$Token.json"
$folder=Join-Path $directory $Token
$search=$Token.Replace('-','').Substring(0,24)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Explicitly elevated owned-fixture setup is required for machine help controls.'}
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
$marker="RustRegistryE2E-$Token"
$roots=@(
 [ordered]@{slot='font';hive='CurrentUser';view='Registry64';path='Software\Microsoft\Windows NT\CurrentVersion\Fonts'},
 [ordered]@{slot='machine_fonts';hive='LocalMachine';view='Registry64';path='Software\Microsoft\Windows NT\CurrentVersion\Fonts'},
 [ordered]@{slot='h64';hive='LocalMachine';view='Registry64';path='Software\Microsoft\Windows\HTML Help'},
 [ordered]@{slot='h32';hive='LocalMachine';view='Registry32';path='Software\Microsoft\Windows\HTML Help'},
 [ordered]@{slot='w64';hive='LocalMachine';view='Registry64';path='Software\Microsoft\Windows\Help'},
 [ordered]@{slot='w32';hive='LocalMachine';view='Registry32';path='Software\Microsoft\Windows\Help'}
)
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Security.AccessControl;using Microsoft.Win32;using Microsoft.Win32.SafeHandles;
public static class FileReferenceFixtureRegistry {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyExW")]static extern int Open(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle child);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out]byte[] data,ref uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegSetValueExW")]static extern int Set(SafeRegistryHandle key,string name,uint reserved,uint type,byte[] data,uint size);
 [DllImport("KtmW32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateTransaction(IntPtr attributes,IntPtr uow,uint options,uint isolation,uint flags,uint timeout,string description);
 [DllImport("KtmW32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool CommitTransaction(SafeFileHandle tx);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyTransactedW")]static extern int OpenTx(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle child,SafeFileHandle tx,IntPtr reserved);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegDeleteKeyTransactedW")]static extern int DeleteTx(SafeRegistryHandle parent,string name,uint access,uint reserved,SafeFileHandle tx,IntPtr extended);
 public static RegistryKey Child(RegistryKey parent,string name,RegistryView view,bool write,bool create){SafeRegistryHandle handle;int code=Open(parent.Handle,name,8,0x20019u|(write?6u:0u)|(view==RegistryView.Registry64?0x100u:0x200u),out handle);if(code==2){if(handle!=null)handle.Dispose();return create?parent.CreateSubKey(name,true):null;}if(code!=0){if(handle!=null)handle.Dispose();throw new InvalidOperationException("Cannot open fixture component: "+code);}return RegistryKey.FromHandle(handle,view);}
 public static object Raw(RegistryKey key,string name){uint type,size=0;int code=Query(key.Handle,name,IntPtr.Zero,out type,null,ref size);if(code!=0||size>262144)throw new InvalidOperationException("Cannot size fixture value: "+code);byte[] data=new byte[size];code=Query(key.Handle,name,IntPtr.Zero,out type,data,ref size);if(code!=0||size!=data.Length)throw new InvalidOperationException("Fixture value changed while reading.");return new{name=name,type=type,data=Convert.ToBase64String(data)};}
 public static void Put(RegistryKey key,string name,uint type,byte[] data){int code=Set(key.Handle,name,0,type,data,(uint)data.Length);if(code!=0)throw new InvalidOperationException("Cannot write owned fixture: "+code);}
 public static bool DeleteOwnedEmptyRoot(RegistryKey parent,string name,RegistryView view,string acl,AccessControlSections sections){using(SafeFileHandle tx=CreateTransaction(IntPtr.Zero,IntPtr.Zero,0,0,0,0,"RustRegistry owned empty-root cleanup")){if(tx.IsInvalid)throw new InvalidOperationException("Cleanup transactions are unavailable.");SafeRegistryHandle handle;uint arch=view==RegistryView.Registry64?0x100u:0x200u;int code=OpenTx(parent.Handle,name,8,0x20019u|arch,out handle,tx,IntPtr.Zero);if(code==2){if(handle!=null)handle.Dispose();return true;}if(code!=0)throw new InvalidOperationException("Cannot verify owned empty root: "+code);using(RegistryKey key=RegistryKey.FromHandle(handle,view)){if(key.GetValueNames().Length!=0||key.GetSubKeyNames().Length!=0||key.GetAccessControl(sections).GetSecurityDescriptorSddlForm(sections)!=acl)return false;}code=DeleteTx(parent.Handle,name,arch,0,tx,IntPtr.Zero);if(code!=0)throw new InvalidOperationException("Cannot remove owned empty root: "+code);if(!CommitTransaction(tx))throw new InvalidOperationException("Empty-root cleanup did not commit.");return true;}}
}
'@
function Root($config,[bool]$write,[bool]$create=$false){
 $rv=[Microsoft.Win32.RegistryView]::$($config.view);$key=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$($config.hive),$rv);$parts=$config.path.Split('\')
 for($i=0;$i -lt $parts.Length;$i++){try{$next=[FileReferenceFixtureRegistry]::Child($key,$parts[$i],$rv,($write -and $i -ge $parts.Length-2),($create -and $i -eq $parts.Length-1))}finally{$key.Dispose()};if(-not $next){return $null};$key=$next;if($key.GetValueNames() -contains 'SymbolicLinkValue'){$key.Dispose();throw 'Registry links are outside owned fixture scope.'}}
 return $key
}
function Values($key){$names=@($key.GetValueNames());[Array]::Sort($names,[StringComparer]::OrdinalIgnoreCase);@(foreach($name in $names){[FileReferenceFixtureRegistry]::Raw($key,$name)})}
function Snapshot($config){$key=Root $config $false;if(-not $key){return [ordered]@{slot=$config.slot;exists=$false;acl=$null;children=@();values=@();marker=$null}};try{$children=@($key.GetSubKeyNames());[Array]::Sort($children,[StringComparer]::OrdinalIgnoreCase);$m=$null;if($config.slot -ceq 'font' -and $children -ccontains $marker){$child=$key.OpenSubKey($marker);try{$m=[ordered]@{acl=$child.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);values=@(Values $child);children=@($child.GetSubKeyNames())}}finally{$child.Dispose()}};[ordered]@{slot=$config.slot;exists=$true;acl=$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);children=$children;values=@(Values $key);marker=$m}}finally{$key.Dispose()}}
function Views{@(foreach($config in $roots){Snapshot $config})}
function Equal($a,$b){($a|ConvertTo-Json -Depth 12 -Compress) -ceq ($b|ConvertTo-Json -Depth 12 -Compress)}
function Assert-Preserved($before,$after,$excluded){
 if(-not $before.exists){return};if(-not $after.exists -or $before.acl -cne $after.acl){throw 'An existing root or its permissions changed.'}
 foreach($name in $before.children){if($after.children -inotcontains $name){throw 'An existing child key was removed.'}}
 $actual=@{};foreach($v in $after.values){$actual[$v.name]=$v};foreach($v in $before.values){if($excluded -icontains $v.name){continue};if(-not $actual.ContainsKey($v.name) -or -not(Equal $v $actual[$v.name])){throw 'A pre-existing unrelated registration changed.'}}
}
function Put-Text($key,[string]$name,[string]$text,[int]$type=1){$data=if($type -eq 4){[BitConverter]::GetBytes([uint32]17)}else{[Text.Encoding]::Unicode.GetBytes($text+[char]0+[char]0)};[FileReferenceFixtureRegistry]::Put($key,$name,$type,$data)}
if($Action -ceq 'create'){
 if(Test-Path -LiteralPath $descriptorPath){throw 'Descriptor already exists.'};New-Item -ItemType Directory -Path $directory -Force|Out-Null;if(Test-Path -LiteralPath $folder){throw 'Owned folder already exists.'}
 foreach($config in $roots){$key=Root $config $true;if($key){$key.Dispose()}else{$parentConfig=[ordered]@{hive=$config.hive;view=$config.view;path=$config.path.Substring(0,$config.path.LastIndexOf('\'))};$parent=Root $parentConfig $true;if(-not $parent){throw 'An existing writable parent is required.'};$parent.Dispose()}}
 $baseline=@(Views);New-Item -ItemType Directory -Path $folder|Out-Null
 $windows=[Environment]::GetFolderPath('Windows');$foundFont=Join-Path $windows 'Fonts\arial.ttf';if(-not(Test-Path -LiteralPath $foundFont -PathType Leaf)){throw 'The standard existing font control is unavailable.'}
 $fixtures=@();$fontName="RustRegistry $search Font"
 foreach($kind in @('One','Two','Found','Relative','Windows','Collection','WrongType','Expanded','Counterpart')){
  $target=Join-Path $folder "$search-font-$kind.ttf";$data=$target;$type=1
  switch($kind){'Two'{$target=Join-Path $folder "$search-font-Two.otf";$data=$target};'Found'{$target=$foundFont;$data=$target};'Relative'{$data="$search-relative.ttf";$target=$null};'Windows'{$target=Join-Path $windows "Fonts\$search-missing.ttf";$data=$target};'Collection'{$target=Join-Path $folder "$search-collection.ttc";$data=$target};'WrongType'{$type=4};'Expanded'{$data="%LOCALAPPDATA%\$search\font.ttf";$target=$null}}
  $fixtures+=,[ordered]@{slot='font';kind=$kind;name="$fontName $kind (TrueType)";value=$data;type=$type;target=$target}
 }
 $counterpart=$fixtures|Where-Object{$_.slot -ceq 'font' -and $_.kind -ceq 'Counterpart'}
 $machineControl=[ordered]@{slot='machine_fonts';kind='Counterpart';name=$counterpart.name.Replace('(TrueType)','(OpenType)');value="$search-machine-control.ttf";type=1;target=$null};$fixtures+=,$machineControl
 foreach($slotName in @('h64','h32','w64','w32')){
  $ext=if($slotName.StartsWith('h')){'.chm'}else{'.hlp'}
  foreach($kind in @('One','Two','Found','Windows','Expanded','Relative','WrongType','WrongExtension')){
   $name="rr$search-$slotName-$kind$ext";$data=Join-Path $folder "$slotName-$kind";$type=1
   switch($kind){'Found'{New-Item -ItemType Directory -Path $data|Out-Null;[IO.File]::WriteAllBytes((Join-Path $data $name),[byte[]]@())};'Windows'{$data=Join-Path $windows 'Help'};'Expanded'{$data='%SystemRoot%\Help';$type=2};'Relative'{$data='relative\folder'};'WrongType'{$type=4};'WrongExtension'{$name="rr$search-$slotName-wrong.txt"}}
   $target=if($type -eq 1 -and [IO.Path]::IsPathRooted($data)){Join-Path $data $name}else{$null}
   $fixtures+=,[ordered]@{slot=$slotName;kind=$kind;name=$name;value=$data;type=$type;target=$target}
  }
 }
 foreach($config in $roots){$before=$baseline|Where-Object{$_.slot -ceq $config.slot};$names=@($fixtures|Where-Object{$_.slot -ceq $config.slot}|ForEach-Object{$_.name});if(@($before.values|Where-Object{$names -icontains $_.name}).Count -or $before.children -ccontains $marker){throw 'Owned registration names already exist.'}}
 $descriptor=[ordered]@{token=$Token;ownerSid=$sid;search=$search;folder=$folder;fixtures=$fixtures;baseline=$baseline;original=$null;fontConflict=$false}
 $descriptor|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 foreach($config in $roots){$key=Root $config $true $true;try{foreach($f in @($fixtures|Where-Object{$_.slot -ceq $config.slot})){Put-Text $key $f.name $f.value $f.type};if($config.slot -ceq 'font'){$child=$key.CreateSubKey($marker,$true);try{$child.SetValue('Keep',[uint32]17,[Microsoft.Win32.RegistryValueKind]::DWord)}finally{$child.Dispose()}}}finally{$key.Dispose()}}
 $descriptor.original=@(Views);$descriptor|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{
 if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned descriptor is missing.'};$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json
 if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $sid -or $descriptor.folder -cne $folder){throw 'Owned fixture identity mismatch.'};$fixtures=$descriptor.fixtures
}
$views=@(Views)
foreach($current in $views){$before=$descriptor.baseline|Where-Object{$_.slot -ceq $current.slot};Assert-Preserved $before $current @();$original=$descriptor.original|Where-Object{$_.slot -ceq $current.slot};if($current.slot -ceq 'font' -and -not(Equal $original.marker $current.marker)){throw 'Owned package child metadata or permissions changed.'}}
$one=$fixtures|Where-Object{$_.slot -ceq $Slot -and $_.kind -ceq 'One'}
if($Action -in @('conflict-file-create','conflict-file-remove')){
 $target=[IO.Path]::GetFullPath($one.target);if(-not $target.StartsWith($folder+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Conflict file escaped the owned folder.'}
 if($Action -ceq 'conflict-file-create'){if(Test-Path -LiteralPath $target){throw 'Conflict file already exists.'};[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))|Out-Null;[IO.File]::WriteAllBytes($target,[byte[]]@())}else{if(-not(Test-Path -LiteralPath $target) -or (Get-Item -LiteralPath $target).Length -ne 0){throw 'Owned conflict file changed.'};Remove-Item -LiteralPath $target;$parent=[IO.Path]::GetDirectoryName($target);if($parent -cne $folder -and @(Get-ChildItem -LiteralPath $parent).Count -eq 0){Remove-Item -LiteralPath $parent}}
}
if($Action -in @('conflict-font-create','conflict-font-remove')){
 $fontOne=$fixtures|Where-Object{$_.slot -ceq 'font' -and $_.kind -ceq 'One'};$config=$roots|Where-Object{$_.slot -ceq 'machine_fonts'};$key=Root $config $true
 try{if($Action -ceq 'conflict-font-create'){if($key.GetValueNames() -icontains $fontOne.name){throw 'Owned machine font conflict exists.'};Put-Text $key $fontOne.name "$search-conflict.ttf";$descriptor.fontConflict=$true}else{if(-not $descriptor.fontConflict){throw 'Owned font conflict was not created.'};$raw=[FileReferenceFixtureRegistry]::Raw($key,$fontOne.name);$expected=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("$search-conflict.ttf"+[char]0+[char]0));if($raw.type -ne 1 -or $raw.data -cne $expected){throw 'Owned font conflict changed.'};$key.DeleteValue($fontOne.name,$true);$descriptor.fontConflict=$false}}finally{$key.Dispose()}
 $descriptor|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
if($Action -ceq 'cleanup'){
 if($descriptor.fontConflict){throw 'Remove the owned font conflict before cleanup.'}
 $protected=@();foreach($current in $views){$original=$descriptor.original|Where-Object{$_.slot -ceq $current.slot};$owned=@($fixtures|Where-Object{$_.slot -ceq $current.slot});$names=@($owned|ForEach-Object{$_.name});foreach($f in $owned){$actual=@($current.values|Where-Object{$_.name -ceq $f.name});$expected=@($original.values|Where-Object{$_.name -ceq $f.name});if($f.kind -in @('One','Two') -and $actual.Count -eq 0){continue};if(-not(Equal $actual $expected)){throw 'Owned font/help control changed unexpectedly.'}};$protected+=,[ordered]@{slot=$current.slot;exists=$true;acl=$current.acl;children=@($current.children|Where-Object{$_ -cne $marker});values=@($current.values|Where-Object{$names -inotcontains $_.name})}}
 foreach($config in $roots){$key=Root $config $true;try{foreach($name in @($fixtures|Where-Object{$_.slot -ceq $config.slot}|ForEach-Object{$_.name})){$key.DeleteValue($name,$false)};if($config.slot -ceq 'font'){$key.DeleteSubKey($marker,$true)}}finally{$key.Dispose()}}
 foreach($file in @(Get-ChildItem -LiteralPath $folder -Recurse -File)){$allowed=@($fixtures|Where-Object{$_.kind -ceq 'Found' -and $_.slot -ne 'font'}|ForEach-Object{$_.target});if($allowed -inotcontains $file.FullName -or $file.Length -ne 0){throw 'Unknown owned-folder data; cleanup stopped.'};Remove-Item -LiteralPath $file.FullName}
 foreach($child in @(Get-ChildItem -LiteralPath $folder -Directory)){if(@(Get-ChildItem -LiteralPath $child.FullName).Count){throw 'Owned child folder is not empty.'};Remove-Item -LiteralPath $child.FullName};if(@(Get-ChildItem -LiteralPath $folder).Count){throw 'Owned folder is not empty.'};Remove-Item -LiteralPath $folder
 $views=@(Views);foreach($current in $views){$before=$protected|Where-Object{$_.slot -ceq $current.slot};Assert-Preserved $before $current @()}
 foreach($config in $roots){$baseline=$descriptor.baseline|Where-Object{$_.slot -ceq $config.slot};if($baseline.exists){continue};$key=Root $config $false;try{$empty=$key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0;$acl=$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)}finally{$key.Dispose()};if($empty){$parentConfig=[ordered]@{hive=$config.hive;view=$config.view;path=$config.path.Substring(0,$config.path.LastIndexOf('\'))};$parent=Root $parentConfig $true;try{[FileReferenceFixtureRegistry]::DeleteOwnedEmptyRoot($parent,$config.path.Split('\')[-1],[Microsoft.Win32.RegistryView]::$($config.view),$acl,$sections)|Out-Null}finally{$parent.Dispose()}}}
 $views=@(Views)
}
[ordered]@{token=$Token;search=$search;fixtures=$fixtures;views=$views;baseline=$descriptor.baseline}|ConvertTo-Json -Depth 14 -Compress
