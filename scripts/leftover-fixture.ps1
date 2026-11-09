param(
 [Parameter(Mandatory=$true)][ValidateSet('create','inspect','conflict-directory-create','conflict-directory-remove','conflict-metadata-create','conflict-metadata-remove','conflict-duplicate-create','conflict-duplicate-remove','conflict-default-create','conflict-default-remove','conflict-path-create','conflict-path-remove','cleanup')][string]$Action,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token,
 [switch]$PathList
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid owned leftover token.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$directory=Join-Path $workspace '.temp_files\leftover-fixtures'
$folder=Join-Path $directory $Token
$retainedDirectory=Join-Path $folder 'Retained'
$retainedTail=$retainedDirectory+';relative;%PRESERVE%\Keep;\\server\share'
$descriptorPath=Join-Path $directory "$Token.json"
$search=$Token.Replace('-','').Substring(0,24)
$apps='Software\Microsoft\Windows\CurrentVersion\App Paths'
$uninstall='Software\Microsoft\Windows\CurrentVersion\Uninstall'
$cache='Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using Microsoft.Win32;using Microsoft.Win32.SafeHandles;
public static class LeftoverFixtureRaw {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyExW")]static extern int Open(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle child);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out]byte[] data,ref uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegSetValueExW")]static extern int Set(SafeRegistryHandle key,string name,uint reserved,uint type,byte[] data,uint size);
 [DllImport("KtmW32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern SafeFileHandle CreateTransaction(IntPtr attributes,IntPtr uow,uint options,uint isolation,uint flags,uint timeout,string description);
 [DllImport("KtmW32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]public static extern bool CommitTransaction(SafeFileHandle tx);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyTransactedW")]static extern int OpenTx(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle child,SafeFileHandle tx,IntPtr reserved);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegDeleteKeyTransactedW")]static extern int DeleteTx(SafeRegistryHandle parent,string name,uint access,uint reserved,SafeFileHandle tx,IntPtr extended);
 public static RegistryKey Child(RegistryKey parent,string name,bool write,SafeFileHandle tx){SafeRegistryHandle handle;uint access=0x20119u|(write?6u:0u);int code=tx==null?Open(parent.Handle,name,8,access,out handle):OpenTx(parent.Handle,name,8,access,out handle,tx,IntPtr.Zero);if(code==2){if(handle!=null)handle.Dispose();return null;}if(code!=0){if(handle!=null)handle.Dispose();throw new InvalidOperationException("Cannot open leftover fixture component: "+code);}return RegistryKey.FromHandle(handle,RegistryView.Registry64);}
 public static object Raw(RegistryKey key,string name){uint type,size=0;int code=Query(key.Handle,name,IntPtr.Zero,out type,null,ref size);if(code!=0||size>262144)throw new InvalidOperationException("Cannot size owned registry value: "+code);byte[] data=new byte[size];code=Query(key.Handle,name,IntPtr.Zero,out type,data,ref size);if(code!=0||size!=data.Length)throw new InvalidOperationException("Registry value changed while reading.");return new{name=name,type=type,data=Convert.ToBase64String(data)};}
 public static void Put(RegistryKey key,string name,uint type,byte[] data){int code=Set(key.Handle,name,0,type,data,(uint)data.Length);if(code!=0)throw new InvalidOperationException("Cannot write owned leftover control: "+code);}
 public static void Delete(RegistryKey parent,string name,SafeFileHandle tx){int code=DeleteTx(parent.Handle,name,0x100,0,tx,IntPtr.Zero);if(code!=0)throw new InvalidOperationException("Conditional leftover fixture cleanup failed: "+code);}
}
'@
function Key([string]$path,[bool]$write=$false,$tx=$null){
 $key=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64);$parts=$path.Split('\');$start=0
 # The fixed Windows-managed user Classes alias is the same trusted entry point used by the application/cache fixtures.
 if($path.StartsWith('Software\Classes\',[StringComparison]::OrdinalIgnoreCase)){try{$next=$key.OpenSubKey('Software\Classes')}finally{$key.Dispose()};$key=$next;$start=2}
 for($i=$start;$i -lt $parts.Length;$i++){try{$next=[LeftoverFixtureRaw]::Child($key,$parts[$i],($write -and $i -eq $parts.Length-1),$tx)}finally{$key.Dispose()};if(-not$next){return $null};$key=$next;if($key.GetValueNames() -icontains 'SymbolicLinkValue'){$key.Dispose();throw 'Registry links are outside leftover fixture scope.'}}
 return $key
}
function Flat([string]$path,$tx=$null){$key=Key $path $false $tx;if(-not$key){return $null};try{$names=@($key.GetValueNames());[Array]::Sort($names,[StringComparer]::OrdinalIgnoreCase);$children=@($key.GetSubKeyNames());[Array]::Sort($children,[StringComparer]::OrdinalIgnoreCase);[ordered]@{acl=$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);children=$children;values=@(foreach($name in $names){[LeftoverFixtureRaw]::Raw($key,$name)})}}finally{$key.Dispose()}}
function Same($a,$b){($a|ConvertTo-Json -Depth 16 -Compress) -ceq ($b|ConvertTo-Json -Depth 16 -Compress)}
function PutText($key,$name,$text,[int]$type=1){[LeftoverFixtureRaw]::Put($key,$name,$type,[Text.Encoding]::Unicode.GetBytes($text+[char]0+[char]0))}
function Roots{[ordered]@{apps=(Flat $apps);uninstall=(Flat $uninstall);cache=(Flat $cache)}}
function Nodes{[ordered]@{applications=@(foreach($f in $descriptor.fixtures){[ordered]@{kind=$f.kind;path=$f.applicationPath;snapshot=(Flat $f.applicationPath)}});uninstall=@(foreach($f in $descriptor.anchors){[ordered]@{name=$f.name;path=$f.path;snapshot=(Flat $f.path)}});cache=@((Flat $cache).values|Where-Object{$descriptor.cacheNames -ccontains $_.name})}}
function Preserved-Root($before,$after,$removed=@()){
 if($before.acl -cne $after.acl){throw 'Existing root permissions changed.'};foreach($name in $before.children){if($after.children -inotcontains $name){throw 'An existing child registration was removed.'}}
 $actual=@{};foreach($v in $after.values){$actual[$v.name]=$v};foreach($v in $before.values){if($removed -icontains $v.name){continue};if(-not$actual.ContainsKey($v.name) -or -not(Same $v $actual[$v.name])){throw 'An unrelated existing registry value changed.'}}
}
function Environment-Preserved{$now=Roots;Preserved-Root $descriptor.baseline.apps $now.apps;Preserved-Root $descriptor.baseline.uninstall $now.uninstall;Preserved-Root $descriptor.baseline.cache $now.cache;return $true}
if($Action -ceq 'create'){
 if((Test-Path -LiteralPath $descriptorPath) -or (Test-Path -LiteralPath $folder)){throw 'Owned leftover fixture already exists.'};foreach($path in @($apps,$uninstall,$cache)){$key=Key $path $true;if(-not$key){throw 'Existing writable fixture roots are required.'};$key.Dispose()}
 $baseline=Roots;New-Item -ItemType Directory -Path $folder -Force|Out-Null;$fixtures=@();$anchors=@()
 foreach($kind in @('One','Two','Deferred','NameOnly','Ambiguous','Msi','Found','Expanded')){
  $exe="rr$search-$kind.exe";$missing=Join-Path $folder $kind;$anchorName="RustRegistry-E2E-$search-$kind";$display="RustRegistry E2E $search $kind"
  $fixtures+=,[ordered]@{kind=$kind;executableName=$exe;applicationPath="$apps\$exe";directory=$missing;executable=(Join-Path $missing $exe);anchorKey=$anchorName;displayName=$display}
  $install=if($kind -ceq 'NameOnly'){Join-Path $folder 'DifferentOwner'}else{$missing};$anchors+=,[ordered]@{name=$anchorName;path="$uninstall\$anchorName";directory=$install;displayName=$display;kind=$kind;type=1}
  if($kind -ceq 'Ambiguous'){$anchors+=,[ordered]@{name="$anchorName-Other";path="$uninstall\$anchorName-Other";directory=$install;displayName=$display;kind='Duplicate';type=2}}
 }
 foreach($f in $fixtures){$key=Key $f.applicationPath;if($key){$key.Dispose();throw 'Owned application path already exists.'}}
 foreach($f in $anchors){$key=Key $f.path;if($key){$key.Dispose();throw 'Owned uninstall anchor already exists.'}}
 $cacheNames=@(($fixtures[0].executable+'.FriendlyAppName'),($fixtures[0].executable+'.ApplicationCompany'));if(@($baseline.cache.values|Where-Object{$cacheNames -icontains $_.name}).Count){throw 'Owned cache values already exist.'}
 $descriptor=[ordered]@{token=$Token;ownerSid=$sid;folder=$folder;search=$search;fixtures=$fixtures;anchors=$anchors;cacheNames=$cacheNames;baseline=$baseline;original=$null;conflict=$null;pathList=[bool]$PathList;retainedTail=$retainedTail;retainedAcl=$null}
 $descriptor|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 $parent=Key $apps $true;try{foreach($f in $fixtures){$key=$parent.CreateSubKey($f.executableName,$true);try{$pathText=$f.directory+'\';if($PathList){$pathText+=';'+$retainedTail};PutText $key 'pAth' $pathText $(if($f.kind -ceq 'Expanded'){2}else{1});$key.SetValue('Keep',[uint32]17,[Microsoft.Win32.RegistryValueKind]::DWord);$key.SetValue('LicenseMarker','OWNED-TEST-PRESERVE',[Microsoft.Win32.RegistryValueKind]::String);$key.SetValue('CustomBinary',[byte[]]@(0,255,1,0),[Microsoft.Win32.RegistryValueKind]::Binary);if($f.kind -ceq 'Deferred'){PutText $key '' $f.executable}}finally{$key.Dispose()}}}finally{$parent.Dispose()}
 $parent=Key $uninstall $true;try{foreach($f in $anchors){$key=$parent.CreateSubKey($f.name,$true);try{PutText $key 'DisplayName' $f.displayName;PutText $key 'InstallLocation' $f.directory $f.type;PutText $key 'UninstallString' ('"'+(Join-Path $f.directory 'uninstall.exe')+'" /remove');PutText $key 'QuietUninstallString' ('"'+(Join-Path $f.directory 'uninstall.exe')+'" /quiet');PutText $key 'Publisher' 'RustRegistry owned controls';PutText $key 'DisplayVersion' '0.0.0-test';$key.SetValue('CustomBinary',[byte[]]@(17,0,255),[Microsoft.Win32.RegistryValueKind]::Binary);if($f.kind -ceq 'Msi'){$key.SetValue('WindowsInstaller',[uint32]1,[Microsoft.Win32.RegistryValueKind]::DWord)}}finally{$key.Dispose()}}}finally{$parent.Dispose()}
 $key=Key $cache $true;try{PutText $key $cacheNames[0] 'Owned stale application';PutText $key $cacheNames[1] ''}finally{$key.Dispose()}
 $found=$fixtures|Where-Object{$_.kind -ceq 'Found'};[IO.Directory]::CreateDirectory($found.directory)|Out-Null;[IO.File]::WriteAllBytes($found.executable,[byte[]]@())
 if($PathList){[IO.Directory]::CreateDirectory($retainedDirectory)|Out-Null;$file=Join-Path $retainedDirectory 'keep.bin';[IO.File]::WriteAllBytes($file,[byte[]]@(0,31,255));$descriptor.retainedAcl=(Get-Acl -LiteralPath $file).Sddl}
 $descriptor.original=Nodes;$descriptor|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{
 if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned leftover descriptor is missing.'};$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json;if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $sid -or $descriptor.folder -cne $folder){throw 'Owned leftover identity mismatch.'}
}
$allowedKinds=@('One','Two','Deferred','NameOnly','Ambiguous','Msi','Found','Expanded')
if($descriptor.pathList -and $descriptor.retainedTail -cne $retainedTail){throw 'Owned retained path scope changed.'}
if($descriptor.pathList){$file=Join-Path $retainedDirectory 'keep.bin';if(-not(Test-Path -LiteralPath $file) -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -cne 'AB//' -or (Get-Acl -LiteralPath $file).Sddl -cne $descriptor.retainedAcl){throw 'Retained file bytes or permissions changed.'}}
if($descriptor.fixtures.Count -ne 8 -or @($descriptor.fixtures.kind|Sort-Object -Unique).Count -ne 8 -or $descriptor.anchors.Count -ne 9){throw 'Owned fixture scope is incomplete.'}
$allowedAnchors=@()
foreach($f in $descriptor.fixtures){
 $expectedExe="rr$search-$($f.kind).exe";$expectedDirectory=Join-Path $folder $f.kind;$expectedAnchor="RustRegistry-E2E-$search-$($f.kind)"
 if($allowedKinds -cnotcontains $f.kind -or $f.executableName -cne $expectedExe -or $f.applicationPath -cne "$apps\$expectedExe" -or $f.directory -cne $expectedDirectory -or $f.executable -cne (Join-Path $expectedDirectory $expectedExe) -or $f.anchorKey -cne $expectedAnchor){throw 'Owned fixture path escaped its fixed registration scope.'}
 $allowedAnchors+=,$expectedAnchor;if($f.kind -ceq 'Ambiguous'){$allowedAnchors+=,"$expectedAnchor-Other"}
}
foreach($a in $descriptor.anchors){if($allowedAnchors -cnotcontains $a.name -or $a.path -cne "$uninstall\$($a.name)"){throw 'Owned uninstall path escaped its fixed scope.'}}
$oneForScope=$descriptor.fixtures|Where-Object{$_.kind -ceq 'One'}
if(-not(Same $descriptor.cacheNames @(($oneForScope.executable+'.FriendlyAppName'),($oneForScope.executable+'.ApplicationCompany')))){throw 'Owned cache scope changed.'}
$preserved=Environment-Preserved
$one=$descriptor.fixtures|Where-Object{$_.kind -ceq 'One'};$anchor=$descriptor.anchors|Where-Object{$_.name -ceq $one.anchorKey}
if($Action -like 'conflict-*-create'){
 if($descriptor.conflict){throw 'An owned conflict is active.'}
 if($Action -ceq 'conflict-path-create'){
  if(-not$descriptor.pathList){throw 'A path-list fixture is required.'};$key=Key $one.applicationPath $true;try{$prior=[LeftoverFixtureRaw]::Raw($key,'pAth');$descriptor|Add-Member -MemberType NoteProperty -Name pathConflictOriginal -Value $prior -Force;PutText $key 'pAth' ($retainedTail+';NewOwnedConflict')}finally{$key.Dispose()}
 }
 switch($Action){'conflict-directory-create'{if(Test-Path -LiteralPath $one.directory){throw 'Owned reinstall directory exists.'};[IO.Directory]::CreateDirectory($one.directory)|Out-Null};'conflict-metadata-create'{$key=Key $anchor.path $true;try{if($key.GetValueNames() -contains 'OwnedLateValue'){throw 'Owned metadata conflict exists.'};PutText $key 'OwnedLateValue' 'preserve'}finally{$key.Dispose()}};'conflict-duplicate-create'{$name="$($one.anchorKey)-LateDuplicate";$key=Key "$uninstall\$name";if($key){$key.Dispose();throw 'Owned duplicate exists.'};$parent=Key $uninstall $true;try{$key=$parent.CreateSubKey($name,$true);try{PutText $key 'InstallLocation' $one.directory 2;PutText $key 'OwnedToken' $Token}finally{$key.Dispose()}}finally{$parent.Dispose()}};'conflict-default-create'{$key=Key $one.applicationPath $true;try{if($key.GetValueNames() -contains ''){throw 'Owned default mapping exists.'};PutText $key '' $one.executable}finally{$key.Dispose()}}}
 $descriptor.conflict=$Action;$descriptor|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
if($Action -like 'conflict-*-remove'){
 if($descriptor.conflict -cne $Action.Replace('-remove','-create')){throw 'Owned conflict identity mismatch.'}
 if($Action -ceq 'conflict-path-remove'){
  if(-not$descriptor.pathList -or -not$descriptor.pathConflictOriginal){throw 'Owned path-list conflict scope is missing.'};$key=Key $one.applicationPath $true;try{$current=[LeftoverFixtureRaw]::Raw($key,'pAth');$expected=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($retainedTail+';NewOwnedConflict'+[char]0+[char]0));if($current.type -ne 1 -or $current.data -cne $expected){throw 'Owned path-list conflict changed.'};$prior=$descriptor.pathConflictOriginal;if($prior.name -cne 'pAth' -or $prior.type -ne 1){throw 'Owned path-list prior value scope changed.'};[LeftoverFixtureRaw]::Put($key,'pAth',1,[Convert]::FromBase64String($prior.data))}finally{$key.Dispose()}
 }
 switch($Action){'conflict-directory-remove'{if(-not(Test-Path -LiteralPath $one.directory) -or @(Get-ChildItem -LiteralPath $one.directory).Count){throw 'Owned reinstall directory changed.'};Remove-Item -LiteralPath $one.directory};'conflict-metadata-remove'{$key=Key $anchor.path $true;try{if($key.GetValue('OwnedLateValue') -cne 'preserve'){throw 'Owned metadata conflict changed.'};$key.DeleteValue('OwnedLateValue',$true)}finally{$key.Dispose()}};'conflict-duplicate-remove'{$name="$($one.anchorKey)-LateDuplicate";$node=Flat "$uninstall\$name";if($node.children.Count -ne 0 -or $node.values.Count -ne 2){throw 'Owned duplicate changed.'};$key=Key "$uninstall\$name";try{if($key.GetValue('OwnedToken') -cne $Token -or $key.GetValue('InstallLocation',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $one.directory){throw 'Owned duplicate identity changed.'}}finally{$key.Dispose()};$tx=[LeftoverFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'RustRegistry owned duplicate cleanup');try{if($tx.IsInvalid -or -not(Same (Flat "$uninstall\$name" $tx) $node)){throw 'Owned duplicate changed before cleanup.'};$parent=Key $uninstall $true $tx;try{[LeftoverFixtureRaw]::Delete($parent,$name,$tx)}finally{$parent.Dispose()};if(-not[LeftoverFixtureRaw]::CommitTransaction($tx)){throw 'Owned duplicate cleanup did not commit.'}}finally{$tx.Dispose()}};'conflict-default-remove'{$key=Key $one.applicationPath $true;try{if($key.GetValue('') -cne $one.executable){throw 'Owned executable mapping changed.'};$key.DeleteValue('',$true)}finally{$key.Dispose()}}}
 $descriptor.conflict=$null;$descriptor|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
$current=Nodes
if($Action -ceq 'cleanup'){
 if($descriptor.conflict){throw 'Remove the active owned conflict before cleanup.'}
 $copy=$current|ConvertTo-Json -Depth 18|ConvertFrom-Json
 foreach($f in $descriptor.fixtures){$node=($copy.applications|Where-Object{$_.kind -ceq $f.kind}).snapshot;$prior=($descriptor.original.applications|Where-Object{$_.kind -ceq $f.kind}).snapshot
  foreach($name in @('pAth','')){$expected=@($prior.values|Where-Object{$_.name -ceq $name});$actual=@($node.values|Where-Object{$_.name -ceq $name});$mutable=($name -ceq 'pAth' -and $f.kind -in @('One','Two','Deferred')) -or ($name -ceq '' -and $f.kind -ceq 'Deferred');if($mutable -and $expected.Count -eq 1 -and $actual.Count -eq 0){$node.values=@($node.values)+@($expected[0])}}
  if($descriptor.pathList -and $f.kind -in @('One','Two','Deferred')){$actual=@($node.values|Where-Object{$_.name -ceq 'pAth'});$pruned=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($retainedTail+[char]0+[char]0));if($actual.Count -eq 1 -and $actual[0].type -eq 1 -and $actual[0].data -ceq $pruned){$node.values=@($node.values|Where-Object{$_.name -cne 'pAth'})+@($prior.values|Where-Object{$_.name -ceq 'pAth'})}}
  $node.values=@($node.values|Sort-Object {$_.name.ToLowerInvariant()})
 }
 foreach($node in $copy.uninstall){$node.snapshot.values=@($node.snapshot.values|Where-Object{if($_.name -ieq 'SystemComponent'){if($_.type -ne 4 -or $_.data -cne 'AQAAAA=='){throw 'Owned visibility flag changed.'};$false}else{$true}})}
 $copy.cache=$descriptor.original.cache
 if(-not(Same $copy $descriptor.original)){throw 'Owned leftover metadata, settings, licenses, controls or permissions changed; cleanup stopped.'}
 foreach($value in $current.cache){$prior=@($descriptor.original.cache|Where-Object{$_.name -ceq $value.name});if($prior.Count -ne 1 -or -not(Same $value $prior[0])){throw 'Owned cache value changed unexpectedly.'}}
 $tx=[LeftoverFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'RustRegistry owned leftover fixture cleanup')
 try{if($tx.IsInvalid){throw 'Owned cleanup transactions are unavailable.'};foreach($node in @($current.applications)+@($current.uninstall)){if(-not(Same (Flat $node.path $tx) $node.snapshot) -or $node.snapshot.children.Count){throw 'Owned flat registration changed before conditional cleanup.'};$split=$node.path.LastIndexOf('\');$parent=Key $node.path.Substring(0,$split) $true $tx;try{[LeftoverFixtureRaw]::Delete($parent,$node.path.Substring($split+1),$tx)}finally{$parent.Dispose()}};$key=Key $cache $true $tx;try{foreach($name in $descriptor.cacheNames){$key.DeleteValue($name,$false)}}finally{$key.Dispose()};if(-not[LeftoverFixtureRaw]::CommitTransaction($tx)){throw 'Owned leftover cleanup did not commit.'}}finally{$tx.Dispose()}
 $found=$descriptor.fixtures|Where-Object{$_.kind -ceq 'Found'};if(-not(Test-Path -LiteralPath $found.executable) -or (Get-Item -LiteralPath $found.executable).Length -ne 0){throw 'Owned inert application file changed.'};Remove-Item -LiteralPath $found.executable;if(@(Get-ChildItem -LiteralPath $found.directory).Count){throw 'Owned found directory is not empty.'};Remove-Item -LiteralPath $found.directory;if($descriptor.pathList){$file=Join-Path $retainedDirectory 'keep.bin';if(@(Get-ChildItem -LiteralPath $retainedDirectory).Count -ne 1){throw 'Owned retained directory changed.'};Remove-Item -LiteralPath $file;Remove-Item -LiteralPath $retainedDirectory};if(@(Get-ChildItem -LiteralPath $folder).Count){throw 'Owned leftover folder is not empty.'};Remove-Item -LiteralPath $folder
 $preserved=Environment-Preserved;$current=Nodes;foreach($node in @($current.applications)+@($current.uninstall)){if($null -ne $node.snapshot){throw 'An owned registration remains.'}};if($current.cache.Count){throw 'Owned cache fields remain.'}
}
[ordered]@{token=$Token;search=$search;fixtures=$descriptor.fixtures;anchors=$descriptor.anchors;original=$descriptor.original;current=$current;environmentPreserved=$preserved;pathList=[bool]$descriptor.pathList;retainedTail=$retainedTail;retainedPreserved=$true}|ConvertTo-Json -Depth 18 -Compress
