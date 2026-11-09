param(
 [Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-directory-create','conflict-directory-remove','conflict-owner-create','conflict-owner-remove','conflict-path-create','conflict-path-remove','conflict-sibling-create','conflict-sibling-remove')][string]$Action,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid owned URL fixture token.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$base=Join-Path $workspace '.temp_files\leftover-urls-fixtures';$folder=Join-Path $base $Token;$descriptorPath=Join-Path $base "$Token.json"
$paths='Software\Microsoft\Windows\CurrentVersion\App Paths';$uninstall='Software\Microsoft\Windows\CurrentVersion\Uninstall';$apps='Software\Classes\Applications'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$search=$Token.Replace('-','').Substring(0,20)
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
. (Join-Path $PSScriptRoot 'registry-fixture-common.ps1')
function Roots { [ordered]@{paths=(Flat $paths);uninstall=(Flat $uninstall);applications=(Flat $apps)} }
function Nodes { [ordered]@{
 paths=@(foreach($f in $descriptor.fixtures){[ordered]@{kind=$f.kind;path=$f.applicationPath;snapshot=(Flat $f.applicationPath)}})
 uninstall=@(foreach($a in $descriptor.anchors){[ordered]@{path=$a.path;snapshot=(Flat $a.path)}})
 counterpart=(Flat $descriptor.counterpart)
} }
function Preserved {
 $now=Roots
 foreach($part in @('paths','uninstall','applications')){
  $before=$descriptor.baseline.$part;$after=$now.$part
  if($before.acl -cne $after.acl){throw 'A pre-existing root permission changed.'}
  foreach($name in $before.children){if($after.children -inotcontains $name){throw 'A pre-existing registration disappeared.'}}
  $values=@{};foreach($v in $after.values){$values[$v.name]=$v}
  foreach($v in $before.values){if(-not$values.ContainsKey($v.name) -or -not(Same $v $values[$v.name])){throw 'A pre-existing root value changed.'}}
 }
 return $true
}
if($Action -ceq 'create'){
 if((Test-Path -LiteralPath $descriptorPath) -or (Test-Path -LiteralPath $folder)){throw 'Owned URL fixture already exists.'}
 $baseline=Roots;foreach($part in @('paths','uninstall','applications')){if(-not$baseline.$part){throw 'Existing fixture roots are required.'}}
 $kinds=@(0..51|ForEach-Object{'Bulk'+$_.ToString('00')})+@('Found','Mapped','Msi','Ambiguous','NameOnly','Delegated','UserApplication','BadTypes')
 $fixtures=@();$anchors=@()
 foreach($kind in $kinds){
  $name="rr$search-$kind.exe";$directory=Join-Path $folder $kind;$owner="RustRegistry-URLs-$search-$kind"
  $fixtures+=,[ordered]@{kind=$kind;executableName=$name;applicationPath=($paths+'\'+$name);directory=$directory;executable=(Join-Path $directory $name);anchorKey=$owner;displayName="RustRegistry URL $search $kind";bulk=$kind.StartsWith('Bulk')}
  $install=if($kind -ceq 'NameOnly'){Join-Path $folder 'OtherOwner'}else{$directory}
  $anchors+=,[ordered]@{name=$owner;path=($uninstall+'\'+$owner);directory=$install;kind=$kind}
  if($kind -ceq 'Ambiguous'){$anchors+=,[ordered]@{name=($owner+'-Other');path=($uninstall+'\'+$owner+'-Other');directory=$install;kind='Duplicate'}}
 }
 foreach($f in $fixtures){$key=Key $f.applicationPath;if($key){$key.Dispose();throw 'Owned App Paths collision.'}}
 foreach($a in $anchors){$key=Key $a.path;if($key){$key.Dispose();throw 'Owned uninstall collision.'}}
 $userApp=@($fixtures|Where-Object{$_.kind -ceq 'UserApplication'})[0];$counterpart=$apps+'\'+$userApp.executableName
 $key=Key $counterpart;if($key){$key.Dispose();throw 'Owned application counterpart collision.'}
 New-Item -ItemType Directory -Path $folder -Force|Out-Null
 $descriptor=[ordered]@{token=$Token;owner=$sid;folder=$folder;search=("RustRegistry URL $search Bulk");fixtures=$fixtures;anchors=$anchors;counterpart=$counterpart;baseline=$baseline;original=$null;conflict=$null}
 $descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 $parent=Key $paths $true
 try{foreach($f in $fixtures){$key=$parent.CreateSubKey($f.executableName,$true);try{
  PutText $key 'pAth' ($f.directory+'\');PutText $key 'SupportedProtocols' 'https:ftp:rr-custom'
  if($f.kind -ceq 'BadTypes'){PutText $key 'uSeUrL' '1'}else{[LeftoverFixtureRaw]::Put($key,'uSeUrL',4,[byte[]]@(1,0,0,0))}
  PutText $key 'LicenseMarker' 'OWNED-URL-PRESERVE';PutText $key 'OwnedToken' $Token;$key.SetValue('Keep',[uint32]17,[Microsoft.Win32.RegistryValueKind]::DWord);$key.SetValue('CustomBinary',[byte[]]@(0,255,1),[Microsoft.Win32.RegistryValueKind]::Binary)
  if($f.kind -ceq 'Mapped'){PutText $key '' $f.executable}
  if($f.kind -ceq 'Delegated'){PutText $key 'DropTarget' '{11111111-1111-4111-8111-111111111111}'}
 }finally{$key.Dispose()}}}finally{$parent.Dispose()}
 $parent=Key $uninstall $true
 try{foreach($a in $anchors){$key=$parent.CreateSubKey($a.name,$true);try{
  PutText $key 'DisplayName' ("RustRegistry URL $search "+$a.kind);PutText $key 'InstallLocation' $a.directory $(if($a.kind -ceq 'Duplicate'){2}else{1});PutText $key 'UninstallString' ('"'+(Join-Path $a.directory 'uninstall.exe')+'" /remove');PutText $key 'Publisher' 'Owned URL controls'
  if($a.kind -ceq 'Msi'){$key.SetValue('WindowsInstaller',[uint32]1,[Microsoft.Win32.RegistryValueKind]::DWord)}
 }finally{$key.Dispose()}}}finally{$parent.Dispose()}
 $parent=Key $apps $true;try{$key=$parent.CreateSubKey($userApp.executableName,$true);try{PutText $key 'OwnedToken' $Token}finally{$key.Dispose()}}finally{$parent.Dispose()}
 $found=@($fixtures|Where-Object{$_.kind -ceq 'Found'})[0];[IO.Directory]::CreateDirectory($found.directory)|Out-Null;[IO.File]::WriteAllBytes($found.executable,[byte[]]@())
 $descriptor.original=Nodes;$descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{
 if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned URL descriptor is missing.'}
 $descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json
}
if($descriptor.token -cne $Token -or $descriptor.owner -cne $sid -or $descriptor.folder -cne $folder -or $descriptor.fixtures.Count -ne 60 -or $descriptor.anchors.Count -ne 61){throw 'Owned URL identity mismatch.'}
$expectedKinds=@(0..51|ForEach-Object{'Bulk'+$_.ToString('00')})+@('Found','Mapped','Msi','Ambiguous','NameOnly','Delegated','UserApplication','BadTypes')
$owners=@();foreach($f in $descriptor.fixtures){$name="rr$search-$($f.kind).exe";if($expectedKinds -cnotcontains $f.kind -or $f.executableName -cne $name -or $f.applicationPath -cne ($paths+'\'+$name) -or $f.directory -cne (Join-Path $folder $f.kind) -or $f.executable -cne (Join-Path (Join-Path $folder $f.kind) $name) -or $f.anchorKey -cne "RustRegistry-URLs-$search-$($f.kind)"){throw 'Owned URL path escaped its fixed scope.'};$owners+=,$f.anchorKey;if($f.kind -ceq 'Ambiguous'){$owners+=,($f.anchorKey+'-Other')}}
foreach($a in $descriptor.anchors){if($owners -cnotcontains $a.name -or $a.path -cne ($uninstall+'\'+$a.name)){throw 'Owned URL anchor escaped its scope.'}}
$userApp=@($descriptor.fixtures|Where-Object{$_.kind -ceq 'UserApplication'})[0];if($descriptor.counterpart -cne ($apps+'\'+$userApp.executableName)){throw 'Owned counterpart escaped its scope.'}
$one=$descriptor.fixtures[0];$path=$one.applicationPath;$late=$uninstall+'\'+$one.anchorKey+'-Late'
if($Action -like 'conflict-*-create'){
 if($descriptor.conflict){throw 'An owned URL conflict is already active.'}
 switch($Action){
  'conflict-directory-create'{if(Test-Path -LiteralPath $one.directory){throw 'Owned directory exists.'};[IO.Directory]::CreateDirectory($one.directory)|Out-Null}
  'conflict-owner-create'{$parent=Key $uninstall $true;try{$key=$parent.CreateSubKey(($one.anchorKey+'-Late'),$true);try{PutText $key 'InstallLocation' $one.directory 2;PutText $key 'OwnedToken' $Token}finally{$key.Dispose()}}finally{$parent.Dispose()}}
  'conflict-path-create'{$key=Key $path $true;try{PutText $key 'pAth' (Join-Path $folder 'OtherMissing')}finally{$key.Dispose()}}
  'conflict-sibling-create'{$key=Key $path $true;try{[LeftoverFixtureRaw]::Put($key,'uSeUrL',4,[byte[]]@(0,0,0,0))}finally{$key.Dispose()}}
 }
 $descriptor.conflict=$Action;$descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
if($Action -like 'conflict-*-remove'){
 if($descriptor.conflict -cne $Action.Replace('-remove','-create')){throw 'Owned URL conflict mismatch.'}
 switch($Action){
  'conflict-directory-remove'{if(@(Get-ChildItem -LiteralPath $one.directory).Count){throw 'Owned directory changed.'};Remove-Item -LiteralPath $one.directory}
  'conflict-path-remove'{$key=Key $path $true;try{if($key.GetValue('pAth') -cne (Join-Path $folder 'OtherMissing')){throw 'Owned conflict path changed.'};$prior=@($descriptor.original.paths[0].snapshot.values|Where-Object{$_.name -ceq 'pAth'})[0];[LeftoverFixtureRaw]::Put($key,'pAth',1,[Convert]::FromBase64String($prior.data))}finally{$key.Dispose()}}
  'conflict-sibling-remove'{$key=Key $path $true;try{$raw=[LeftoverFixtureRaw]::Raw($key,'uSeUrL');if($raw.type -ne 4 -or $raw.data -cne 'AAAAAA=='){throw 'Owned sibling conflict changed.'};[LeftoverFixtureRaw]::Put($key,'uSeUrL',4,[byte[]]@(1,0,0,0))}finally{$key.Dispose()}}
  'conflict-owner-remove'{
   $snapshot=Flat $late;$key=Key $late;try{if($key.GetValue('OwnedToken') -cne $Token -or $snapshot.values.Count -ne 2 -or $snapshot.children.Count){throw 'Owned duplicate changed.'}}finally{$key.Dispose()}
   $tx=[LeftoverFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'Owned URL duplicate cleanup')
   try{if($tx.IsInvalid -or -not(Same (Flat $late $tx) $snapshot)){throw 'Owned duplicate changed before cleanup.'};$parent=Key $uninstall $true $tx;try{[LeftoverFixtureRaw]::Delete($parent,($one.anchorKey+'-Late'),$tx)}finally{$parent.Dispose()};if(-not[LeftoverFixtureRaw]::CommitTransaction($tx)){throw 'Owned duplicate cleanup failed.'}}finally{$tx.Dispose()}
  }
 }
 $descriptor.conflict=$null;$descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
$preserved=Preserved;$current=Nodes
if($Action -ceq 'cleanup'){
 if($descriptor.conflict){throw 'Remove the active owned conflict first.'}
 $copy=$current|ConvertTo-Json -Depth 20|ConvertFrom-Json
 foreach($f in $descriptor.fixtures|Where-Object{$_.bulk}){
  $node=@($copy.paths|Where-Object{$_.path -ceq $f.applicationPath})[0];$prior=@($descriptor.original.paths|Where-Object{$_.path -ceq $f.applicationPath})[0]
  foreach($name in @('pAth','SupportedProtocols','uSeUrL')){if(@($node.snapshot.values|Where-Object{$_.name -ceq $name}).Count -eq 0){$node.snapshot.values=@($node.snapshot.values)+@($prior.snapshot.values|Where-Object{$_.name -ceq $name})}}
  $node.snapshot.values=@($node.snapshot.values|Sort-Object {$_.name.ToLowerInvariant()})
 }
 foreach($a in $copy.uninstall){$a.snapshot.values=@($a.snapshot.values|Where-Object{if($_.name -ieq 'SystemComponent'){if($_.type -ne 4 -or $_.data -cne 'AQAAAA=='){throw 'Owned visibility changed.'};$false}else{$true}})}
 if(-not(Same $copy $descriptor.original)){throw 'Owned URL values, controls, license markers, keys or permissions changed; cleanup stopped.'}
 $tx=[LeftoverFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'RustRegistry owned URL fixture cleanup')
 try{
  if($tx.IsInvalid){throw 'Owned URL cleanup transaction unavailable.'}
  foreach($node in @($current.paths)+@($current.uninstall)){if(-not(Same (Flat $node.path $tx) $node.snapshot)){throw 'Owned URL key changed before cleanup.'}}
  if(-not(Same (Flat $descriptor.counterpart $tx) $current.counterpart)){throw 'Owned URL counterpart changed.'}
  foreach($keyPath in @($current.paths.path)+@($current.uninstall.path)+@($descriptor.counterpart)){$split=$keyPath.LastIndexOf('\');$parent=Key $keyPath.Substring(0,$split) $true $tx;try{[LeftoverFixtureRaw]::Delete($parent,$keyPath.Substring($split+1),$tx)}finally{$parent.Dispose()}}
  if(-not[LeftoverFixtureRaw]::CommitTransaction($tx)){throw 'Owned URL cleanup transaction failed.'}
 }finally{$tx.Dispose()}
 $found=@($descriptor.fixtures|Where-Object{$_.kind -ceq 'Found'})[0]
 if((Get-Item -LiteralPath $found.executable).Length -ne 0 -or @(Get-ChildItem -LiteralPath $found.directory).Count -ne 1){throw 'Owned inert file changed.'}
 Remove-Item -LiteralPath $found.executable;Remove-Item -LiteralPath $found.directory
 if(@(Get-ChildItem -LiteralPath $folder).Count){throw 'Owned URL directory is not empty.'};Remove-Item -LiteralPath $folder
 $current=Nodes;if(@($current.paths|Where-Object{$_.snapshot}).Count -or @($current.uninstall|Where-Object{$_.snapshot}).Count -or $current.counterpart){throw 'Owned URL registrations remain.'};$preserved=Preserved
}
[ordered]@{token=$Token;search=$descriptor.search;fixtures=$descriptor.fixtures;original=$descriptor.original;current=$current;environmentPreserved=$preserved}|ConvertTo-Json -Depth 20 -Compress
