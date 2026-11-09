param([Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-directory-create','conflict-directory-remove','conflict-metadata-create','conflict-metadata-remove','conflict-anchor-create','conflict-anchor-remove','conflict-duplicate-create','conflict-duplicate-remove','conflict-command-create','conflict-command-remove','conflict-value-create','conflict-value-remove','conflict-app-path-create','conflict-app-path-remove')][string]$Action,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid owned type token.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent));$base=Join-Path $workspace '.temp_files\leftover-types-fixtures';$folder=Join-Path $base $Token;$descriptorPath=Join-Path $base "$Token.json"
$apps='Software\Classes\Applications';$paths='Software\Microsoft\Windows\CurrentVersion\App Paths';$uninstall='Software\Microsoft\Windows\CurrentVersion\Uninstall';$cache='Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$search=$Token.Replace('-','').Substring(0,20)
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
. (Join-Path $PSScriptRoot 'registry-fixture-common.ps1')
function Tree([string]$path,$tx=$null){
 $root=Flat $path $tx;if(-not$root){return};$queue=@('');$nodes=@()
 for($i=0;$i -lt $queue.Count;$i++){
  if($i -ge 32){throw 'Owned tree exceeds its node limit.'};$relative=$queue[$i];if($relative.Split('\').Count -gt 6){throw 'Owned tree exceeds its depth limit.'}
  $full=if($relative){$path+'\'+$relative}else{$path};$snapshot=Flat $full $tx;if(-not$snapshot){throw 'Owned tree changed during reading.'};$nodes+=,[ordered]@{path=$relative;snapshot=$snapshot}
  foreach($child in $snapshot.children){if($child.Contains('\') -or $child.Contains([char]0)){throw 'Invalid owned child name.'};$queue+=,$(if($relative){$relative+'\'+$child}else{$child})}
 }
 @($nodes|Sort-Object path)
}
function Roots{[ordered]@{apps=(Flat $apps);paths=(Flat $paths);uninstall=(Flat $uninstall);cache=(Flat $cache)}}
function Nodes{[ordered]@{applications=@(foreach($f in $descriptor.fixtures){[ordered]@{kind=$f.kind;path=$f.applicationPath;nodes=@(Tree $f.applicationPath)}});uninstall=@(foreach($a in $descriptor.anchors){[ordered]@{path=$a.path;snapshot=(Flat $a.path)}});activePath=(Flat $descriptor.activePath);cache=@((Flat $cache).values|Where-Object{$descriptor.cacheNames -ccontains $_.name})}}
function Preserved{
 $current=Roots;foreach($part in @('apps','paths','uninstall','cache')){$before=$descriptor.baseline.$part;$after=$current.$part;if($before.acl -cne $after.acl){throw 'A pre-existing root permission changed.'};foreach($name in $before.children){if($after.children -inotcontains $name){throw 'A pre-existing registration disappeared.'}};$lookup=@{};foreach($v in $after.values){$lookup[$v.name]=$v};foreach($v in $before.values){if(-not$lookup.ContainsKey($v.name) -or -not(Same $v $lookup[$v.name])){throw 'A pre-existing root value changed.'}}};return $true
}
if($Action -ceq 'create'){
 if((Test-Path -LiteralPath $descriptorPath) -or (Test-Path -LiteralPath $folder)){throw 'Owned type fixture exists.'};$baseline=Roots;foreach($part in @('apps','paths','uninstall','cache')){if(-not$baseline.$part){throw 'Existing fixture roots are required.'}}
 New-Item -ItemType Directory -Path $folder -Force|Out-Null;$fixtures=@();$anchors=@();$extensions=@(('.rra'+$search.Substring(0,8)),('.rrb'+$search.Substring(0,8)),('.rrkeep'+$search.Substring(0,8)))
 foreach($kind in @('One','Found','Msi','Ambiguous','NameOnly','Delegated','ActivePath')){
  $name="rr$search-$kind.exe";$directory=Join-Path $folder $kind;$owner="RustRegistry-Types-$search-$kind";$install=if($kind -ceq 'NameOnly'){Join-Path $folder 'OtherOwner'}else{$directory}
  $fixtures+=,[ordered]@{kind=$kind;executableName=$name;applicationPath="$apps\$name";directory=$directory;executable=(Join-Path $directory $name);anchorKey=$owner;displayName="RustRegistry types $search $kind";extensions=$extensions;command=('"'+(Join-Path $directory $name)+'" "%1" %*')}
  $anchors+=,[ordered]@{name=$owner;path="$uninstall\$owner";directory=$install;kind=$kind};if($kind -ceq 'Ambiguous'){$anchors+=,[ordered]@{name="$owner-Other";path="$uninstall\$owner-Other";directory=$install;kind='Duplicate'}}
 }
 foreach($f in $fixtures){$key=Key $f.applicationPath;if($key){$key.Dispose();throw 'Owned application collision.'}}
 foreach($a in $anchors){$key=Key $a.path;if($key){$key.Dispose();throw 'Owned uninstall collision.'}}
 $one=$fixtures|Where-Object{$_.kind -ceq 'One'};$active=$fixtures|Where-Object{$_.kind -ceq 'ActivePath'};$cacheNames=@(($one.executable+'.FriendlyAppName'),($one.executable+'.ApplicationCompany'));if(@($baseline.cache.values|Where-Object{$cacheNames -ccontains $_.name}).Count){throw 'Owned cache collision.'}
 $descriptor=[ordered]@{token=$Token;owner=$sid;folder=$folder;fixtures=$fixtures;anchors=$anchors;cacheNames=$cacheNames;activePath=($paths+'\'+$active.executableName);baseline=$baseline;original=$null;conflict=$null;priorValue=$null};$descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 $parent=Key $apps $true;try{foreach($f in $fixtures){$key=$parent.CreateSubKey($f.executableName,$true);try{PutText $key 'FriendlyAppName' $f.displayName;PutText $key 'LicenseMarker' 'OWNED-PRESERVE';$key.SetValue('CustomBinary',[byte[]]@(0,255,1),[Microsoft.Win32.RegistryValueKind]::Binary);$leaf=$key.CreateSubKey('shell\open\command',$true);try{PutText $leaf '' $f.command;if($f.kind -ceq 'Delegated'){PutText $leaf 'DelegateExecute' '{11111111-1111-4111-8111-111111111111}'}}finally{$leaf.Dispose()};$leaf=$key.CreateSubKey('DefaultIcon',$true);try{PutText $leaf '' '%SystemRoot%\preserved.ico,0' 2}finally{$leaf.Dispose()};$leaf=$key.CreateSubKey('SupportedTypes',$true);try{[LeftoverFixtureRaw]::Put($leaf,$extensions[0],1,[byte[]]@(0,0));PutText $leaf $extensions[1] '';PutText $leaf $extensions[2] 'preserve nonempty metadata'}finally{$leaf.Dispose()}}finally{$key.Dispose()}}}finally{$parent.Dispose()}
 $parent=Key $uninstall $true;try{foreach($a in $anchors){$key=$parent.CreateSubKey($a.name,$true);try{PutText $key 'DisplayName' ("RustRegistry types $search "+$a.kind);PutText $key 'InstallLocation' $a.directory $(if($a.kind -ceq 'Duplicate'){2}else{1});PutText $key 'UninstallString' ('"'+(Join-Path $a.directory 'uninstall.exe')+'" /remove');PutText $key 'Publisher' 'Owned controls';if($a.kind -ceq 'Msi'){$key.SetValue('WindowsInstaller',[uint32]1,[Microsoft.Win32.RegistryValueKind]::DWord)}}finally{$key.Dispose()}}}finally{$parent.Dispose()}
 $parent=Key $paths $true;try{$key=$parent.CreateSubKey($active.executableName,$true);try{PutText $key '' $active.executable;PutText $key 'OwnedToken' $Token}finally{$key.Dispose()}}finally{$parent.Dispose()}
 $key=Key $cache $true;try{PutText $key $cacheNames[0] 'Owned type cache';PutText $key $cacheNames[1] ''}finally{$key.Dispose()}
 $found=$fixtures|Where-Object{$_.kind -ceq 'Found'};[IO.Directory]::CreateDirectory($found.directory)|Out-Null;[IO.File]::WriteAllBytes($found.executable,[byte[]]@())
 $descriptor.original=Nodes;$descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned type descriptor missing.'};$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json}
if($descriptor.token -cne $Token -or $descriptor.owner -cne $sid -or $descriptor.folder -cne $folder -or $descriptor.fixtures.Count -ne 7 -or $descriptor.anchors.Count -ne 8){throw 'Owned type identity mismatch.'}
$allowed=@('One','Found','Msi','Ambiguous','NameOnly','Delegated','ActivePath');$owners=@()
foreach($f in $descriptor.fixtures){$name="rr$search-$($f.kind).exe";if($allowed -cnotcontains $f.kind -or $f.executableName -cne $name -or $f.applicationPath -cne "$apps\$name" -or $f.directory -cne (Join-Path $folder $f.kind) -or $f.executable -cne (Join-Path (Join-Path $folder $f.kind) $name) -or $f.anchorKey -cne "RustRegistry-Types-$search-$($f.kind)"){throw 'Owned application path escaped its scope.'};$owners+=,$f.anchorKey;if($f.kind -ceq 'Ambiguous'){$owners+=,($f.anchorKey+'-Other')}}
foreach($a in $descriptor.anchors){if($owners -cnotcontains $a.name -or $a.path -cne "$uninstall\$($a.name)"){throw 'Owned uninstall path escaped its scope.'}}
$one=$descriptor.fixtures|Where-Object{$_.kind -ceq 'One'};$active=$descriptor.fixtures|Where-Object{$_.kind -ceq 'ActivePath'}
if($descriptor.activePath -cne "$paths\$($active.executableName)" -or -not(Same $descriptor.cacheNames @(($one.executable+'.FriendlyAppName'),($one.executable+'.ApplicationCompany')))){throw 'Owned ancillary scope changed.'}
$anchor="$uninstall\$($one.anchorKey)";$commandPath=$one.applicationPath+'\shell\open\command';$hintPath=$one.applicationPath+'\SupportedTypes';$first=$one.extensions[0]
if($Action -like 'conflict-*-create'){
 if($descriptor.conflict){throw 'An owned conflict is already active.'}
 switch($Action){
 'conflict-directory-create'{if(Test-Path -LiteralPath $one.directory){throw 'Owned directory exists.'};[IO.Directory]::CreateDirectory($one.directory)|Out-Null}
 'conflict-metadata-create'{$key=Key $one.applicationPath $true;try{PutText $key 'OwnedLateValue' 'preserve'}finally{$key.Dispose()}}
 'conflict-anchor-create'{$key=Key $anchor $true;try{PutText $key 'OwnedLateValue' 'preserve'}finally{$key.Dispose()}}
 'conflict-command-create'{$key=Key $commandPath $true;try{PutText $key '' ('"'+(Join-Path $folder ('Other\'+$one.executableName))+'" "%1"')}finally{$key.Dispose()}}
 'conflict-value-create'{$key=Key $hintPath $true;try{$descriptor.priorValue=if($key.GetValueNames() -ccontains $first){[LeftoverFixtureRaw]::Raw($key,$first)}else{$null};PutText $key $first 'OWNED-LATE-PRESERVE'}finally{$key.Dispose()}}
 'conflict-duplicate-create'{$parent=Key $uninstall $true;try{$key=$parent.CreateSubKey($one.anchorKey+'-Late',$true);try{PutText $key 'InstallLocation' $one.directory 2;PutText $key 'OwnedToken' $Token}finally{$key.Dispose()}}finally{$parent.Dispose()}}
 'conflict-app-path-create'{$parent=Key $paths $true;try{$key=$parent.CreateSubKey($one.executableName,$true);try{PutText $key '' $one.executable;PutText $key 'OwnedToken' $Token}finally{$key.Dispose()}}finally{$parent.Dispose()}}
 }
 $descriptor.conflict=$Action;$descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
if($Action -like 'conflict-*-remove'){
 if($descriptor.conflict -cne $Action.Replace('-remove','-create')){throw 'Owned conflict identity mismatch.'}
 switch($Action){
 'conflict-directory-remove'{if(@(Get-ChildItem -LiteralPath $one.directory).Count){throw 'Owned directory changed.'};Remove-Item -LiteralPath $one.directory}
 'conflict-metadata-remove'{$key=Key $one.applicationPath $true;try{if($key.GetValue('OwnedLateValue') -cne 'preserve'){throw 'Owned metadata changed.'};$key.DeleteValue('OwnedLateValue',$true)}finally{$key.Dispose()}}
 'conflict-anchor-remove'{$key=Key $anchor $true;try{if($key.GetValue('OwnedLateValue') -cne 'preserve'){throw 'Owned anchor changed.'};$key.DeleteValue('OwnedLateValue',$true)}finally{$key.Dispose()}}
 'conflict-command-remove'{$key=Key $commandPath $true;try{if($key.GetValue('') -cne ('"'+(Join-Path $folder ('Other\'+$one.executableName))+'" "%1"')){throw 'Owned command changed.'};PutText $key '' $one.command}finally{$key.Dispose()}}
 'conflict-value-remove'{$key=Key $hintPath $true;try{if($key.GetValue($first) -cne 'OWNED-LATE-PRESERVE'){throw 'Owned value changed.'};if($descriptor.priorValue){[LeftoverFixtureRaw]::Put($key,$first,1,[Convert]::FromBase64String($descriptor.priorValue.data))}else{$key.DeleteValue($first,$true)}}finally{$key.Dispose()}}
 {$_ -in @('conflict-duplicate-remove','conflict-app-path-remove')}{$path=if($Action -ceq 'conflict-duplicate-remove'){$uninstall+'\'+$one.anchorKey+'-Late'}else{$paths+'\'+$one.executableName};$snapshot=Flat $path;$key=Key $path;try{if($key.GetValue('OwnedToken') -cne $Token -or $snapshot.values.Count -ne 2 -or $snapshot.children.Count){throw 'Owned counterpart changed.'}}finally{$key.Dispose()};$tx=[LeftoverFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'Owned type counterpart cleanup');try{if($tx.IsInvalid -or -not(Same (Flat $path $tx) $snapshot)){throw 'Owned counterpart changed before cleanup.'};$split=$path.LastIndexOf('\');$parent=Key $path.Substring(0,$split) $true $tx;try{[LeftoverFixtureRaw]::Delete($parent,$path.Substring($split+1),$tx)}finally{$parent.Dispose()};if(-not[LeftoverFixtureRaw]::CommitTransaction($tx)){throw 'Owned counterpart cleanup failed.'}}finally{$tx.Dispose()}}
 }
 $descriptor.conflict=$null;$descriptor|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
$preserved=Preserved;$current=Nodes
if($Action -ceq 'cleanup'){
 if($descriptor.conflict){throw 'Remove the active owned conflict first.'};$copy=$current|ConvertTo-Json -Depth 20|ConvertFrom-Json
 $node=($copy.applications|Where-Object{$_.kind -ceq 'One'}).nodes|Where-Object{$_.path -ceq 'SupportedTypes'};$prior=($descriptor.original.applications|Where-Object{$_.kind -ceq 'One'}).nodes|Where-Object{$_.path -ceq 'SupportedTypes'}
 foreach($name in $one.extensions[0..1]){if(@($node.snapshot.values|Where-Object{$_.name -ceq $name}).Count -eq 0){$node.snapshot.values=@($node.snapshot.values)+@($prior.snapshot.values|Where-Object{$_.name -ceq $name})}};$node.snapshot.values=@($node.snapshot.values|Sort-Object {$_.name.ToLowerInvariant()})
 foreach($u in $copy.uninstall){if($u.path -ceq $anchor){$u.snapshot.values=@($u.snapshot.values|Where-Object{if($_.name -ieq 'SystemComponent'){if($_.type -ne 4 -or $_.data -cne 'AQAAAA=='){throw 'Owned visibility changed.'};$false}else{$true}})}}
 $copy.cache=$descriptor.original.cache;if(-not(Same $copy $descriptor.original)){throw 'Owned metadata, commands, license markers, controls or permissions changed; cleanup stopped.'}
 foreach($v in $current.cache){if(-not(Same $v @($descriptor.original.cache|Where-Object{$_.name -ceq $v.name})[0])){throw 'Owned cache changed.'}}
 $tx=[LeftoverFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'RustRegistry owned type fixture cleanup')
 try{
  if($tx.IsInvalid){throw 'Owned cleanup transaction unavailable.'}
  foreach($f in $current.applications){if(-not(Same @(Tree $f.path $tx) $f.nodes)){throw 'Owned application tree changed before cleanup.'}}
  foreach($u in $current.uninstall){if(-not(Same (Flat $u.path $tx) $u.snapshot)){throw 'Owned uninstall changed before cleanup.'}}
  if(-not(Same (Flat $descriptor.activePath $tx) $current.activePath)){throw 'Owned active path changed before cleanup.'}
  foreach($f in $current.applications){foreach($node in @($f.nodes|Sort-Object {$_.path.Length} -Descending)){$path=if($node.path){$f.path+'\'+$node.path}else{$f.path};$split=$path.LastIndexOf('\');$parent=Key $path.Substring(0,$split) $true $tx;try{[LeftoverFixtureRaw]::Delete($parent,$path.Substring($split+1),$tx)}finally{$parent.Dispose()}}}
  foreach($path in @($current.uninstall.path)+@($descriptor.activePath)){$split=$path.LastIndexOf('\');$parent=Key $path.Substring(0,$split) $true $tx;try{[LeftoverFixtureRaw]::Delete($parent,$path.Substring($split+1),$tx)}finally{$parent.Dispose()}}
  $key=Key $cache $true $tx;try{foreach($name in $descriptor.cacheNames){$key.DeleteValue($name,$false)}}finally{$key.Dispose()};if(-not[LeftoverFixtureRaw]::CommitTransaction($tx)){throw 'Owned tree cleanup did not commit.'}
 }finally{$tx.Dispose()}
 $found=$descriptor.fixtures|Where-Object{$_.kind -ceq 'Found'};if((Get-Item -LiteralPath $found.executable).Length -ne 0 -or @(Get-ChildItem -LiteralPath $found.directory).Count -ne 1){throw 'Owned inert file changed.'};Remove-Item -LiteralPath $found.executable;Remove-Item -LiteralPath $found.directory;if(@(Get-ChildItem -LiteralPath $folder).Count){throw 'Owned fixture folder is not empty.'};Remove-Item -LiteralPath $folder
 $current=Nodes;if(@($current.applications|Where-Object{$_.nodes.Count}).Count -or @($current.uninstall|Where-Object{$_.snapshot}).Count -or $current.activePath -or $current.cache.Count){throw 'Owned registrations remain.'};$preserved=Preserved
}
[ordered]@{token=$Token;search=$search;fixtures=$descriptor.fixtures;original=$descriptor.original;current=$current;environmentPreserved=$preserved}|ConvertTo-Json -Depth 20 -Compress
