param([Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup')][string]$Action,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid bulk fixture token.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent));$folder=Join-Path $workspace '.temp_files\large-clean-fixtures';$descriptorPath=Join-Path $folder "$Token.json"
$cache='Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
. (Join-Path $PSScriptRoot 'registry-fixture-common.ps1')
$search='RustRegistry-Bulk-'+$Token
function OwnedValues { @((Flat $cache).values|Where-Object{$descriptor.names -ccontains $_.name}) }
function Preserved {
 $now=Flat $cache;if($now.acl -cne $descriptor.baseline.acl -or -not(Same $now.children $descriptor.baseline.children)){throw 'Cache root structure or permissions changed.'}
 $actual=@{};foreach($v in $now.values){$actual[$v.name]=$v};foreach($v in $descriptor.baseline.values){if(-not$actual.ContainsKey($v.name) -or -not(Same $actual[$v.name] $v)){throw 'A pre-existing cache value changed.'}}
 return $true
}
if($Action -ceq 'create'){
 if(Test-Path -LiteralPath $descriptorPath){throw 'Owned bulk fixture already exists.'};$baseline=Flat $cache;if(-not$baseline){throw 'An existing cache root is required.'}
 $targets=@(0..127|ForEach-Object{Join-Path $folder "$Token\Missing\$search-$_.exe"});$names=@(foreach($target in $targets){$target+'.FriendlyAppName';$target+'.ApplicationCompany'})
 foreach($v in $baseline.values){if($names -ccontains $v.name){throw 'Owned bulk value collision.'}}
 foreach($target in $targets){if(Test-Path -LiteralPath $target){throw 'An owned missing target exists.'}}
 New-Item -ItemType Directory -Path $folder -Force|Out-Null
 $descriptor=[ordered]@{token=$Token;owner=$sid;search=$search;targets=$targets;names=$names;baseline=$baseline;original=$null};$descriptor|ConvertTo-Json -Depth 16|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 $key=Key $cache $true;try{foreach($target in $targets){PutText $key ($target+'.FriendlyAppName') ($search+' '+[IO.Path]::GetFileNameWithoutExtension($target));PutText $key ($target+'.ApplicationCompany') 'RustRegistry owned bulk controls'}}finally{$key.Dispose()}
 $descriptor.original=@(OwnedValues);$descriptor|ConvertTo-Json -Depth 16|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{
 if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned bulk descriptor is missing.'};$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json
}
if($descriptor.token -cne $Token -or $descriptor.owner -cne $sid -or $descriptor.search -cne $search -or $descriptor.targets.Count -ne 128 -or $descriptor.names.Count -ne 256){throw 'Owned bulk fixture identity mismatch.'}
$expectedTargets=@(0..127|ForEach-Object{Join-Path $folder "$Token\Missing\$search-$_.exe"});if(-not(Same $descriptor.targets $expectedTargets)){throw 'Owned bulk paths escaped their fixed scope.'}
$expectedNames=@(foreach($target in $expectedTargets){$target+'.FriendlyAppName';$target+'.ApplicationCompany'});if(-not(Same $descriptor.names $expectedNames)){throw 'Owned bulk values escaped their fixed scope.'}
$preserved=Preserved;$current=@(OwnedValues)
foreach($v in $current){$prior=@($descriptor.original|Where-Object{$_.name -ceq $v.name});if($prior.Count -ne 1 -or -not(Same $prior[0] $v)){throw 'Owned bulk bytes changed unexpectedly.'}}
if($Action -ceq 'cleanup'){
 $tx=[LeftoverFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'RustRegistry owned bulk cleanup')
 try{if($tx.IsInvalid){throw 'Owned cleanup transactions are unavailable.'};$key=Key $cache $true $tx;try{foreach($v in $current){$actual=[LeftoverFixtureRaw]::Raw($key,$v.name);if(-not(Same $actual $v)){throw 'Owned bulk value changed before cleanup.'};$key.DeleteValue($v.name,$true)}}finally{$key.Dispose()};if(-not[LeftoverFixtureRaw]::CommitTransaction($tx)){throw 'Owned bulk cleanup did not commit.'}}finally{$tx.Dispose()}
 $current=@(OwnedValues);if($current.Count){throw 'Owned bulk values remain.'};$preserved=Preserved
}
[ordered]@{token=$Token;search=$search;targets=$descriptor.targets;names=$descriptor.names;original=$descriptor.original;current=$current;environmentPreserved=$preserved}|ConvertTo-Json -Depth 16 -Compress
