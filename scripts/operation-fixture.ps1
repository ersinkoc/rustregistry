param([Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup')][string]$Action,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid operation fixture token.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent));$folder=Join-Path $workspace '.temp_files\operation-fixtures';$descriptorPath=Join-Path $folder "$Token.json"
$path='Software\Microsoft\Windows\CurrentVersion\Run';$search='RustRegistry-Operations-'+$Token
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
. (Join-Path $PSScriptRoot 'registry-fixture-common.ps1')
$names=@(0..999|ForEach-Object{"$search-$_"})
function OwnedValues { @((Flat $path).values|Where-Object{$names -ccontains $_.name}) }
function Preserved {
 $now=Flat $path;if($now.acl -cne $descriptor.baseline.acl -or -not(Same $now.children $descriptor.baseline.children)){throw 'Startup root structure or permissions changed.'}
 $actual=@{};foreach($v in $now.values){$actual[$v.name]=$v};foreach($v in $descriptor.baseline.values){if(-not$actual.ContainsKey($v.name) -or -not(Same $actual[$v.name] $v)){throw 'A pre-existing startup value changed.'}};return $true
}
if($Action -ceq 'create'){
 if(Test-Path -LiteralPath $descriptorPath){throw 'Owned operation fixture already exists.'};$baseline=Flat $path;if(-not$baseline){throw 'Existing startup root is required.'}
 foreach($v in $baseline.values){if($names -ccontains $v.name){throw 'Fixture value collision.'}}
 $target=Join-Path $folder "$Token\missing.exe";if(Test-Path -LiteralPath $target){throw 'Owned missing target exists.'}
 New-Item -ItemType Directory -Path $folder -Force|Out-Null
 $descriptor=[ordered]@{token=$Token;owner=$sid;search=$search;baseline=$baseline;original=$null};$descriptor|ConvertTo-Json -Depth 16|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 $key=Key $path $true;try{foreach($name in $names){PutText $key $name ('"'+$target+'" --owned-fixture') 2}}finally{$key.Dispose()}
 $descriptor.original=@(OwnedValues);$descriptor|ConvertTo-Json -Depth 16|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned descriptor is missing.'};$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json}
if($descriptor.token -cne $Token -or $descriptor.owner -cne $sid -or $descriptor.search -cne $search -or $descriptor.original.Count -ne 1000){throw 'Owned fixture identity mismatch.'}
$preserved=Preserved;$current=@(OwnedValues)
foreach($v in $current){$prior=@($descriptor.original|Where-Object{$_.name -ceq $v.name});if($prior.Count -ne 1 -or -not(Same $prior[0] $v)){throw 'Owned original bytes changed.'}}
if($Action -ceq 'cleanup'){
 $key=Key $path $true;try{foreach($v in $current){$actual=[LeftoverFixtureRaw]::Raw($key,$v.name);if(-not(Same $actual $v)){throw 'Owned cleanup conflict.'};$key.DeleteValue($v.name,$true)}}finally{$key.Dispose()}
 $current=@(OwnedValues);if($current.Count){throw 'Owned fixture values remain.'};$preserved=Preserved
}
[ordered]@{token=$Token;search=$search;names=$names;original=$descriptor.original;current=$current;environmentPreserved=$preserved}|ConvertTo-Json -Depth 16 -Compress
