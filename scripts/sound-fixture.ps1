param(
 [Parameter(Mandatory=$true)][ValidateSet('create','inspect','conflict-file-create','conflict-file-remove','conflict-metadata-create','conflict-metadata-remove','cleanup')][string]$Action,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid owned sound token.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$directory=Join-Path $workspace '.temp_files\sound-fixtures'
$folder=Join-Path $directory $Token
$descriptorPath=Join-Path $directory "$Token.json"
$search=$Token.Replace('-','').Substring(0,24)
$app="RustRegistryE2E_$search"
$appsPath='AppEvents\Schemes\Apps'
$appPath="$appsPath\$app"
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using Microsoft.Win32;using Microsoft.Win32.SafeHandles;
public static class SoundFixtureRaw {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyExW")]static extern int Open(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle child);
 [DllImport("KtmW32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern SafeFileHandle CreateTransaction(IntPtr attributes,IntPtr uow,uint options,uint isolation,uint flags,uint timeout,string description);
 [DllImport("KtmW32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]public static extern bool CommitTransaction(SafeFileHandle tx);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegOpenKeyTransactedW")]static extern int OpenTx(SafeRegistryHandle parent,string name,uint options,uint access,out SafeRegistryHandle child,SafeFileHandle tx,IntPtr reserved);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegDeleteKeyTransactedW")]static extern int DeleteTx(SafeRegistryHandle parent,string name,uint access,uint reserved,SafeFileHandle tx,IntPtr extended);
 public static RegistryKey Child(RegistryKey parent,string name,bool write,SafeFileHandle tx){SafeRegistryHandle handle;uint access=0x20119u|(write?6u:0u);int code=tx==null?Open(parent.Handle,name,8,access,out handle):OpenTx(parent.Handle,name,8,access,out handle,tx,IntPtr.Zero);if(code==2){if(handle!=null)handle.Dispose();return null;}if(code!=0){if(handle!=null)handle.Dispose();throw new InvalidOperationException("Cannot open owned sound component: "+code);}return RegistryKey.FromHandle(handle,RegistryView.Registry64);}
 public static void Delete(RegistryKey parent,string name,SafeFileHandle tx){int code=DeleteTx(parent.Handle,name,0x100,0,tx,IntPtr.Zero);if(code!=0)throw new InvalidOperationException("Conditional owned sound cleanup failed: "+code);}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out]byte[] data,ref uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegSetValueExW")]static extern int Set(SafeRegistryHandle key,string name,uint reserved,uint type,byte[] data,uint size);
 public static object Raw(RegistryKey key,string name){uint type,size=0;int code=Query(key.Handle,name,IntPtr.Zero,out type,null,ref size);if(code!=0||size>262144)throw new InvalidOperationException("Cannot size sound value: "+code);byte[] data=new byte[size];code=Query(key.Handle,name,IntPtr.Zero,out type,data,ref size);if(code!=0||size!=data.Length)throw new InvalidOperationException("Sound value changed while reading.");return new{name=name,type=type,data=Convert.ToBase64String(data)};}
 public static void Put(RegistryKey key,string name,uint type,byte[] data){int code=Set(key.Handle,name,0,type,data,(uint)data.Length);if(code!=0)throw new InvalidOperationException("Cannot write owned sound fixture: "+code);}
}
'@
$cu=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
function Key([string]$path,[bool]$write=$false,$tx=$null){
 $parts=$path.Split('\');$key=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
 for($i=0;$i -lt $parts.Length;$i++){try{$next=[SoundFixtureRaw]::Child($key,$parts[$i],($write -and $i -eq $parts.Length-1),$tx)}finally{$key.Dispose()};if(-not $next){return $null};$key=$next;if($key.GetValueNames() -icontains 'SymbolicLinkValue'){$key.Dispose();throw 'Registry links are outside sound fixture scope.'}}
 return $key
}
function Tree([string]$path,$tx=$null){$key=Key $path $false $tx;if(-not$key){return $null};try{$names=@($key.GetValueNames());[Array]::Sort($names,[StringComparer]::OrdinalIgnoreCase);$values=@(foreach($name in $names){[SoundFixtureRaw]::Raw($key,$name)});$children=@($key.GetSubKeyNames());[Array]::Sort($children,[StringComparer]::OrdinalIgnoreCase);$sub=@(foreach($child in $children){[ordered]@{name=$child;node=(Tree "$path\$child" $tx)}});return [ordered]@{acl=$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);values=$values;children=$sub}}finally{$key.Dispose()}}
function Delete-OwnedNode([string]$parent,[string]$name,$node,$tx){$path="$parent\$name";foreach($child in $node.children){Delete-OwnedNode $path $child.name $child.node $tx};$key=Key $parent $true $tx;try{[SoundFixtureRaw]::Delete($key,$name,$tx)}finally{$key.Dispose()}}
function Same($a,$b){($a|ConvertTo-Json -Depth 24 -Compress) -ceq ($b|ConvertTo-Json -Depth 24 -Compress)}
function EnvironmentState {
 $schemes=Key 'AppEvents\Schemes';$apps=Key $appsPath
 try{$selection=if($schemes.GetValueNames() -contains ''){[SoundFixtureRaw]::Raw($schemes,'')}else{$null};$others=@(foreach($name in @($apps.GetSubKeyNames()|Where-Object{$_ -ine $app}|Sort-Object)){[ordered]@{name=$name;node=(Tree "$appsPath\$name")}});[ordered]@{selection=$selection;appsAcl=$apps.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections);others=$others}}finally{$apps.Dispose();$schemes.Dispose()}
}
function Assert-Environment($before,$after){if(-not(Same $before.selection $after.selection) -or $before.appsAcl -cne $after.appsAcl){throw 'The selected sound scheme or existing Apps permissions changed.'};foreach($node in $before.others){$current=@($after.others|Where-Object{$_.name -ceq $node.name});if($current.Count -ne 1 -or -not(Same $node.node $current[0].node)){throw 'A pre-existing unrelated sound application changed.'}}}
if($Action -ceq 'create'){
 if((Test-Path -LiteralPath $descriptorPath) -or (Test-Path -LiteralPath $folder)){throw 'Owned sound fixture already exists.'}
 $existing=Key $appPath;if($existing){$existing.Dispose();throw 'Owned sound application already exists.'}
 $baseline=EnvironmentState
 New-Item -ItemType Directory -Path $folder -Force|Out-Null
 $fixtures=@();foreach($event in @('MissingOne','MissingTwo','Found','Empty','Absent','Expanded','Relative','Windows','WrongType','WrongExtension','Nested','SystemDefault')){
  $target=Join-Path $folder "$event.wav";$value=$target;$type=1
  switch($event){'Found'{[IO.File]::WriteAllBytes($target,[byte[]]@())};'Empty'{$value='';$target=$null};'Absent'{$target=$null};'Expanded'{$value="%LOCALAPPDATA%\$search\event.wav";$target=$null;$type=2};'Relative'{$value="$search.wav";$target=$null};'Windows'{$target=Join-Path $env:SystemRoot "Media\$search.wav";$value=$target};'WrongType'{$type=4};'WrongExtension'{$value=Join-Path $folder 'event.mp3';$target=$null}}
  $fixtures+=,[ordered]@{event=$event;target=$target;value=$value;type=$type;name="$app / $event / .Current"}
 }
 $descriptor=[ordered]@{token=$Token;ownerSid=$sid;folder=$folder;application=$app;baseline=$baseline;original=$null;fixtures=$fixtures;metadataConflict=$false}
 $descriptor|ConvertTo-Json -Depth 24|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
 $apps=Key $appsPath $true;try{$owned=$apps.CreateSubKey($app,$true);$owned.SetValue('DisplayLabel','Owned sound controls',[Microsoft.Win32.RegistryValueKind]::String);$owned.Dispose()}finally{$apps.Dispose()}
 foreach($f in $fixtures){$owned=Key $appPath $true;try{$event=$owned.CreateSubKey($f.event,$true)}finally{$owned.Dispose()};try{$event.SetValue('DisplayLabel','Preserved event metadata',[Microsoft.Win32.RegistryValueKind]::String);foreach($scheme in @('.Current','.Default','.None','OwnedSaved')){$key=$event.CreateSubKey($scheme,$true);try{$key.SetValue('Keep',[uint32]17,[Microsoft.Win32.RegistryValueKind]::DWord);if($scheme -ceq '.Current'){
     if($f.event -cne 'Absent'){$bytes=if($f.type -eq 4){[BitConverter]::GetBytes([uint32]17)}else{[Text.Encoding]::Unicode.GetBytes($f.value+[char]0+[char]0)};[SoundFixtureRaw]::Put($key,'',$f.type,$bytes)};if($f.event -ceq 'Nested'){$child=$key.CreateSubKey('PreserveChild');$child.SetValue('Keep','preserve');$child.Dispose()}
    }else{$text=if($scheme -ceq '.None'){''}else{Join-Path $folder "$($f.event)-saved.wav"};$key.SetValue('',$text,[Microsoft.Win32.RegistryValueKind]::String)}}finally{$key.Dispose()}}}finally{$event.Dispose()}}
 $descriptor.original=Tree $appPath;$descriptor|ConvertTo-Json -Depth 24|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}else{
 if(-not(Test-Path -LiteralPath $descriptorPath)){throw 'Owned sound descriptor is missing.'};$descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json
 if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $sid -or $descriptor.folder -cne $folder -or $descriptor.application -cne $app){throw 'Owned sound identity mismatch.'}
}
Assert-Environment $descriptor.baseline (EnvironmentState)
$target=Join-Path $folder 'MissingOne.wav'
if($Action -in @('conflict-file-create','conflict-file-remove')){if($Action -ceq 'conflict-file-create'){if(Test-Path -LiteralPath $target){throw 'Owned conflict already exists.'};[IO.File]::WriteAllBytes($target,[byte[]]@())}else{if(-not(Test-Path -LiteralPath $target) -or (Get-Item -LiteralPath $target).Length -ne 0){throw 'Owned file conflict changed.'};Remove-Item -LiteralPath $target}}
if($Action -in @('conflict-metadata-create','conflict-metadata-remove')){
 $key=Key "$appPath\MissingOne\.Default" $true
 try{if($Action -ceq 'conflict-metadata-create'){if($key.GetValueNames() -contains 'OwnedLateValue'){throw 'Owned metadata conflict exists.'};$key.SetValue('OwnedLateValue','preserve');$descriptor.metadataConflict=$true}else{if(-not $descriptor.metadataConflict -or $key.GetValue('OwnedLateValue') -cne 'preserve'){throw 'Owned metadata conflict changed.'};$key.DeleteValue('OwnedLateValue',$true);$descriptor.metadataConflict=$false}}finally{$key.Dispose()}
 $descriptor|ConvertTo-Json -Depth 24|Set-Content -LiteralPath $descriptorPath -Encoding UTF8
}
$tree=Tree $appPath
if($Action -ceq 'cleanup'){
 if($descriptor.metadataConflict){throw 'Remove the owned metadata conflict before cleanup.'}
 # Only the two intentionally mutable defaults may differ, and only by our exact empty assignment.
 $copy=$tree|ConvertTo-Json -Depth 24|ConvertFrom-Json
 foreach($event in @('MissingOne','MissingTwo')){$node=($copy.children|Where-Object{$_.name -ceq $event}).node;$current=($node.children|Where-Object{$_.name -ceq '.Current'}).node;$prior=((($descriptor.original.children|Where-Object{$_.name -ceq $event}).node.children|Where-Object{$_.name -ceq '.Current'}).node.values|Where-Object{$_.name -ceq ''});$actual=@($current.values|Where-Object{$_.name -ceq ''});if($actual.Count -ne 1){throw 'The owned current assignment is absent.'};if(-not(Same $actual[0] $prior) -and -not($actual[0].type -eq 1 -and $actual[0].data -ceq 'AAA=')){throw 'An owned sound assignment changed unexpectedly.'};$current.values=@($current.values|Where-Object{$_.name -cne ''})+@($prior);$current.values=@($current.values|Sort-Object name)}
 if(-not(Same $copy $descriptor.original)){throw 'Owned sound controls or permissions changed; cleanup stopped.'}
 foreach($file in @(Get-ChildItem -LiteralPath $folder -File)){if($file.Name -cne 'Found.wav' -or $file.Length -ne 0){throw 'Unexpected file in owned sound folder.'}}
 $tx=[SoundFixtureRaw]::CreateTransaction([IntPtr]::Zero,[IntPtr]::Zero,0,0,0,0,'RustRegistry owned sound fixture cleanup')
 try{if($tx.IsInvalid){throw 'Owned sound cleanup transactions are unavailable.'};if(-not(Same (Tree $appPath $tx) $tree)){throw 'Owned sound data changed before conditional cleanup.'};Delete-OwnedNode $appsPath $app $tree $tx;if(-not[SoundFixtureRaw]::CommitTransaction($tx)){throw 'Owned sound cleanup did not commit.'}}finally{$tx.Dispose()}
 foreach($file in @(Get-ChildItem -LiteralPath $folder -File)){Remove-Item -LiteralPath $file.FullName};if(@(Get-ChildItem -LiteralPath $folder).Count){throw 'Owned sound folder is not empty.'};Remove-Item -LiteralPath $folder
 Assert-Environment $descriptor.baseline (EnvironmentState);$tree=Tree $appPath;if($null -ne $tree){throw 'Owned sound application remains.'}
}
$cu.Dispose()
[ordered]@{token=$Token;search=$search;application=$app;fixtures=$descriptor.fixtures;tree=$tree;original=$descriptor.original;environmentPreserved=$true}|ConvertTo-Json -Depth 24 -Compress
