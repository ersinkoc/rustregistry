param(
    [Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-create','conflict-remove')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token) {throw 'Invalid fixture identifier.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$descriptorDirectory=Join-Path $workspace '.temp_files\prog-id-fixtures'
$descriptorPath=Join-Path $descriptorDirectory "$Token.json"
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$search=$Token.Replace('-','').Substring(0,24)
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
if($Action -eq 'create') {
    if(Test-Path -LiteralPath $descriptorPath) {throw 'Owned fixture descriptor collision.'}
    $machine=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $user64=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
    $user32=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry32)
    try {
        $classes=$machine.OpenSubKey('Software\Classes\CLSID')
        try {
            $machineClsid=$null
            foreach($id in @($classes.GetSubKeyNames() | Sort-Object)) {
                if($id -notmatch '^\{[a-fA-F0-9-]{36}\}$' -or $id -eq '{00000000-0000-0000-0000-000000000000}') {continue}
                $a=$user64.OpenSubKey("Software\Classes\CLSID\$id");$b=$user32.OpenSubKey("Software\Classes\CLSID\$id")
                try {if(-not $a -and -not $b){$machineClsid=$id;break}} finally {if($a){$a.Dispose()};if($b){$b.Dispose()}}
            }
            if(-not $machineClsid) {throw 'No read-only machine CLSID control could be selected.'}
        } finally {$classes.Dispose()}
    } finally {$machine.Dispose();$user64.Dispose();$user32.Dispose()}
} else {
    $descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json
    if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $owner) {throw 'Owned fixture identity mismatch.'}
    $machineClsid=$descriptor.machineClsid
    if($machineClsid -notmatch '^\{[a-fA-F0-9-]{36}\}$') {throw 'Invalid read-only machine control.'}
}
$fixtures=@()
foreach($kind in @('One','Two','Found32','Found64','Machine','Complex','Malformed')) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Token-$kind"))}finally{$sha.Dispose()}
    $id=if($kind -eq 'Machine'){$machineClsid}else{[Guid]::new([byte[]]$digest[0..15]).ToString('B')}
    $fixtures+=[ordered]@{kind=$kind;progId="RR.$search.$kind";clsid=$id;description="RustRegistry owned ProgID $Token $kind"}
}
$names=@($fixtures|ForEach-Object{$_.progId})
$managedIds=@($fixtures|Where-Object{$_.kind -ne 'Machine'}|ForEach-Object{$_.clsid})
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ProgIdFixtureReader {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]
    private static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out] byte[] data,ref uint size);
    public static string Read(SafeRegistryHandle key,string name,out uint type) {
        uint size=0;int code=Query(key,name,IntPtr.Zero,out type,null,ref size);
        if(code!=0||size>262144)throw new InvalidOperationException("Cannot size registry value: "+code);
        byte[] data=new byte[size];code=Query(key,name,IntPtr.Zero,out type,data,ref size);
        if(code!=0||size>data.Length)throw new InvalidOperationException("Cannot read registry value: "+code);
        return Convert.ToBase64String(data,0,(int)size);
    }
}
'@
function Read-Values($key) {
    @($key.GetValueNames()|Sort-Object|ForEach-Object{[uint32]$kind=0;$bytes=[ProgIdFixtureReader]::Read($key.Handle,$_ ,[ref]$kind);[ordered]@{name=$_;kind=$kind;bytes=$bytes}})
}
function Security($key) {$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)}
function Read-Tree($key,$path='',$depth=0) {
    if($depth -gt 3 -or $key.ValueCount -gt 8 -or $key.SubKeyCount -gt 8){throw 'Unexpected owned ProgID tree.'}
    [ordered]@{path=$path;values=@(Read-Values $key);security=Security $key}
    foreach($name in @($key.GetSubKeyNames()|Sort-Object)){$child=$key.OpenSubKey($name);try{Read-Tree $child $(if($path){"$path\$name"}else{$name}) ($depth+1)}finally{$child.Dispose()}}
}
function Read-Views {
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,$view)
        try {
            $root=$base.OpenSubKey('Software\Classes');$classes=$base.OpenSubKey('Software\Classes\CLSID')
            if(-not $root -or -not $classes){throw 'Existing Classes and CLSID roots in both views are required.'}
            try {
                $programs=@(foreach($fixture in $fixtures){$key=$root.OpenSubKey($fixture.progId);if($key){try{[ordered]@{kind=$fixture.kind;progId=$fixture.progId;exists=$true;nodes=@(Read-Tree $key)}}finally{$key.Dispose()}}else{[ordered]@{kind=$fixture.kind;progId=$fixture.progId;exists=$false;nodes=@()}}})
                $targets=@(foreach($fixture in @($fixtures|Where-Object{$_.kind -ne 'Machine'})){$key=$classes.OpenSubKey($fixture.clsid);if($key){try{[ordered]@{kind=$fixture.kind;clsid=$fixture.clsid;exists=$true;nodes=@(Read-Tree $key)}}finally{$key.Dispose()}}else{[ordered]@{kind=$fixture.kind;clsid=$fixture.clsid;exists=$false;nodes=@()}}})
                [ordered]@{view=$view.ToString();rootSecurity=Security $root;rootValues=@(Read-Values $root);otherProgIdNames=@($root.GetSubKeyNames()|Sort-Object|Where-Object{$_ -notin $names});classRootSecurity=Security $classes;classRootValues=@(Read-Values $classes);otherClassIds=@($classes.GetSubKeyNames()|Sort-Object|Where-Object{$_ -notin $managedIds});programs=$programs;targets=$targets}
            }finally{$classes.Dispose();$root.Dispose()}
        }finally{$base.Dispose()}
    }
}
function Check-Roots($views,$baseline) {
    foreach($view in $views){$before=$baseline|Where-Object{$_.view -ceq $view.view};foreach($name in @('rootSecurity','rootValues','otherProgIdNames','classRootSecurity','classRootValues','otherClassIds')){if((ConvertTo-Json -InputObject $view.$name -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $before.$name -Depth 6 -Compress)){throw "Unrelated Classes/$name changed. No unrelated data will be overwritten."}}}
}
function Class-Marker($kind) {"RustRegistry owned ProgID class $Token $kind"}
if($Action -eq 'create') {
    $baseline=@(Read-Views)
    if(@($baseline.programs|Where-Object{$_.exists}).Count -ne 0 -or @($baseline.targets|Where-Object{$_.exists}).Count -ne 0){throw 'Owned fixture collision.'}
    New-Item -ItemType Directory -Path $descriptorDirectory -Force|Out-Null
    $descriptor=[ordered]@{token=$Token;ownerSid=$owner;machineClsid=$machineClsid;baseline=$baseline;originalViews=$null}
    [IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
    try {$root=$base.OpenSubKey('Software\Classes',$true);try{foreach($fixture in $fixtures){$key=$root.CreateSubKey($fixture.progId);try{$key.SetValue('',$fixture.description,[Microsoft.Win32.RegistryValueKind]::String);$leaf=$key.CreateSubKey('CLSID');try{$value=if($fixture.kind -eq 'Malformed'){'not-a-guid'}else{$fixture.clsid};$kind=if($fixture.kind -eq 'One'){[Microsoft.Win32.RegistryValueKind]::ExpandString}else{[Microsoft.Win32.RegistryValueKind]::String};$leaf.SetValue('',$value,$kind)}finally{$leaf.Dispose()};if($fixture.kind -eq 'Complex'){$child=$key.CreateSubKey('CurVer');try{$child.SetValue('',$fixture.progId,[Microsoft.Win32.RegistryValueKind]::String)}finally{$child.Dispose()}}}finally{$key.Dispose()}}}finally{$root.Dispose()}}finally{$base.Dispose()}
    foreach($control in @(@{kind='Found32';view=[Microsoft.Win32.RegistryView]::Registry32},@{kind='Found64';view=[Microsoft.Win32.RegistryView]::Registry64})){$fixture=$fixtures|Where-Object{$_.kind -ceq $control.kind};$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,$control.view);try{$classes=$base.OpenSubKey('Software\Classes\CLSID',$true);try{$key=$classes.CreateSubKey($fixture.clsid);try{$key.SetValue('',(Class-Marker $fixture.kind),[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}finally{$classes.Dispose()}}finally{$base.Dispose()}}
    $descriptor.originalViews=@(Read-Views)
    [IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
}
if($descriptor.originalViews.Count -ne 2){throw 'Owned fixture setup is incomplete.'}
$views=@(Read-Views);Check-Roots $views $descriptor.baseline
if($Action -in @('conflict-create','conflict-remove')){
    $one=$fixtures|Where-Object{$_.kind -ceq 'One'};$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry32)
    try{$classes=$base.OpenSubKey('Software\Classes\CLSID',$true);try{$existing=$classes.OpenSubKey($one.clsid);if($Action -eq 'conflict-create'){if($existing){$existing.Dispose();throw 'Conflict control already exists.'};$key=$classes.CreateSubKey($one.clsid);try{$key.SetValue('',(Class-Marker 'One'),[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}else{if(-not $existing){throw 'Owned conflict control is missing.'};try{if($existing.ValueCount -ne 1 -or $existing.SubKeyCount -ne 0 -or $existing.GetValueKind('') -ne [Microsoft.Win32.RegistryValueKind]::String -or $existing.GetValue('') -cne (Class-Marker 'One')){throw 'Owned conflict control changed.'}}finally{$existing.Dispose()};$classes.DeleteSubKey($one.clsid,$true)}}finally{$classes.Dispose()}}finally{$base.Dispose()}
    $views=@(Read-Views);Check-Roots $views $descriptor.baseline
}
if($Action -eq 'cleanup'){
    foreach($view in $views){$original=$descriptor.originalViews|Where-Object{$_.view -ceq $view.view};foreach($program in $view.programs){$expected=($original.programs|Where-Object{$_.progId -ceq $program.progId})|ConvertTo-Json -Depth 12|ConvertFrom-Json;if($program.kind -in @('One','Two')){$leaf=$program.nodes|Where-Object{$_.path -ceq 'CLSID'};if($leaf -and $leaf.values.Count -eq 0){($expected.nodes|Where-Object{$_.path -ceq 'CLSID'}).values=@()}};if(($program|ConvertTo-Json -Depth 12 -Compress) -cne ($expected|ConvertTo-Json -Depth 12 -Compress)){throw 'Owned ProgID metadata or permissions changed. Cleanup stopped.'}};foreach($target in $view.targets){if($target.kind -eq 'One' -and $view.view -eq 'Registry32' -and $target.exists){if($target.nodes.Count -ne 1 -or $target.nodes[0].values.Count -ne 1 -or $target.nodes[0].values[0].name -cne '' -or $target.nodes[0].values[0].kind -ne 1 -or $target.nodes[0].values[0].bytes -cne [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((Class-Marker 'One')+[char]0))){throw 'Owned conflict class changed.'}}else{$expected=$original.targets|Where-Object{$_.clsid -ceq $target.clsid};if(($target|ConvertTo-Json -Depth 12 -Compress) -cne ($expected|ConvertTo-Json -Depth 12 -Compress)){throw 'A class control changed. Cleanup stopped.'}}}}
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
    try{$root=$base.OpenSubKey('Software\Classes',$true);try{foreach($program in $views[0].programs){foreach($node in @($program.nodes|Sort-Object{$_.path.Length} -Descending)){$path=if($node.path){"$($program.progId)\$($node.path)"}else{$program.progId};$root.DeleteSubKey($path,$true)}}}finally{$root.Dispose()}}finally{$base.Dispose()}
    foreach($view in $views){$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::$($view.view));try{$classes=$base.OpenSubKey('Software\Classes\CLSID',$true);try{foreach($target in @($view.targets|Where-Object{$_.exists})){$classes.DeleteSubKey($target.clsid,$true)}}finally{$classes.Dispose()}}finally{$base.Dispose()}}
    $views=@(Read-Views);Check-Roots $views $descriptor.baseline
}
[ordered]@{token=$Token;search=$search;fixtures=$fixtures;views=$views}|ConvertTo-Json -Depth 12 -Compress
