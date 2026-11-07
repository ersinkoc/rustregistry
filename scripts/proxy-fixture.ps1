param(
    [Parameter(Mandatory=$true)][ValidateSet('create','inspect','cleanup','conflict-create','conflict-remove')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token){throw 'Invalid fixture identifier.'}
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$directory=Join-Path $workspace '.temp_files\proxy-fixtures'
$descriptorPath=Join-Path $directory "$Token.json"
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$search=$Token.Replace('-','').Substring(0,24)
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
function Base($view){[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::$view)}
function Id($kind){$sha=[Security.Cryptography.SHA256]::Create();try{$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Token-$kind"));[Guid]::new([byte[]]$digest[0..15]).ToString('B')}finally{$sha.Dispose()}}
if($Action -eq 'create'){
    if(Test-Path -LiteralPath $descriptorPath){throw 'Owned fixture collision.'}
    $machine=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $user=Base 'Registry64';$user32=Base 'Registry32'
    try{$classes=$machine.OpenSubKey('Software\Classes\CLSID');try{
        $machineClsid=$null
        foreach($id in @($classes.GetSubKeyNames()|Sort-Object)){if($id -notmatch '^\{[a-fA-F0-9-]{36}\}$' -or $id -eq '{00000000-0000-0000-0000-000000000000}'){continue};$key=$user.OpenSubKey("Software\Classes\CLSID\$id");$other=$user32.OpenSubKey("Software\Classes\CLSID\$id");try{if(-not $key -and -not $other){$machineClsid=$id;break}}finally{if($key){$key.Dispose()};if($other){$other.Dispose()}}}
        if(-not $machineClsid){throw 'No read-only machine class control is available.'}
    }finally{$classes.Dispose()}}finally{$machine.Dispose();$user.Dispose();$user32.Dispose()}
    $machine=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $user=Base 'Registry64'
    try{$libraries=$machine.OpenSubKey('Software\Classes\TypeLib');try{
        $existingLibrary=$null
        foreach($id in @($libraries.GetSubKeyNames()|Sort-Object)){if($id -notmatch '^\{[a-fA-F0-9-]{36}\}$' -or $id -eq '{00000000-0000-0000-0000-000000000000}'){continue};$key=$user.OpenSubKey("Software\Classes\TypeLib\$id");if($key){$key.Dispose()}else{$existingLibrary=$id;break}}
        if(-not $existingLibrary){throw 'No read-only machine TypeLib control is available.'}
    }finally{$libraries.Dispose()}}finally{$machine.Dispose();$user.Dispose()}
}else{
    $descriptor=Get-Content -LiteralPath $descriptorPath -Raw|ConvertFrom-Json
    if($descriptor.token -cne $Token -or $descriptor.ownerSid -cne $owner){throw 'Owned fixture identity mismatch.'}
    $existingLibrary=$descriptor.existingLibrary
    if($existingLibrary -notmatch '^\{[a-fA-F0-9-]{36}\}$'){throw 'Invalid preserved library control.'}
    $machineClsid=$descriptor.machineClsid
    if($machineClsid -notmatch '^\{[a-fA-F0-9-]{36}\}$'){throw 'Invalid machine control.'}
}
$fixtures=@(foreach($kind in @('One','Two','Found32','Found64','Machine','Complex','Malformed','ReadOnly32')){
    [ordered]@{kind=$kind;iid=(Id "interface-$kind");clsid=$(if($kind -eq 'Machine'){$machineClsid}else{Id "library-$kind"});name="RR.$search.$kind"}
})
$ids=@($fixtures|ForEach-Object{$_.iid});$clsids=@($fixtures|Where-Object{$_.kind -ne 'Machine'}|ForEach-Object{$_.clsid})
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ProxyFixtureReader {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,EntryPoint="RegQueryValueExW")]
    private static extern int Query(SafeRegistryHandle key,string name,IntPtr reserved,out uint type,[Out] byte[] data,ref uint size);
    public static string Read(SafeRegistryHandle key,string name,out uint type) {
        uint size=0;int code=Query(key,name,IntPtr.Zero,out type,null,ref size);
        if(code!=0||size>262144)throw new InvalidOperationException("Cannot size value: "+code);
        byte[] data=new byte[size];code=Query(key,name,IntPtr.Zero,out type,data,ref size);
        if(code!=0||size>data.Length)throw new InvalidOperationException("Cannot read value: "+code);
        return Convert.ToBase64String(data,0,(int)size);
    }
}
'@
function Read-Values($key){@($key.GetValueNames()|Sort-Object|ForEach-Object{[uint32]$kind=0;$bytes=[ProxyFixtureReader]::Read($key.Handle,$_ ,[ref]$kind);[ordered]@{name=$_;kind=$kind;bytes=$bytes}})}
function Security($key){$key.GetAccessControl($sections).GetSecurityDescriptorSddlForm($sections)}
function Read-Tree($key,$path='',$depth=0){
    if($depth -gt 3 -or $key.ValueCount -gt 8 -or $key.SubKeyCount -gt 8){throw 'Unexpected owned tree.'}
    [ordered]@{path=$path;values=@(Read-Values $key);security=Security $key}
    foreach($name in @($key.GetSubKeyNames()|Sort-Object)){$child=$key.OpenSubKey($name);try{Read-Tree $child $(if($path){"$path\$name"}else{$name}) ($depth+1)}finally{$child.Dispose()}}
}
function Read-Views {
    foreach($view in @('Registry64','Registry32')){
        $base=Base $view
        try{$root=$base.OpenSubKey('Software\Classes\Interface');$classes=$base.OpenSubKey('Software\Classes\CLSID')
            if(-not $root -or -not $classes){throw 'Existing Interface and CLSID roots are required.'}
            try{
                $interfaces=@(foreach($fixture in $fixtures){$key=$root.OpenSubKey($fixture.iid);if($key){try{[ordered]@{kind=$fixture.kind;iid=$fixture.iid;exists=$true;nodes=@(Read-Tree $key)}}finally{$key.Dispose()}}else{[ordered]@{kind=$fixture.kind;iid=$fixture.iid;exists=$false;nodes=@()}}})
                $targets=@(foreach($fixture in @($fixtures|Where-Object{$_.kind -ne 'Machine'})){$key=$classes.OpenSubKey($fixture.clsid);if($key){try{[ordered]@{kind=$fixture.kind;clsid=$fixture.clsid;exists=$true;nodes=@(Read-Tree $key)}}finally{$key.Dispose()}}else{[ordered]@{kind=$fixture.kind;clsid=$fixture.clsid;exists=$false;nodes=@()}}})
                [ordered]@{view=$view;rootSecurity=Security $root;rootValues=@(Read-Values $root);otherInterfaceIds=@($root.GetSubKeyNames()|Sort-Object|Where-Object{$_ -notin $ids});classRootSecurity=Security $classes;classRootValues=@(Read-Values $classes);otherClassIds=@($classes.GetSubKeyNames()|Sort-Object|Where-Object{$_ -notin $clsids});interfaces=$interfaces;targets=$targets}
            }finally{$root.Dispose();$classes.Dispose()}
        }finally{$base.Dispose()}
    }
}
function Check-Roots($views,$baseline){foreach($view in $views){$before=$baseline|Where-Object{$_.view -ceq $view.view};foreach($name in @('rootSecurity','rootValues','otherInterfaceIds','classRootSecurity','classRootValues','otherClassIds')){if((ConvertTo-Json -InputObject $view.$name -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $before.$name -Depth 6 -Compress)){throw "Unrelated registry $name changed. No unrelated data will be overwritten."}}}}
function Marker($kind){"RustRegistry owned proxy class $Token $kind"}
if($Action -eq 'create'){
    $baseline=@(Read-Views)
    if(@($baseline.interfaces|Where-Object{$_.exists}).Count -ne 0 -or @($baseline.targets|Where-Object{$_.exists}).Count -ne 0){throw 'Owned registry fixture collision.'}
    New-Item -ItemType Directory -Path $directory -Force|Out-Null
    $descriptor=[ordered]@{token=$Token;ownerSid=$owner;machineClsid=$machineClsid;existingLibrary=$existingLibrary;baseline=$baseline;originalViews=$null}
    [IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
    foreach($view in @('Registry64','Registry32')){
        $base=Base $view
        try{$root=$base.OpenSubKey('Software\Classes\Interface',$true);try{
            foreach($fixture in $fixtures){
                if(($view -eq 'Registry64' -and $fixture.kind -eq 'ReadOnly32') -or ($view -eq 'Registry32' -and $fixture.kind -notin @('One','ReadOnly32'))){continue}
                $key=$root.CreateSubKey($fixture.iid)
                try{$key.SetValue('',($fixture.name+$(if($view -eq 'Registry32' -and $fixture.kind -eq 'One'){'32'}else{''})),[Microsoft.Win32.RegistryValueKind]::String)
                    $leaf=$key.CreateSubKey('ProxyStubClsid32');try{$leaf.SetValue('',$(if($fixture.kind -eq 'Malformed'){'%LIBID%'}else{$fixture.clsid}),$(if($fixture.kind -eq 'One'){[Microsoft.Win32.RegistryValueKind]::ExpandString}else{[Microsoft.Win32.RegistryValueKind]::String}))}finally{$leaf.Dispose()}
                    $proxy=$key.CreateSubKey('TypeLib');try{$proxy.SetValue('',$existingLibrary,[Microsoft.Win32.RegistryValueKind]::String);$proxy.SetValue('Version','1.0',[Microsoft.Win32.RegistryValueKind]::String)}finally{$proxy.Dispose()}
                    if($fixture.kind -eq 'Complex'){$child=$key.CreateSubKey('NumMethods');try{$child.SetValue('','3',[Microsoft.Win32.RegistryValueKind]::String)}finally{$child.Dispose()}}
                }finally{$key.Dispose()}
            }
        }finally{$root.Dispose()}}finally{$base.Dispose()}
    }
    foreach($control in @(@{kind='Found32';view='Registry32'},@{kind='Found64';view='Registry64'})){
        $found=$fixtures|Where-Object{$_.kind -ceq $control.kind};$base=Base $control.view
        try{$key=$base.CreateSubKey("Software\Classes\CLSID\$($found.clsid)");try{$key.SetValue('',(Marker $found.kind),[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}finally{$base.Dispose()}
    }
    $descriptor.originalViews=@(Read-Views)
    [IO.File]::WriteAllText($descriptorPath,($descriptor|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
}
if($descriptor.originalViews.Count -ne 2){throw 'Owned fixture setup is incomplete.'}
$views=@(Read-Views);Check-Roots $views $descriptor.baseline
if($Action -in @('conflict-create','conflict-remove')){
    $one=$fixtures|Where-Object{$_.kind -ceq 'One'};$base=Base 'Registry32'
    try{$root=$base.OpenSubKey('Software\Classes\CLSID',$true);try{$existing=$root.OpenSubKey($one.clsid)
        if($Action -eq 'conflict-create'){if($existing){$existing.Dispose();throw 'Conflict control already exists.'};$key=$root.CreateSubKey($one.clsid);try{$key.SetValue('',(Marker 'One'),[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Dispose()}}
        else{if(-not $existing){throw 'Owned conflict control missing.'};try{if($existing.ValueCount -ne 1 -or $existing.SubKeyCount -ne 0 -or $existing.GetValueKind('') -ne [Microsoft.Win32.RegistryValueKind]::String -or $existing.GetValue('') -cne (Marker 'One')){throw 'Owned conflict control changed.'}}finally{$existing.Dispose()};$root.DeleteSubKey($one.clsid,$true)}
    }finally{$root.Dispose()}}finally{$base.Dispose()}
    $views=@(Read-Views);Check-Roots $views $descriptor.baseline
}
if($Action -eq 'cleanup'){
    foreach($view in $views){$original=$descriptor.originalViews|Where-Object{$_.view -ceq $view.view}
        foreach($interface in $view.interfaces){$expected=($original.interfaces|Where-Object{$_.iid -ceq $interface.iid})|ConvertTo-Json -Depth 12|ConvertFrom-Json
            if($view.view -eq 'Registry64' -and $interface.kind -in @('One','Two')){$leaf=$interface.nodes|Where-Object{$_.path -ceq 'ProxyStubClsid32'};if($leaf -and @($leaf.values|Where-Object{$_.name -ceq ''}).Count -eq 0){($expected.nodes|Where-Object{$_.path -ceq 'ProxyStubClsid32'}).values=@(($expected.nodes|Where-Object{$_.path -ceq 'ProxyStubClsid32'}).values|Where-Object{$_.name -cne ''})}}
            if(($interface|ConvertTo-Json -Depth 12 -Compress) -cne ($expected|ConvertTo-Json -Depth 12 -Compress)){throw 'Owned interface data or permissions changed. Cleanup stopped.'}
        }
        foreach($target in $view.targets){$expected=$original.targets|Where-Object{$_.clsid -ceq $target.clsid};if(($target|ConvertTo-Json -Depth 12 -Compress) -cne ($expected|ConvertTo-Json -Depth 12 -Compress)){throw 'Owned class control changed. Remove any owned conflict before cleanup.'}}
    }
    foreach($view in $views){$base=Base $view.view;try{$root=$base.OpenSubKey('Software\Classes\Interface',$true);try{foreach($interface in @($view.interfaces|Where-Object{$_.exists})){foreach($node in @($interface.nodes|Sort-Object{$_.path.Length} -Descending)){$path=if($node.path){"$($interface.iid)\$($node.path)"}else{$interface.iid};$root.DeleteSubKey($path,$true)}}}finally{$root.Dispose()}}finally{$base.Dispose()}}
    foreach($view in $views){$base=Base $view.view;try{$root=$base.OpenSubKey('Software\Classes\CLSID',$true);try{foreach($target in @($view.targets|Where-Object{$_.exists})){$root.DeleteSubKey($target.clsid,$true)}}finally{$root.Dispose()}}finally{$base.Dispose()}}
    $views=@(Read-Views);Check-Roots $views $descriptor.baseline
}
[ordered]@{token=$Token;search=$search;fixtures=$fixtures;views=$views}|ConvertTo-Json -Depth 12 -Compress
