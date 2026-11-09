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
