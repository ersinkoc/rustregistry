[CmdletBinding()]
param([Parameter(Mandatory)][string]$Executable)

$ErrorActionPreference = 'Stop'
if (-not ('RustRegistryStartupWindow' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class RustRegistryStartupWindow {
    private delegate bool WindowCallback(IntPtr window, IntPtr data);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(WindowCallback callback, IntPtr data);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint owner);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr window, StringBuilder title, int count);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr window, uint message, IntPtr wparam, IntPtr lparam,
        uint flags, uint timeout, out UIntPtr result);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool PostMessage(IntPtr window, uint message, IntPtr wparam, IntPtr lparam);

    public static IntPtr Find(uint processId) {
        IntPtr result = IntPtr.Zero;
        EnumWindows((window, data) => {
            uint owner;
            GetWindowThreadProcessId(window, out owner);
            if (owner != processId) return true;
            var title = new StringBuilder(64);
            GetWindowText(window, title, title.Capacity);
            if (title.ToString() != "RustRegistry") return true;
            result = window;
            return false;
        }, IntPtr.Zero);
        return result;
    }

    public static bool IsResponsive(IntPtr window) {
        UIntPtr result;
        return SendMessageTimeout(window, 0, IntPtr.Zero, IntPtr.Zero, 2, 3000, out result) != IntPtr.Zero;
    }

    public static bool Close(IntPtr window, uint processId) {
        uint owner;
        GetWindowThreadProcessId(window, out owner);
        return owner == processId && PostMessage(window, 0x10, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
}

$file = Get-Item -LiteralPath $Executable
$app = Start-Process -FilePath $file.FullName -WorkingDirectory $file.DirectoryName -WindowStyle Hidden -PassThru
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $window = [IntPtr]::Zero
    while ([DateTime]::UtcNow -lt $deadline -and -not $app.HasExited) {
        $window = [RustRegistryStartupWindow]::Find($app.Id)
        if ($window -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($window -eq [IntPtr]::Zero -or -not [RustRegistryStartupWindow]::IsResponsive($window)) {
        throw 'The packaged GPUI window did not become responsive.'
    }
    if (-not [RustRegistryStartupWindow]::Close($window, $app.Id) -or -not $app.WaitForExit(15000)) {
        throw 'The packaged application did not close cleanly.'
    }
    if ($app.ExitCode -ne 0) { throw "The packaged application exited with $($app.ExitCode)." }
    Write-Output 'The packaged GPUI window opened, responded, and exited with code 0.'
}
finally {
    if (-not $app.HasExited) { $app.Kill(); $app.WaitForExit(5000) | Out-Null }
    $app.Dispose()
}
