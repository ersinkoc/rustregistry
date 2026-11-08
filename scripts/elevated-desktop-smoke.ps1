param(
    [ValidateSet('prepare','run')][string]$Action='prepare',
    [ValidateSet('shared-dll-only','full')][string]$Mode='shared-dll-only',
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9-]{36}$')][string]$Token,
    [string]$Executable,
    [string]$OwnerSid,
    [string]$NodePath,
    [string]$ExpectedSHA256,
    [ValidatePattern('^[a-f0-9-]{36}$')][string]$ServiceToken
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if ([Guid]::ParseExact($Token,'D').ToString('D') -cne $Token) { throw 'Invalid fixture identifier.' }
$workspace=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if (-not $Executable) { $Executable=Join-Path $workspace 'target\release\rustregistry.exe' }
$Executable=[IO.Path]::GetFullPath($Executable)
if (-not $Executable.StartsWith($workspace+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($Executable) -ine 'rustregistry.exe' -or -not [IO.File]::Exists($Executable)) { throw 'An existing RustRegistry executable inside this workspace is required.' }
$version=(Get-Content -LiteralPath (Join-Path $workspace 'package.json') -Raw | ConvertFrom-Json).version
if ([Diagnostics.FileVersionInfo]::GetVersionInfo($Executable).ProductVersion -cne $version) { throw 'The executable version does not match the current source.' }
$output=Join-Path $workspace '.temp_files'
$resultPath=Join-Path $output "elevated-$Mode-$Token.json"
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($Action -eq 'prepare') {
    if (Test-Path -LiteralPath $resultPath) { throw 'Elevated test result already exists.' }
    $OwnerSid=$identity.User.Value
    $NodePath=(Get-Command node.exe -ErrorAction Stop).Source
    $ExpectedSHA256=(Get-FileHash -LiteralPath $Executable).Hash
    $arguments=@('-NoProfile','-NonInteractive','-File',('"'+$PSCommandPath+'"'),'-Action','run','-Mode',$Mode,'-Token',$Token,'-Executable',('"'+$Executable+'"'),'-OwnerSid',$OwnerSid,'-NodePath',('"'+$NodePath+'"'),'-ExpectedSHA256',$ExpectedSHA256)
    if ($ServiceToken) { $arguments+=@('-ServiceToken',$ServiceToken) }
    # This explicit developer test setup elevates the test process, never the production app or normal smoke command.
    $helper=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru
    # The full suite re-scans all 58 sections after each repair/restore, including
    # thousands of real MUI cache paths. A large live cache can exceed 30 minutes.
    # This is only the outer process-wait budget; individual test deadlines stay unchanged.
    $sessionTimeout=if($Mode -eq 'full'){2700000}else{600000}
    if (-not $helper.WaitForExit($sessionTimeout)) { throw 'The elevated test session is still running. Inspect its private log before continuing.' }
    if ($helper.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $resultPath)) { throw "Elevated desktop verification failed. Inspect .temp_files/elevated-$Mode-$Token.stdout.log and stderr.log." }
    Get-Content -LiteralPath $resultPath -Raw
    exit
}
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -cne $OwnerSid) { throw 'The explicit test session must run elevated under the same Windows account.' }
if (-not [IO.File]::Exists($NodePath) -or [IO.Path]::GetFileName($NodePath) -ine 'node.exe' -or (Get-FileHash -LiteralPath $Executable).Hash -cne $ExpectedSHA256) { throw 'Elevated test input identity changed.' }
[Diagnostics.Process]::GetCurrentProcess().PriorityClass=[Diagnostics.ProcessPriorityClass]::Normal
$env:RUSTREGISTRY_EXE=$Executable
$env:RUSTREGISTRY_SOURCE_EXE=$Executable
$aliasDirectory=Join-Path $output "elevated-executables\$Token"
if (Test-Path -LiteralPath $aliasDirectory) { throw 'Owned executable directory already exists.' }
New-Item -ItemType Directory -Path $aliasDirectory | Out-Null
$aliasExecutable=Join-Path $aliasDirectory "RustRegistry-E2E-WebView-$Token.exe"
Copy-Item -LiteralPath $Executable -Destination $aliasExecutable
if ((Get-FileHash -LiteralPath $aliasExecutable).Hash -cne $ExpectedSHA256) { throw 'The owned test executable copy does not match the package.' }
$env:RUSTREGISTRY_EXE=$aliasExecutable
$env:RUSTREGISTRY_ELEVATED_WEBVIEW_TOKEN=$Token
$env:RUSTREGISTRY_SHARED_DLL_FIXTURE_TOKEN=$Token
if ($ServiceToken) { $env:RUSTREGISTRY_SERVICE_FIXTURE_TOKEN=$ServiceToken } else { Remove-Item Env:\RUSTREGISTRY_SERVICE_FIXTURE_TOKEN -ErrorAction SilentlyContinue }
$arguments=@(('"'+(Join-Path $workspace 'scripts\desktop-smoke.mjs')+'"'))
if ($Mode -eq 'shared-dll-only') { $arguments+='--shared-dll-only' }
$stdout=Join-Path $output "elevated-$Mode-$Token.stdout.log"
$stderr=Join-Path $output "elevated-$Mode-$Token.stderr.log"
$process=Start-Process -FilePath $NodePath -ArgumentList $arguments -WorkingDirectory $workspace -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
$reportName=if ($Mode -eq 'full') { 'desktop-verification.json' } else { 'desktop-shared-dll-verification.json' }
$reportPath=Join-Path $output $reportName
$passed=$false
if (Test-Path -LiteralPath $reportPath) { $report=Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json; $passed=$process.ExitCode -eq 0 -and $report.passed -and $report.version -ceq $version -and $report.sharedDllFixtureCleanup -eq $true -and $report.errors.Count -eq 0 }
[ordered]@{ mode=$Mode; token=$Token; exitCode=$process.ExitCode; passed=$passed; reportPath=$reportPath; executableSHA256=$ExpectedSHA256; sameWindowsAccount=$true } | ConvertTo-Json -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8
if (-not $passed) { exit 1 }
