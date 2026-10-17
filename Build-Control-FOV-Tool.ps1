$ErrorActionPreference = 'Stop'
$sourceDir = $PSScriptRoot
$compilerCandidates = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$compiler = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compiler) { throw 'Could not find the .NET Framework C# compiler (csc.exe).' }
$automationGac = Join-Path $env:WINDIR 'Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation'
$automationAssembly = Get-ChildItem -LiteralPath $automationGac -Filter 'System.Management.Automation.dll' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $automationAssembly) {
    $automationAssembly = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\System.Management.Automation.dll'
}
if (-not (Test-Path -LiteralPath $automationAssembly)) { throw 'Could not find the Windows PowerShell 5.1 assembly in the .NET GAC or Windows PowerShell folder.' }
$scriptFile = Join-Path $sourceDir 'Control-FOV-Tool.ps1'
$launcherFile = Join-Path $sourceDir 'ControlFOVLauncher.cs'
$iconFile = Join-Path $sourceDir 'ControlFOV.ico'
foreach ($file in @($scriptFile, $launcherFile, $iconFile)) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Required source file is missing: $file" }
}
$distDir = Join-Path $sourceDir 'dist'
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
$outputFile = Join-Path $distDir 'Control FOV Tool.exe'
$resource = "$scriptFile,ControlFOVTool.ps1"
$arguments = @(
    '/nologo', '/target:winexe', '/platform:x64',
    "/win32icon:$iconFile",
    "/out:$outputFile",
    "/reference:$automationAssembly",
    '/reference:System.Windows.Forms.dll',
    "/resource:$resource",
    $launcherFile
)
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw "C# compilation failed with exit code $LASTEXITCODE." }
Write-Host "Build complete: $outputFile"
