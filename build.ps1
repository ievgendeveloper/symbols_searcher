# scripts/build.ps1
#
# Finds Visual Studio via vswhere, then runs vcvars + the build
# in a single cmd.exe session — no environment transfer, no temp files.
#
# Usage:
#   .\scripts\build.ps1              # configure + build + test (debug)
#   .\scripts\build.ps1 release      # release preset
#   .\scripts\build.ps1 -NoTest      # skip ctest

[CmdletBinding()]
param(
    [string]$Preset = 'debug',
    [switch]$NoTest
)

$ErrorActionPreference = 'Stop'

# Locate vswhere
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere.exe not found. Visual Studio 2017+ or Build Tools required."
    exit 1
}

# Find latest VS installation with C++ tools
$vsRoot = & $vswhere -latest -prerelease `
    -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath

if (-not $vsRoot) {
    Write-Error "No Visual Studio installation with MSVC found."
    exit 1
}

$vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) {
    Write-Error "vcvars64.bat not found at: $vcvars"
    exit 1
}

Write-Host "Using MSVC from: $vsRoot" -ForegroundColor Cyan

# Build the cmd commands chain. Each step uses && so the next runs only
# if the previous succeeded. All inside one cmd.exe — vcvars sets env,
# cmake/ctest see it.
$commands = @(
    "`"$vcvars`"",
    "cmake --preset $Preset",
    "cmake --build --preset $Preset"
)
if (-not $NoTest) {
    $commands += "ctest --preset $Preset"
}

$cmdLine = $commands -join ' && '
cmd.exe /c $cmdLine
exit $LASTEXITCODE

# powershell.exe -Executionpolicy Bypass -File "build.ps1"