# scripts/build.ps1
[CmdletBinding()]
param(
    [string]$preset = 'debug',
    [switch]$noTest
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Ensure Chocolatey is installed
# ---------------------------------------------------------------------------
if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
    Write-Host 'Chocolatey not found — installing...' -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Refresh PATH for the current session so choco.exe becomes callable
    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = $machinePath, $userPath -join ';'
    
    if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
        Write-Error 'Chocolatey installation appears to have failed.'
        exit 1
    }
    Write-Host 'Chocolatey installed.' -ForegroundColor Green
} else {
    Write-Host 'Chocolatey already present.' -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Ensure re2c is installed
# ---------------------------------------------------------------------------
if (-not (Get-Command re2c.exe -ErrorAction SilentlyContinue)) {
    Write-Host 'Installing re2c via Chocolatey...' -ForegroundColor Yellow
    choco install re2c -y --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Error ('Failed to install re2c (choco exit code ' + $LASTEXITCODE + ').')
        exit 1
    }

    # Refresh PATH again so re2c.exe becomes callable in this session
    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = $machinePath, $userPath -join ';'    
} else {
    Write-Host 're2c already present.' -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Locate Visual Studio via vswhere
# ---------------------------------------------------------------------------
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    Write-Error 'vswhere.exe not found. Visual Studio 2017+ or Build Tools required.'
    exit 1
}

# Find latest VS installation with C++ tools
$vsRoot = & $vswhere -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

if (-not $vsRoot) {
    Write-Error 'No Visual Studio installation with MSVC found.'
    exit 1
}

$vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) {
    Write-Error ('vcvars64.bat not found at: ' + $vcvars)
    exit 1
}

Write-Host ('Using MSVC from: ' + $vsRoot) -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Build the cmd commands chain (NO DOUBLE QUOTES AT ALL)
# ---------------------------------------------------------------------------
$doubleQuote = [char]34
$vcvarsEscaped = $doubleQuote + $vcvars + $doubleQuote

$commands = @(
    $vcvarsEscaped,
    ('cmake --preset ' + $preset),
    ('cmake --build --preset ' + $preset)
)
if (-not $noTest) {
    $commands += ('ctest --preset ' + $preset)
}

$cmdLine = $commands -join ' && '
cmd.exe /c $cmdLine
exit $LASTEXITCODE

#powershell.exe -Executionpolicy Bypass -File "build.ps1"