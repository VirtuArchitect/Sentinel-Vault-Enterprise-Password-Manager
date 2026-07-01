param(
  [string]$OutputDir = "artifacts\windows",
  [string]$PackageName = "SentinelVault-Windows",
  [string]$InnoSetupCompiler = "",
  [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $root $OutputDir
$zipPath = Join-Path $outputRoot "$PackageName.zip"
$extractRoot = Join-Path ([System.IO.Path]::GetTempPath()) "$PackageName-installer-stage"
$innoScript = Join-Path $root "deployments\windows\inno\SentinelVault.iss"

function Find-InnoSetupCompiler {
  if ($InnoSetupCompiler -and (Test-Path -LiteralPath $InnoSetupCompiler)) {
    return $InnoSetupCompiler
  }

  $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }

  $candidates = @(
    "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  return $null
}

if (!(Test-Path -LiteralPath $innoScript)) {
  throw "Missing Inno Setup script at $innoScript"
}

if ($ValidateOnly) {
  Write-Host "Windows installer authoring files validated."
  exit 0
}

Set-Location $root
if (!(Test-Path -LiteralPath $zipPath)) {
  powershell -ExecutionPolicy Bypass -File (Join-Path $root "scripts\build-windows-package.ps1") -OutputDir $OutputDir -PackageName $PackageName
}

if (Test-Path -LiteralPath $extractRoot) {
  Remove-Item -LiteralPath $extractRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
tar.exe -xf $zipPath -C $extractRoot
if ($LASTEXITCODE -ne 0) {
  throw "tar.exe failed extracting $zipPath with exit code $LASTEXITCODE"
}

$compiler = Find-InnoSetupCompiler
if (!$compiler) {
  throw "Inno Setup Compiler (ISCC.exe) was not found. Install Inno Setup 6 or pass -InnoSetupCompiler, then rerun this script."
}

& $compiler $innoScript /DSourceRoot="$extractRoot" /O"$outputRoot"
if ($LASTEXITCODE -ne 0) {
  throw "Inno Setup failed with exit code $LASTEXITCODE"
}

Write-Host "Windows installer created:"
Write-Host (Join-Path $outputRoot "SentinelVault-Windows-Setup.exe")
