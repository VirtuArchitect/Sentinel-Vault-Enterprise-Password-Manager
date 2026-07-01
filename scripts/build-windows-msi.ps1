param(
  [string]$OutputDir = "artifacts\windows",
  [string]$PackageName = "SentinelVault-Windows",
  [string]$ProductVersion = "1.0.0",
  [string]$Manufacturer = "VirtuArchitect",
  [string]$UpgradeCode = "11111111-2222-3333-4444-555555555555",
  [string]$WixBinPath = "",
  [switch]$ValidateOnly,
  [switch]$SkipPackageBuild
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $root $OutputDir
$zipPath = Join-Path $outputRoot "$PackageName.zip"
$wixTemplate = Join-Path $root "deployments\windows\wix\SentinelVault.wxs"
$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) "$PackageName-msi-stage"
$extractRoot = Join-Path $stageRoot "payload"
$objRoot = Join-Path $stageRoot "obj"
$expandedWxs = Join-Path $objRoot "SentinelVault.expanded.wxs"
$harvestedWxs = Join-Path $objRoot "SentinelPayload.wxs"
$msiPath = Join-Path $outputRoot "$PackageName.msi"

function Find-WixTool {
  param(
    [string]$ToolName
  )

  if ($WixBinPath) {
    $candidate = Join-Path $WixBinPath $ToolName
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }

  $command = Get-Command $ToolName -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }

  $candidates = @(
    "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin\$ToolName",
    "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin\$ToolName",
    "$env:ProgramFiles\WiX Toolset v3.14\bin\$ToolName",
    "$env:ProgramFiles\WiX Toolset v3.11\bin\$ToolName"
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  return $null
}

function Expand-WixTemplate {
  param(
    [string]$TemplatePath,
    [string]$DestinationPath
  )

  $content = Get-Content -Path $TemplatePath -Raw
  Set-Content -Path $DestinationPath -Value $content -Encoding UTF8
  [xml]$wixXml = Get-Content -Path $DestinationPath -Raw
  return $wixXml
}

if (!(Test-Path -LiteralPath $wixTemplate)) {
  throw "Missing WiX template at $wixTemplate"
}

$candle = Find-WixTool -ToolName "candle.exe"
$light = Find-WixTool -ToolName "light.exe"
$heat = Find-WixTool -ToolName "heat.exe"

if (Test-Path -LiteralPath $stageRoot) {
  Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $objRoot -Force | Out-Null
$wixXml = Expand-WixTemplate -TemplatePath $wixTemplate -DestinationPath $expandedWxs

if (!$wixXml.Wix.Product.Feature.ComponentGroupRef.Id) {
  throw "WiX template must reference the SentinelPayload component group."
}

if ($ValidateOnly) {
  Write-Host "MSI authoring files validated."
  if ($candle -and $light -and $heat) {
    Write-Host "WiX Toolset found:"
    Write-Host "  candle: $candle"
    Write-Host "  light:  $light"
    Write-Host "  heat:   $heat"
  } else {
    Write-Host "WiX Toolset was not fully found. Install WiX Toolset v3 on the release host before MSI packaging."
  }
  exit 0
}

if (!$candle -or !$light -or !$heat) {
  throw "WiX Toolset v3 tools were not found. Install WiX or pass -WixBinPath, then rerun this script."
}

Set-Location $root
if (!(Test-Path -LiteralPath $zipPath)) {
  if ($SkipPackageBuild) {
    throw "Missing Windows package at $zipPath and -SkipPackageBuild was provided."
  }
  powershell -ExecutionPolicy Bypass -File (Join-Path $root "scripts\build-windows-package.ps1") -OutputDir $OutputDir -PackageName $PackageName
}

New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
tar.exe -xf $zipPath -C $extractRoot
if ($LASTEXITCODE -ne 0) {
  throw "tar.exe failed extracting $zipPath with exit code $LASTEXITCODE"
}

& $heat dir $extractRoot -cg SentinelPayload -dr INSTALLFOLDER -srd -sreg -gg -var var.SourceRoot -out $harvestedWxs
if ($LASTEXITCODE -ne 0) {
  throw "WiX heat failed with exit code $LASTEXITCODE"
}

& $candle $expandedWxs $harvestedWxs -out "$objRoot\" -dSourceRoot="$extractRoot" -dProductVersion="$ProductVersion" -dManufacturer="$Manufacturer" -dUpgradeCode="$UpgradeCode"
if ($LASTEXITCODE -ne 0) {
  throw "WiX candle failed with exit code $LASTEXITCODE"
}

if (Test-Path -LiteralPath $msiPath) {
  Remove-Item -LiteralPath $msiPath -Force
}

& $light (Join-Path $objRoot "SentinelVault.expanded.wixobj") (Join-Path $objRoot "SentinelPayload.wixobj") -out $msiPath
if ($LASTEXITCODE -ne 0) {
  throw "WiX light failed with exit code $LASTEXITCODE"
}

Write-Host "Windows MSI package created:"
Write-Host $msiPath
