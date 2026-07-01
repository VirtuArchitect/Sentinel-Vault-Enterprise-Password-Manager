param(
  [string]$ArtifactsDir = "artifacts\windows",
  [string]$SignToolPath = "",
  [string]$CertificatePath = "",
  [string]$CertificatePassword = "",
  [string]$CertificateThumbprint = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root $ArtifactsDir

function Find-SignTool {
  if ($SignToolPath -and (Test-Path -LiteralPath $SignToolPath)) {
    return $SignToolPath
  }

  $command = Get-Command "SignTool.exe" -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }

  $sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  if (Test-Path -LiteralPath $sdkRoot) {
    $candidate = Get-ChildItem -Path $sdkRoot -Recurse -Filter "SignTool.exe" -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match "\\x64\\" } |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
  }

  return $null
}

if (!(Test-Path -LiteralPath $artifactRoot)) {
  throw "Artifacts directory not found: $artifactRoot"
}

$artifacts = Get-ChildItem -LiteralPath $artifactRoot -File |
  Where-Object { $_.Extension -in @(".zip", ".exe", ".msi", ".msix") } |
  Sort-Object Name

if (!$artifacts) {
  throw "No Windows release artifacts found in $artifactRoot"
}

$signTool = Find-SignTool
if ($ValidateOnly) {
  Write-Host "Windows signing inputs validated."
  if ($signTool) {
    Write-Host "SignTool.exe found: $signTool"
  } else {
    Write-Host "SignTool.exe not found. Install Windows SDK on the release host before signing."
  }
  Write-Host "Artifacts:"
  $artifacts | ForEach-Object { Write-Host "  $($_.FullName)" }
  exit 0
}

if (!$signTool) {
  throw "SignTool.exe was not found. Install Windows SDK or pass -SignToolPath, then rerun this script."
}
if (!$CertificatePath -and !$CertificateThumbprint) {
  throw "Pass -CertificatePath for a PFX file or -CertificateThumbprint for a certificate in the Windows certificate store."
}

foreach ($artifact in $artifacts) {
  $args = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")
  if ($CertificatePath) {
    $args += @("/f", $CertificatePath)
    if ($CertificatePassword) {
      $args += @("/p", $CertificatePassword)
    }
  } else {
    $args += @("/sha1", $CertificateThumbprint)
  }
  $args += $artifact.FullName
  & $signTool @args
  if ($LASTEXITCODE -ne 0) {
    throw "SignTool failed for $($artifact.Name) with exit code $LASTEXITCODE"
  }
}

Write-Host "Windows release artifacts signed:"
$artifacts | ForEach-Object { Write-Host "  $($_.FullName)" }
