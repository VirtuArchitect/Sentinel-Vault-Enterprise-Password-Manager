param(
  [string]$OutputDir = "artifacts\windows",
  [string]$PackageName = "SentinelVault-Windows",
  [string]$MsixIdentityName = "VirtuArchitect.SentinelVault",
  [string]$Publisher = "CN=VirtuArchitect",
  [string]$PublisherDisplayName = "VirtuArchitect",
  [string]$Version = "1.0.0.0",
  [string]$MakeAppxPath = "",
  [string]$SignToolPath = "",
  [string]$CertificatePath = "",
  [string]$CertificatePassword = "",
  [switch]$ValidateOnly,
  [switch]$SkipPackageBuild,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$ForwardedArgs
)

$ErrorActionPreference = "Stop"

if ($ForwardedArgs) {
  $unexpectedArgs = $ForwardedArgs | Where-Object { $_ -ne "--" }
  if ($unexpectedArgs) {
    throw "Unsupported arguments: $($unexpectedArgs -join ' ')"
  }
}

$root = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $root $OutputDir
$zipPath = Join-Path $outputRoot "$PackageName.zip"
$msixTemplate = Join-Path $root "deployments\windows\msix\SentinelVault.AppxManifest.xml"
$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) "$PackageName-msix-stage"
$packageRoot = Join-Path $stageRoot "package"
$installRoot = Join-Path $packageRoot "VFS\ProgramFilesX64\Sentinel Vault"
$manifestPath = Join-Path $packageRoot "AppxManifest.xml"
$msixPath = Join-Path $outputRoot "$PackageName.msix"

function Remove-DirectoryWithRetry {
  param(
    [string]$Path
  )

  if (!(Test-Path -LiteralPath $Path)) { return }
  for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
      Remove-Item -LiteralPath $Path -Recurse -Force
      return
    } catch {
      if ($attempt -eq 5) { throw }
      Start-Sleep -Milliseconds (250 * $attempt)
    }
  }
}

function Find-WindowsSdkTool {
  param(
    [string]$ToolName,
    [string]$ExplicitPath
  )

  if ($ExplicitPath -and (Test-Path -LiteralPath $ExplicitPath)) {
    return $ExplicitPath
  }

  $command = Get-Command $ToolName -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }

  $sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  if (Test-Path -LiteralPath $sdkRoot) {
    $candidate = Get-ChildItem -Path $sdkRoot -Recurse -Filter $ToolName -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match "\\x64\\" } |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
  }

  return $null
}

function Expand-MsixManifestTemplate {
  param(
    [string]$TemplatePath,
    [string]$DestinationPath
  )

  $content = Get-Content -Path $TemplatePath -Raw
  $content = $content.Replace("{{PACKAGE_NAME}}", $MsixIdentityName)
  $content = $content.Replace("{{PUBLISHER}}", $Publisher)
  $content = $content.Replace("{{PUBLISHER_DISPLAY_NAME}}", $PublisherDisplayName)
  $content = $content.Replace("{{VERSION}}", $Version)
  Set-Content -Path $DestinationPath -Value $content -Encoding UTF8
  [xml]$manifestXml = Get-Content -Path $DestinationPath -Raw
  return $manifestXml
}

function New-MsixLogo {
  param(
    [string]$Path,
    [int]$Size
  )

  Add-Type -AssemblyName System.Drawing
  $bitmap = New-Object System.Drawing.Bitmap $Size, $Size
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $background = [System.Drawing.Color]::FromArgb(48, 50, 70)
  $accent = [System.Drawing.Color]::FromArgb(141, 151, 255)
  $panel = [System.Drawing.Color]::FromArgb(67, 69, 109)
  $graphics.Clear($background)

  $padding = [Math]::Max(4, [int]($Size * 0.18))
  $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
  $shield.AddPolygon(@(
    (New-Object System.Drawing.PointF ([float]($Size / 2)), ([float]$padding)),
    (New-Object System.Drawing.PointF ([float]($Size - $padding)), ([float]($Size * 0.34))),
    (New-Object System.Drawing.PointF ([float]($Size * 0.78)), ([float]($Size - $padding))),
    (New-Object System.Drawing.PointF ([float]($Size / 2)), ([float]($Size * 0.88))),
    (New-Object System.Drawing.PointF ([float]($Size * 0.22)), ([float]($Size - $padding))),
    (New-Object System.Drawing.PointF ([float]$padding), ([float]($Size * 0.34)))
  ))
  $graphics.FillPath((New-Object System.Drawing.SolidBrush $panel), $shield)
  $graphics.DrawPath((New-Object System.Drawing.Pen $accent, ([Math]::Max(1, $Size * 0.035))), $shield)

  $lockWidth = [float]($Size * 0.28)
  $lockHeight = [float]($Size * 0.24)
  $lockX = [float](($Size - $lockWidth) / 2)
  $lockY = [float]($Size * 0.47)
  $graphics.DrawArc((New-Object System.Drawing.Pen $accent, ([Math]::Max(1, $Size * 0.03))), $lockX, ([float]($lockY - ($lockHeight * 0.45))), $lockWidth, $lockHeight, 200, 140)
  $graphics.DrawRectangle((New-Object System.Drawing.Pen $accent, ([Math]::Max(1, $Size * 0.03))), $lockX, $lockY, $lockWidth, $lockHeight)

  $graphics.Dispose()
  $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
  $bitmap.Dispose()
}

function New-MsixLauncher {
  param(
    [string]$Path
  )

  $launcherSource = @"
using System;
using System.Diagnostics;
using System.IO;

public static class SentinelVaultLauncher
{
    public static int Main()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string scriptPath = Path.Combine(baseDir, "run-sentinel.ps1");
        if (!File.Exists(scriptPath))
        {
            return 2;
        }

        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = "powershell.exe";
        startInfo.Arguments = "-ExecutionPolicy Bypass -File \"" + scriptPath + "\"";
        startInfo.WorkingDirectory = baseDir;
        startInfo.UseShellExecute = false;
        Process process = Process.Start(startInfo);
        return process == null ? 1 : 0;
    }
}
"@

  Add-Type -TypeDefinition $launcherSource -OutputAssembly $Path -OutputType WindowsApplication -ReferencedAssemblies "System.dll"
}

if (!(Test-Path -LiteralPath $msixTemplate)) {
  throw "Missing MSIX manifest template at $msixTemplate"
}

$makeAppx = Find-WindowsSdkTool -ToolName "MakeAppx.exe" -ExplicitPath $MakeAppxPath
$signTool = Find-WindowsSdkTool -ToolName "SignTool.exe" -ExplicitPath $SignToolPath

Remove-DirectoryWithRetry -Path $stageRoot
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $packageRoot "Assets") -Force | Out-Null

$manifestXml = Expand-MsixManifestTemplate -TemplatePath $msixTemplate -DestinationPath $manifestPath

if (!$manifestXml.Package.Identity.Name -or !$manifestXml.Package.Identity.Publisher -or !$manifestXml.Package.Identity.Version) {
  throw "MSIX manifest identity fields were not expanded correctly."
}

New-MsixLogo -Path (Join-Path $packageRoot "Assets\StoreLogo.png") -Size 50
New-MsixLogo -Path (Join-Path $packageRoot "Assets\Square44x44Logo.png") -Size 44
New-MsixLogo -Path (Join-Path $packageRoot "Assets\Square150x150Logo.png") -Size 150
Copy-Item -Path (Join-Path $root "deployments\windows\assets\sentinel-vault-app-icon.svg") -Destination (Join-Path $packageRoot "Assets\sentinel-vault-app-icon.svg")

if ($ValidateOnly) {
  Write-Host "MSIX authoring files validated."
  if ($makeAppx) {
    Write-Host "MakeAppx.exe found: $makeAppx"
  } else {
    Write-Host "MakeAppx.exe not found. Install Windows SDK on the release host before packaging."
  }
  if ($signTool) {
    Write-Host "SignTool.exe found: $signTool"
  } else {
    Write-Host "SignTool.exe not found. Install Windows SDK on the release host before signing."
  }
  exit 0
}

if (!$makeAppx) {
  throw "MakeAppx.exe was not found. Install Windows SDK or pass -MakeAppxPath, then rerun this script."
}

Set-Location $root
if (!(Test-Path -LiteralPath $zipPath)) {
  if ($SkipPackageBuild) {
    throw "Missing Windows package at $zipPath and -SkipPackageBuild was provided."
  }
  powershell -ExecutionPolicy Bypass -File (Join-Path $root "scripts\build-windows-package.ps1") -OutputDir $OutputDir -PackageName $PackageName
}

New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
tar.exe -xf $zipPath -C $installRoot
if ($LASTEXITCODE -ne 0) {
  throw "tar.exe failed extracting $zipPath with exit code $LASTEXITCODE"
}

New-MsixLauncher -Path (Join-Path $installRoot "SentinelVaultLauncher.exe")

if (Test-Path -LiteralPath $msixPath) {
  Remove-Item -LiteralPath $msixPath -Force
}

& $makeAppx pack /d $packageRoot /p $msixPath /o
if ($LASTEXITCODE -ne 0) {
  throw "MakeAppx failed with exit code $LASTEXITCODE"
}

if ($CertificatePath) {
  if (!$signTool) {
    throw "SignTool.exe was not found. Install Windows SDK or pass -SignToolPath, then rerun this script."
  }
  $signArgs = @("sign", "/fd", "SHA256", "/f", $CertificatePath)
  if ($CertificatePassword) {
    $signArgs += @("/p", $CertificatePassword)
  }
  $signArgs += $msixPath
  & $signTool @signArgs
  if ($LASTEXITCODE -ne 0) {
    throw "SignTool failed with exit code $LASTEXITCODE"
  }
} else {
  Write-Warning "MSIX package was created unsigned. Sign it on an approved certificate-backed release host before distribution."
}

Write-Host "Windows MSIX package created:"
Write-Host $msixPath
