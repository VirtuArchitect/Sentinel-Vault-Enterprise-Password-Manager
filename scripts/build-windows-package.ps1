param(
  [string]$OutputDir = "artifacts\windows",
  [string]$PackageName = "SentinelVault-Windows"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $root $OutputDir
$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) "$PackageName-stage"
$appRoot = Join-Path $stageRoot "app"
$zipPath = Join-Path $outputRoot "$PackageName.zip"

function Copy-Tree {
  param(
    [string]$Source,
    [string]$Destination
  )

  robocopy $Source $Destination /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed copying $Source to $Destination with exit code $LASTEXITCODE"
  }
}

Set-Location $root

pnpm install --frozen-lockfile
pnpm verify

if (Test-Path $stageRoot) {
  Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $appRoot | Out-Null

Copy-Item -Path (Join-Path $root "server.mjs") -Destination $appRoot
Copy-Item -Path (Join-Path $root "package.json") -Destination $appRoot
Copy-Item -Path (Join-Path $root "pnpm-lock.yaml") -Destination $appRoot
Copy-Tree -Source (Join-Path $root "dist") -Destination (Join-Path $appRoot "dist")

New-Item -ItemType Directory -Path (Join-Path $appRoot "src") | Out-Null
Copy-Tree -Source (Join-Path $root "src\server") -Destination (Join-Path $appRoot "src\server")

Push-Location $appRoot
try {
  pnpm install --prod --frozen-lockfile --config.node-linker=hoisted
} finally {
  Pop-Location
}

Copy-Item -Path (Join-Path $root "deployments\windows\install.ps1") -Destination $stageRoot
Copy-Item -Path (Join-Path $root "deployments\windows\uninstall.ps1") -Destination $stageRoot
Copy-Item -Path (Join-Path $root "deployments\windows\rollback.ps1") -Destination $stageRoot
Copy-Item -Path (Join-Path $root "deployments\windows\run-sentinel.ps1") -Destination $stageRoot
Copy-Item -Path (Join-Path $root "deployments\windows\healthcheck.ps1") -Destination $stageRoot
Copy-Item -Path (Join-Path $root "deployments\windows\README.md") -Destination $stageRoot
Copy-Tree -Source (Join-Path $root "deployments\windows\assets") -Destination (Join-Path $stageRoot "assets")
Copy-Tree -Source (Join-Path $root "companions\windows") -Destination (Join-Path $stageRoot "companions\windows")

if (Test-Path $zipPath) {
  Remove-Item -LiteralPath $zipPath -Force
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stageRoot, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Write-Host "Windows package created:"
Write-Host $zipPath
