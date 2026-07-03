param(
  [string]$PackagePath = "artifacts\windows\SentinelVault-Windows.zip",
  [string]$ExtractDir = "",
  [string]$Out = "",
  [int]$Port = 0,
  [switch]$SkipRuntimeSmoke,
  [switch]$KeepExtracted
)

$ErrorActionPreference = "Stop"

function Resolve-FreePort {
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $candidate = Get-Random -Minimum 5200 -Maximum 5999
    $listener = Get-NetTCPConnection -LocalPort $candidate -State Listen -ErrorAction SilentlyContinue
    if (!$listener) {
      return $candidate
    }
  }
  throw "Unable to find a free local TCP port for package smoke validation."
}

function Assert-Exists {
  param(
    [string]$Path,
    [string]$Label
  )

  if (!(Test-Path -LiteralPath $Path)) {
    throw "$Label was not found: $Path"
  }
}

$root = Split-Path -Parent $PSScriptRoot
$resolvedPackage = if ([System.IO.Path]::IsPathRooted($PackagePath)) { $PackagePath } else { Join-Path $root $PackagePath }
Assert-Exists -Path $resolvedPackage -Label "Windows package"

if ([string]::IsNullOrWhiteSpace($ExtractDir)) {
  $ExtractDir = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-windows-package-validation-{0}" -f ([guid]::NewGuid().ToString("N")))
}
$resolvedExtractDir = if ([System.IO.Path]::IsPathRooted($ExtractDir)) { $ExtractDir } else { Join-Path $root $ExtractDir }

if (Test-Path -LiteralPath $resolvedExtractDir) {
  throw "Extraction directory already exists: $resolvedExtractDir"
}
New-Item -ItemType Directory -Path $resolvedExtractDir -Force | Out-Null

$smokePort = if ($Port -gt 0) { $Port } else { Resolve-FreePort }
$nodeProcess = $null
$healthUrl = "http://127.0.0.1:$smokePort/healthz"

try {
  Expand-Archive -LiteralPath $resolvedPackage -DestinationPath $resolvedExtractDir -Force

  $requiredPaths = @(
    "install.ps1",
    "preflight.ps1",
    "uninstall.ps1",
    "rollback.ps1",
    "run-sentinel.ps1",
    "healthcheck.ps1",
    "README.md",
    "assets\sentinel-vault-app-icon.svg",
    "companions\windows\sentinel-tray-helper.ps1",
    "app\server.mjs",
    "app\package.json",
    "app\pnpm-lock.yaml",
    "app\dist\index.html",
    "app\src\server\app.mjs",
    "app\node_modules\express\package.json"
  )

  foreach ($relativePath in $requiredPaths) {
    Assert-Exists -Path (Join-Path $resolvedExtractDir $relativePath) -Label "Required package file"
  }

  if (!$SkipRuntimeSmoke) {
    if (!(Get-Command node -ErrorAction SilentlyContinue)) {
      throw "Node.js is required for runtime smoke validation."
    }

    $appRoot = Join-Path $resolvedExtractDir "app"
    $stdoutPath = Join-Path $resolvedExtractDir "sentinel-package-smoke.out.log"
    $stderrPath = Join-Path $resolvedExtractDir "sentinel-package-smoke.err.log"
    $oldNodeEnv = $env:NODE_ENV
    $oldHost = $env:HOST
    $oldPort = $env:PORT
    $oldVaultRootKey = $env:VAULT_ROOT_KEY
    $oldStorageProvider = $env:STORAGE_PROVIDER

    try {
      $env:NODE_ENV = "production"
      $env:HOST = "127.0.0.1"
      $env:PORT = [string]$smokePort
      $env:VAULT_ROOT_KEY = "windows-package-validation-root-key"
      $env:STORAGE_PROVIDER = "json"

      $nodeProcess = Start-Process `
        -FilePath "node" `
        -ArgumentList "server.mjs" `
        -WorkingDirectory $appRoot `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

      $healthy = $false
      for ($index = 0; $index -lt 30; $index++) {
        Start-Sleep -Seconds 1
        try {
          $response = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
          if ($response.ok -eq $true) {
            $healthy = $true
            break
          }
        } catch {
        }
      }

      if (!$healthy) {
        $errorTail = if (Test-Path -LiteralPath $stderrPath) { (Get-Content -LiteralPath $stderrPath -Tail 40) -join "`n" } else { "" }
        throw "Extracted Windows package did not pass health check at $healthUrl. $errorTail"
      }
    } finally {
      if ($nodeProcess -and !$nodeProcess.HasExited) {
        Stop-Process -Id $nodeProcess.Id -Force
      }
      $env:NODE_ENV = $oldNodeEnv
      $env:HOST = $oldHost
      $env:PORT = $oldPort
      $env:VAULT_ROOT_KEY = $oldVaultRootKey
      $env:STORAGE_PROVIDER = $oldStorageProvider
    }
  }

  $result = @{
    format = "sentinel-windows-package-validation-v1"
    packagePath = (Resolve-Path -LiteralPath $resolvedPackage).Path
    extractedTo = $resolvedExtractDir
    runtimeSmoke = if ($SkipRuntimeSmoke) { "skipped" } else { "passed" }
    healthUrl = if ($SkipRuntimeSmoke) { $null } else { $healthUrl }
    requiredFileCount = $requiredPaths.Count
    validated = $true
  }

  $json = $result | ConvertTo-Json -Depth 5
  if (![string]::IsNullOrWhiteSpace($Out)) {
    $resolvedOut = if ([System.IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path $root $Out }
    $outParent = Split-Path -Parent $resolvedOut
    if (![string]::IsNullOrWhiteSpace($outParent)) {
      New-Item -ItemType Directory -Path $outParent -Force | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($resolvedOut, $json, $utf8NoBom)
  }
  $json
} finally {
  if (!$KeepExtracted -and (Test-Path -LiteralPath $resolvedExtractDir)) {
    Remove-Item -LiteralPath $resolvedExtractDir -Recurse -Force
  }
}
