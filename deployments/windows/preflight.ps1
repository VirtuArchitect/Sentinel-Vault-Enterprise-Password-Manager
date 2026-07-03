param(
  [string]$PackageRoot = $PSScriptRoot,
  [string]$InstallDir = "$env:ProgramFiles\Sentinel Vault",
  [string]$HostName = "127.0.0.1",
  [int]$Port = 5173,
  [string]$VaultRootKey = "",
  [ValidateSet("json", "sqlite")]
  [string]$StorageProvider = "json",
  [switch]$ConfigureIis,
  [string]$SiteName = "Sentinel Vault",
  [int]$SitePort = 8080,
  [string]$Out = "",
  [switch]$AllowFailures
)

$ErrorActionPreference = "Stop"

function New-Check {
  param(
    [string]$Name,
    [ValidateSet("passed", "failed", "warning", "skipped")]
    [string]$Status,
    [string]$Message,
    [object]$Data = $null
  )

  $check = [ordered]@{
    name = $Name
    status = $Status
    message = $Message
  }
  if ($null -ne $Data) {
    $check.data = $Data
  }
  [pscustomobject]$check
}

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NodeVersion {
  $command = Get-Command node -ErrorAction SilentlyContinue
  if (!$command) {
    return $null
  }

  $rawVersion = (& $command.Source --version 2>$null)
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rawVersion)) {
    return @{ source = $command.Source; raw = ""; major = 0 }
  }

  $versionText = $rawVersion.Trim().TrimStart("v")
  $major = 0
  [void][int]::TryParse(($versionText -split "\.")[0], [ref]$major)
  return @{
    source = $command.Source
    raw = $rawVersion.Trim()
    major = $major
  }
}

function Test-PortAvailable {
  param(
    [int]$PortNumber
  )

  $listener = Get-NetTCPConnection -LocalPort $PortNumber -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if (!$listener) {
    return @{ available = $true; owningProcess = $null; processName = "" }
  }

  $processName = ""
  try {
    $processName = (Get-Process -Id $listener.OwningProcess -ErrorAction Stop).ProcessName
  } catch {
    $processName = "unknown"
  }
  return @{ available = $false; owningProcess = $listener.OwningProcess; processName = $processName }
}

function Test-NodeSqlite {
  $command = Get-Command node -ErrorAction SilentlyContinue
  if (!$command) {
    return $false
  }
  & $command.Source -e "try { require('node:sqlite'); process.exit(0); } catch { process.exit(1); }" 2>$null
  return $LASTEXITCODE -eq 0
}

$resolvedPackageRoot = if ([System.IO.Path]::IsPathRooted($PackageRoot)) { $PackageRoot } else { Join-Path (Get-Location) $PackageRoot }
$checks = New-Object System.Collections.Generic.List[object]

$requiredPaths = @(
  "app\server.mjs",
  "app\package.json",
  "app\pnpm-lock.yaml",
  "app\dist\index.html",
  "app\src\server\app.mjs",
  "app\node_modules\express\package.json",
  "preflight.ps1",
  "install.ps1",
  "uninstall.ps1",
  "rollback.ps1",
  "run-sentinel.ps1",
  "healthcheck.ps1",
  "README.md",
  "assets\sentinel-vault-app-icon.svg",
  "companions\windows\sentinel-tray-helper.ps1"
)

$missingPaths = @()
foreach ($relativePath in $requiredPaths) {
  if (!(Test-Path -LiteralPath (Join-Path $resolvedPackageRoot $relativePath))) {
    $missingPaths += $relativePath
  }
}
if ($missingPaths.Count -eq 0) {
  $checks.Add((New-Check -Name "package-layout" -Status "passed" -Message "Windows package layout contains required runtime, installer, asset, and companion files." -Data @{ requiredFileCount = $requiredPaths.Count }))
} else {
  $checks.Add((New-Check -Name "package-layout" -Status "failed" -Message "Windows package layout is missing required files." -Data @{ missing = $missingPaths }))
}

if (Test-Administrator) {
  $checks.Add((New-Check -Name "administrator" -Status "passed" -Message "PowerShell is running elevated for installer operations."))
} else {
  $checks.Add((New-Check -Name "administrator" -Status "failed" -Message "Run install.ps1 from an elevated PowerShell session."))
}

$nodeVersion = Get-NodeVersion
if (!$nodeVersion) {
  $checks.Add((New-Check -Name "node-runtime" -Status "failed" -Message "Node.js was not found. Install Node.js 20+ before running install.ps1."))
} elseif ($nodeVersion.major -lt 20) {
  $checks.Add((New-Check -Name "node-runtime" -Status "failed" -Message "Node.js 20+ is required." -Data $nodeVersion))
} else {
  $checks.Add((New-Check -Name "node-runtime" -Status "passed" -Message "Node.js runtime meets the minimum version for the packaged app." -Data $nodeVersion))
}

if ($StorageProvider -eq "sqlite") {
  if ($nodeVersion -and $nodeVersion.major -ge 24 -and (Test-NodeSqlite)) {
    $checks.Add((New-Check -Name "sqlite-runtime" -Status "passed" -Message "Node.js runtime supports node:sqlite for SQLite storage."))
  } else {
    $checks.Add((New-Check -Name "sqlite-runtime" -Status "failed" -Message "SQLite storage requires Node.js 24+ with node:sqlite support, or rerun with -StorageProvider json."))
  }
} else {
  $checks.Add((New-Check -Name "sqlite-runtime" -Status "skipped" -Message "SQLite runtime check skipped because StorageProvider is json."))
}

$apiPort = Test-PortAvailable -PortNumber $Port
if ($apiPort.available) {
  $checks.Add((New-Check -Name "api-port" -Status "passed" -Message "Node API port $Port is available." -Data @{ port = $Port; hostName = $HostName }))
} else {
  $checks.Add((New-Check -Name "api-port" -Status "failed" -Message "Node API port $Port is already in use." -Data $apiPort))
}

if ($ConfigureIis) {
  $iisPort = Test-PortAvailable -PortNumber $SitePort
  if ($iisPort.available) {
    $checks.Add((New-Check -Name "iis-port" -Status "passed" -Message "IIS site port $SitePort is available." -Data @{ port = $SitePort; siteName = $SiteName }))
  } else {
    $checks.Add((New-Check -Name "iis-port" -Status "failed" -Message "IIS site port $SitePort is already in use." -Data $iisPort))
  }

  try {
    Import-Module WebAdministration -ErrorAction Stop
    $checks.Add((New-Check -Name "iis-webadministration" -Status "passed" -Message "WebAdministration module is available for IIS configuration."))
  } catch {
    $checks.Add((New-Check -Name "iis-webadministration" -Status "failed" -Message "IIS WebAdministration module is not available. Install the Web Server (IIS) role before -ConfigureIis."))
  }

  try {
    $rewriteModule = Get-WebGlobalModule -Name "RewriteModule" -ErrorAction Stop
    $checks.Add((New-Check -Name "iis-url-rewrite" -Status "passed" -Message "IIS URL Rewrite module is available." -Data @{ module = $rewriteModule.Name }))
  } catch {
    $checks.Add((New-Check -Name "iis-url-rewrite" -Status "warning" -Message "IIS URL Rewrite module was not detected. Install URL Rewrite before relying on IIS API proxying."))
  }
} else {
  $checks.Add((New-Check -Name "iis-webadministration" -Status "skipped" -Message "IIS checks skipped because -ConfigureIis was not selected."))
}

if ($VaultRootKey -eq "change-this-test-secret" -or $VaultRootKey -eq "replace-with-production-secret") {
  $checks.Add((New-Check -Name "vault-root-key" -Status "warning" -Message "Replace placeholder VaultRootKey values before production deployment."))
}

$failed = @($checks | Where-Object { $_.status -eq "failed" })
$warnings = @($checks | Where-Object { $_.status -eq "warning" })
$result = [ordered]@{
  format = "sentinel-windows-target-preflight-v1"
  generatedAt = (Get-Date).ToUniversalTime().ToString("o")
  packageRoot = $resolvedPackageRoot
  installDir = $InstallDir
  hostName = $HostName
  port = $Port
  storageProvider = $StorageProvider
  configureIis = [bool]$ConfigureIis
  ready = $failed.Count -eq 0
  failedCount = $failed.Count
  warningCount = $warnings.Count
  checks = $checks
}

$json = $result | ConvertTo-Json -Depth 8
if (![string]::IsNullOrWhiteSpace($Out)) {
  $resolvedOut = if ([System.IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path (Get-Location) $Out }
  $outParent = Split-Path -Parent $resolvedOut
  if (![string]::IsNullOrWhiteSpace($outParent)) {
    New-Item -ItemType Directory -Path $outParent -Force | Out-Null
  }
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($resolvedOut, $json, $utf8NoBom)
}

$json
if (!$AllowFailures -and $failed.Count -gt 0) {
  exit 1
}
