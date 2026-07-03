param(
  [int]$Port = 5173,
  [string]$HostName = "127.0.0.1",
  [switch]$SkipInstall,
  [switch]$ResetState
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$dataDir = Join-Path $root "data"
$stateFile = Join-Path $dataDir "sentinel-state.json"
$sqliteFiles = @(
  (Join-Path $dataDir "sentinel-vault.sqlite"),
  (Join-Path $dataDir "sentinel-vault.sqlite-shm"),
  (Join-Path $dataDir "sentinel-vault.sqlite-wal")
)

function Resolve-PnpmCommand {
  $pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
  if ($pnpm) {
    return @{
      Command = $pnpm.Source
      Prefix = @()
      Label = "pnpm"
    }
  }

  $npx = Get-Command npx -ErrorAction SilentlyContinue
  if ($npx) {
    return @{
      Command = $npx.Source
      Prefix = @("pnpm@11.8.0")
      Label = "npx pnpm@11.8.0"
    }
  }

  throw "Neither pnpm nor npx was found. Install Node.js 20+ from https://nodejs.org and reopen PowerShell."
}

function Invoke-Pnpm {
  param(
    [hashtable]$Tool,
    [string[]]$Arguments
  )

  & $Tool.Command @($Tool.Prefix + $Arguments)
  if ($LASTEXITCODE -ne 0) {
    throw "$($Tool.Label) $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
  }
}

$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) {
  $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
  if ($ResetState) {
    throw "Port $Port is already in use by process $($listener.OwningProcess) $($process.ProcessName). Stop that process before resetting demo state."
  }
  Write-Host "Port $Port is already in use by process $($listener.OwningProcess) $($process.ProcessName)."
  Write-Host "Open http://$HostName`:$Port if the Sentinel Vault console is already running, or stop that process and rerun this script."
  exit 0
}

if ($ResetState) {
  $archived = @()
  $backupDir = Join-Path $dataDir ("reset-backups\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
  foreach ($candidate in @($stateFile) + $sqliteFiles) {
    if (Test-Path $candidate) {
      New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
      $destination = Join-Path $backupDir (Split-Path -Leaf $candidate)
      Move-Item -LiteralPath $candidate -Destination $destination -Force
      $archived += $destination
    }
  }
  if ($archived.Count) {
    Write-Host "Archived old demo state:"
    $archived | ForEach-Object { Write-Host " - $_" }
  } else {
    Write-Host "No persisted demo state found. The seeded enterprise demo data will be created on start."
  }
}

$tool = Resolve-PnpmCommand
Write-Host "Using $($tool.Label)"

if (!$SkipInstall -or !(Test-Path (Join-Path $root "node_modules"))) {
  Invoke-Pnpm -Tool $tool -Arguments @("install")
}

$env:HOST = $HostName
$env:PORT = [string]$Port
Write-Host "Starting Sentinel Vault demo console at http://$HostName`:$Port"
Write-Host "Demo user: avery.stone@enterprise.example / Passw0rd!"
Invoke-Pnpm -Tool $tool -Arguments @("dev")
