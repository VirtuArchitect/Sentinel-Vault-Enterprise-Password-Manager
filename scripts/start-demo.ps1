param(
  [int]$Port = 5173,
  [string]$HostName = "127.0.0.1",
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

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
      Prefix = @("pnpm@11.7.0")
      Label = "npx pnpm@11.7.0"
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
  Write-Host "Port $Port is already in use by process $($listener.OwningProcess) $($process.ProcessName)."
  Write-Host "Open http://$HostName`:$Port if the Sentinel Vault console is already running, or stop that process and rerun this script."
  exit 0
}

$tool = Resolve-PnpmCommand
Write-Host "Using $($tool.Label)"

if (!$SkipInstall -or !(Test-Path (Join-Path $root "node_modules"))) {
  Invoke-Pnpm -Tool $tool -Arguments @("install")
}

$env:HOST = $HostName
$env:PORT = [string]$Port
Write-Host "Starting Sentinel Vault demo console at http://$HostName`:$Port"
Write-Host "Demo user: ada@defence.local / Passw0rd!"
Invoke-Pnpm -Tool $tool -Arguments @("dev")
