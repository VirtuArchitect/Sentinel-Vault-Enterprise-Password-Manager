param(
  [string]$InstallDir = "$env:ProgramFiles\Sentinel Vault",
  [switch]$RemoveIis,
  [string]$SiteName = "Sentinel Vault",
  [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell session."
  }
}

Assert-Administrator

$taskName = "SentinelVault"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -like "*run-sentinel.ps1*" -or $_.CommandLine -like "*server.mjs*" } |
  ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
  }

if ($RemoveIis) {
  Import-Module WebAdministration -ErrorAction Stop
  if (Test-Path "IIS:\Sites\$SiteName") {
    Remove-Website -Name $SiteName
  }
  if (Test-Path "IIS:\AppPools\$SiteName") {
    Remove-WebAppPool -Name $SiteName
  }
}

if ($RemoveData -and (Test-Path $InstallDir)) {
  Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

Write-Host "Sentinel Vault scheduled task removed."
if ($RemoveData) {
  Write-Host "Install directory removed: $InstallDir"
} else {
  Write-Host "Install directory retained: $InstallDir"
}
