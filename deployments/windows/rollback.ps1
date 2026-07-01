param(
  [Parameter(Mandatory = $true)]
  [string]$BackupDir,
  [string]$InstallDir = "$env:ProgramFiles\Sentinel Vault",
  [string]$TaskName = "SentinelVault"
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run rollback from an elevated PowerShell session."
  }
}

Assert-Administrator

if (!(Test-Path (Join-Path $BackupDir "server.mjs"))) {
  throw "Rollback backup does not contain a Sentinel Vault server.mjs file: $BackupDir"
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
robocopy $BackupDir $InstallDir /MIR /XD logs data /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -gt 7) {
  throw "robocopy failed restoring $BackupDir to $InstallDir with exit code $LASTEXITCODE"
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Start-ScheduledTask -TaskName $TaskName
}

Write-Host "Sentinel Vault rollback restored from $BackupDir"
