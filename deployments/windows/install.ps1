param(
  [string]$InstallDir = "$env:ProgramFiles\Sentinel Vault",
  [string]$HostName = "127.0.0.1",
  [int]$Port = 5173,
  [string]$VaultRootKey = "",
  [ValidateSet("json", "sqlite")]
  [string]$StorageProvider = "json",
  [string]$SqlitePath = "",
  [switch]$ConfigureIis,
  [string]$SiteName = "Sentinel Vault",
  [int]$SitePort = 8080,
  [switch]$SkipStartMenuShortcut
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell session."
  }
}

function New-SecretKey {
  $bytes = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
  [Convert]::ToBase64String($bytes)
}

function Write-IisWebConfig {
  param(
    [string]$DistDir,
    [int]$ApiPort
  )

  $webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="Sentinel Vault API" stopProcessing="true">
          <match url="^api/(.*)" />
          <action type="Rewrite" url="http://127.0.0.1:$ApiPort/api/{R:1}" />
        </rule>
        <rule name="Sentinel Vault SPA" stopProcessing="true">
          <match url=".*" />
          <conditions logicalGrouping="MatchAll">
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
            <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
          </conditions>
          <action type="Rewrite" url="/index.html" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@

  Set-Content -Path (Join-Path $DistDir "web.config") -Value $webConfig -Encoding UTF8
}

function Backup-ExistingInstall {
  param(
    [string]$CurrentInstallDir
  )

  if (!(Test-Path (Join-Path $CurrentInstallDir "server.mjs"))) {
    return $null
  }

  $rollbackRoot = Join-Path (Split-Path -Parent $CurrentInstallDir) "Sentinel Vault Rollbacks"
  $backupName = "backup-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
  $backupDir = Join-Path $rollbackRoot $backupName
  New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

  robocopy $CurrentInstallDir $backupDir /MIR /XD logs data "Sentinel Vault Rollbacks" /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed creating rollback backup at $backupDir with exit code $LASTEXITCODE"
  }

  Set-Content -Path (Join-Path $backupDir "rollback-manifest.txt") -Value @(
    "CreatedAt=$(Get-Date -Format o)",
    "InstallDir=$CurrentInstallDir",
    "SourcePackage=$PSScriptRoot"
  ) -Encoding UTF8

  return $backupDir
}

function New-StartMenuShortcut {
  param(
    [string]$ShortcutUrl,
    [string]$IconPath
  )

  $programsDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
  $shortcutPath = Join-Path $programsDir "Sentinel Vault.url"
  $shortcut = @(
    "[InternetShortcut]",
    "URL=$ShortcutUrl"
  )
  if (Test-Path $IconPath) {
    $shortcut += "IconFile=$IconPath"
    $shortcut += "IconIndex=0"
  }
  Set-Content -Path $shortcutPath -Value $shortcut -Encoding ASCII
  return $shortcutPath
}

Assert-Administrator

$packageRoot = $PSScriptRoot
$sourceApp = Join-Path $packageRoot "app"
$runner = Join-Path $packageRoot "run-sentinel.ps1"
$taskName = "SentinelVault"

if (!(Test-Path $sourceApp)) {
  throw "Package app folder was not found at $sourceApp. Run this script from an extracted Sentinel Vault Windows package."
}
if (!(Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js is required on the target server. Install Node.js 20+ before running this installer."
}
if ($StorageProvider -eq "sqlite") {
  if ([string]::IsNullOrWhiteSpace($SqlitePath)) {
    $SqlitePath = Join-Path $InstallDir "data\sentinel-vault.sqlite"
  }
  $sqliteCheck = & node -e "try { require('node:sqlite'); process.exit(0); } catch { process.exit(1); }"
  if ($LASTEXITCODE -ne 0) {
    throw "SQLite storage requires a Node.js runtime with node:sqlite support. Install Node.js 24+ or rerun with -StorageProvider json."
  }
}

if ([string]::IsNullOrWhiteSpace($VaultRootKey)) {
  $VaultRootKey = New-SecretKey
}

$backupDir = Backup-ExistingInstall -CurrentInstallDir $InstallDir

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path (Join-Path $sourceApp "*") -Destination $InstallDir -Recurse -Force
Copy-Item -Path $runner -Destination $InstallDir -Force
if (Test-Path (Join-Path $packageRoot "assets")) {
  Copy-Item -Path (Join-Path $packageRoot "assets") -Destination $InstallDir -Recurse -Force
}
New-Item -ItemType Directory -Path (Join-Path $InstallDir "logs") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallDir "data") -Force | Out-Null
if ($StorageProvider -eq "sqlite") {
  New-Item -ItemType Directory -Path (Split-Path -Parent $SqlitePath) -Force | Out-Null
}

$envContent = @(
  "NODE_ENV=production",
  "HOST=$HostName",
  "PORT=$Port",
  "VAULT_ROOT_KEY=$VaultRootKey",
  "STORAGE_PROVIDER=$StorageProvider"
)
if ($StorageProvider -eq "sqlite") {
  $envContent += "SQLITE_PATH=$SqlitePath"
}
Set-Content -Path (Join-Path $InstallDir "sentinel.env") -Value $envContent -Encoding UTF8

icacls (Join-Path $InstallDir "sentinel.env") /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" | Out-Null

$taskAction = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\run-sentinel.ps1`" -InstallDir `"$InstallDir`""
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)

Register-ScheduledTask `
  -TaskName $taskName `
  -Action $taskAction `
  -Trigger $taskTrigger `
  -Principal $taskPrincipal `
  -Settings $taskSettings `
  -Force | Out-Null

Start-ScheduledTask -TaskName $taskName

if ($ConfigureIis) {
  Import-Module WebAdministration -ErrorAction Stop
  $distDir = Join-Path $InstallDir "dist"
  Write-IisWebConfig -DistDir $distDir -ApiPort $Port

  if (!(Test-Path "IIS:\AppPools\$SiteName")) {
    New-WebAppPool -Name $SiteName | Out-Null
  }
  Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ""

  if (Test-Path "IIS:\Sites\$SiteName") {
    Remove-Website -Name $SiteName
  }

  New-Website `
    -Name $SiteName `
    -Port $SitePort `
    -PhysicalPath $distDir `
    -ApplicationPool $SiteName | Out-Null
}

$consoleUrl = if ($ConfigureIis) { "http://localhost:$SitePort" } else { "http://$HostName`:$Port" }
if (!$SkipStartMenuShortcut) {
  $shortcutPath = New-StartMenuShortcut -ShortcutUrl $consoleUrl -IconPath (Join-Path $InstallDir "assets\sentinel-vault-app-icon.svg")
  Write-Host "Start Menu shortcut: $shortcutPath"
}

Write-Host "Sentinel Vault installed to $InstallDir"
Write-Host "Node API: http://$HostName`:$Port"
if ($backupDir) {
  Write-Host "Rollback backup: $backupDir"
  Write-Host "Rollback command: .\rollback.ps1 -BackupDir `"$backupDir`" -InstallDir `"$InstallDir`""
}
if ($ConfigureIis) {
  Write-Host "IIS site: http://localhost:$SitePort"
  Write-Host "IIS URL Rewrite and ARR must be installed for API proxying."
}
