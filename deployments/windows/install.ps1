param(
  [string]$InstallDir = "$env:ProgramFiles\Sentinel Vault",
  [string]$HostName = "127.0.0.1",
  [int]$Port = 5173,
  [string]$VaultRootKey = "",
  [switch]$ConfigureIis,
  [string]$SiteName = "Sentinel Vault",
  [int]$SitePort = 8080
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

if ([string]::IsNullOrWhiteSpace($VaultRootKey)) {
  $VaultRootKey = New-SecretKey
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path (Join-Path $sourceApp "*") -Destination $InstallDir -Recurse -Force
Copy-Item -Path $runner -Destination $InstallDir -Force
New-Item -ItemType Directory -Path (Join-Path $InstallDir "logs") -Force | Out-Null

$envContent = @(
  "NODE_ENV=production",
  "HOST=$HostName",
  "PORT=$Port",
  "VAULT_ROOT_KEY=$VaultRootKey"
)
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

Write-Host "Sentinel Vault installed to $InstallDir"
Write-Host "Node API: http://$HostName`:$Port"
if ($ConfigureIis) {
  Write-Host "IIS site: http://localhost:$SitePort"
  Write-Host "IIS URL Rewrite and ARR must be installed for API proxying."
}
