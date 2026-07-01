param(
  [string]$ConsoleUrl = "http://127.0.0.1:5173",
  [int]$ClipboardTtlSeconds = 30,
  [string]$Value = "",
  [switch]$AutoType,
  [string]$WindowTitle = "",
  [string]$Username = "",
  [string]$Password = "",
  [switch]$IUnderstandAutotypeRisk,
  [switch]$Tray,
  [string]$OfflineCachePath = "",
  [switch]$ProtectOfflineCache,
  [switch]$ShowOfflineCache,
  [switch]$BrowseOfflineCache,
  [switch]$RemoveExpiredOfflineCache,
  [switch]$InstallOfflineCacheCleanupTask,
  [switch]$RemoveOfflineCacheCleanupTask,
  [switch]$Watch,
  [switch]$ClearNow,
  [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$stateDir = Join-Path $env:LOCALAPPDATA "SentinelVault"
$markerPath = Join-Path $stateDir "clipboard-marker.json"
$protectedOfflineCachePath = Join-Path $stateDir "offline-cache.dpapi"
$offlineCleanupTaskName = "SentinelVaultOfflineCacheCleanup"

function Get-SentinelHash {
  param([Parameter(Mandatory = $true)][string]$Text)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha256.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace "-", "").ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function ConvertTo-Base64UrlBytes {
  param([Parameter(Mandatory = $true)][string]$Value)
  $base64 = $Value.Replace("-", "+").Replace("_", "/")
  switch ($base64.Length % 4) {
    2 { $base64 += "==" }
    3 { $base64 += "=" }
  }
  return [Convert]::FromBase64String($base64)
}

function Protect-SentinelBytes {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  Add-Type -AssemblyName System.Security
  return [System.Security.Cryptography.ProtectedData]::Protect($Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Unprotect-SentinelBytes {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)
  Add-Type -AssemblyName System.Security
  return [System.Security.Cryptography.ProtectedData]::Unprotect($Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Save-SentinelMarker {
  param(
    [Parameter(Mandatory = $true)][string]$Text,
    [Parameter(Mandatory = $true)][int]$TtlSeconds
  )
  New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
  $now = [DateTimeOffset]::UtcNow
  $marker = [ordered]@{
    hash = Get-SentinelHash -Text $Text
    writtenAt = $now.ToString("o")
    expiresAt = $now.AddSeconds([Math]::Max(5, $TtlSeconds)).ToString("o")
    consoleUrl = $ConsoleUrl
  }
  $marker | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding UTF8
  return $marker
}

function Read-SentinelMarker {
  if (!(Test-Path -LiteralPath $markerPath)) { return $null }
  try {
    return Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
  } catch {
    Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    return $null
  }
}

function Clear-SentinelClipboard {
  $marker = Read-SentinelMarker
  if ($null -eq $marker) { return $false }

  $current = Get-Clipboard -Raw -ErrorAction SilentlyContinue
  if ([string]::IsNullOrEmpty($current)) {
    Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    return $false
  }

  $currentHash = Get-SentinelHash -Text $current
  if ($currentHash -ne $marker.hash) { return $false }

  Set-Clipboard -Value ""
  Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
  Write-Host "Cleared Sentinel-owned clipboard value."
  return $true
}

function Watch-SentinelClipboard {
  Write-Host "Watching Sentinel-owned clipboard marker. TTL: $ClipboardTtlSeconds seconds"
  while ($true) {
    $marker = Read-SentinelMarker
    if ($null -ne $marker) {
      $expiresAt = [DateTimeOffset]::Parse($marker.expiresAt)
      if ([DateTimeOffset]::UtcNow -ge $expiresAt) {
        Clear-SentinelClipboard | Out-Null
      }
    }
    Start-Sleep -Seconds 1
  }
}

function Set-SentinelClipboard {
  param([Parameter(Mandatory = $true)][string]$SecretValue)
  Set-Clipboard -Value $SecretValue
  $marker = Save-SentinelMarker -Text $SecretValue -TtlSeconds $ClipboardTtlSeconds
  Write-Host "Copied Sentinel-owned value. Expires at $($marker.expiresAt)."
}

function ConvertTo-SendKeysLiteral {
  param([Parameter(Mandatory = $true)][string]$Text)
  $builder = [System.Text.StringBuilder]::new()
  foreach ($char in $Text.ToCharArray()) {
    switch ($char) {
      "{" { [void]$builder.Append("{{}") }
      "}" { [void]$builder.Append("{}}") }
      "+" { [void]$builder.Append("{+}") }
      "^" { [void]$builder.Append("{^}") }
      "%" { [void]$builder.Append("{%}") }
      "~" { [void]$builder.Append("{~}") }
      "(" { [void]$builder.Append("{(}") }
      ")" { [void]$builder.Append("{)}") }
      "[" { [void]$builder.Append("{[}") }
      "]" { [void]$builder.Append("{]}") }
      default { [void]$builder.Append($char) }
    }
  }
  return $builder.ToString()
}

function Invoke-SentinelAutoType {
  param(
    [Parameter(Mandatory = $true)][string]$TargetWindowTitle,
    [Parameter(Mandatory = $true)][string]$UserNameValue,
    [Parameter(Mandatory = $true)][string]$PasswordValue
  )

  if (!$IUnderstandAutotypeRisk) {
    throw "Autotype requires -IUnderstandAutotypeRisk because it sends keystrokes to the active desktop."
  }
  if ($TargetWindowTitle.Trim().Length -lt 3) {
    throw "Autotype requires a target -WindowTitle of at least 3 characters."
  }

  Add-Type -AssemblyName Microsoft.VisualBasic
  Add-Type -AssemblyName System.Windows.Forms
  $activated = [Microsoft.VisualBasic.Interaction]::AppActivate($TargetWindowTitle)
  if (!$activated) {
    throw "Could not activate a window matching '$TargetWindowTitle'."
  }

  Start-Sleep -Milliseconds 250
  [System.Windows.Forms.SendKeys]::SendWait((ConvertTo-SendKeysLiteral -Text $UserNameValue))
  [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
  [System.Windows.Forms.SendKeys]::SendWait((ConvertTo-SendKeysLiteral -Text $PasswordValue))
  Write-Host "Autotype completed for target window '$TargetWindowTitle'."
}

function Start-SentinelTray {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $contextMenu = [System.Windows.Forms.ContextMenuStrip]::new()
  $openConsole = [System.Windows.Forms.ToolStripMenuItem]::new("Open Sentinel Console")
  $clearClipboard = [System.Windows.Forms.ToolStripMenuItem]::new("Clear Sentinel Clipboard")
  $exitItem = [System.Windows.Forms.ToolStripMenuItem]::new("Exit")
  [void]$contextMenu.Items.Add($openConsole)
  [void]$contextMenu.Items.Add($clearClipboard)
  [void]$contextMenu.Items.Add($exitItem)

  $notifyIcon = [System.Windows.Forms.NotifyIcon]::new()
  $notifyIcon.Text = "Sentinel Vault"
  $notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
  $notifyIcon.ContextMenuStrip = $contextMenu
  $notifyIcon.Visible = $true

  $openConsole.Add_Click({
    Start-Process $ConsoleUrl
  })
  $clearClipboard.Add_Click({
    Clear-SentinelClipboard | Out-Null
    $notifyIcon.ShowBalloonTip(2000, "Sentinel Vault", "Clear command completed for Sentinel-owned clipboard values.", [System.Windows.Forms.ToolTipIcon]::Info)
  })
  $exitItem.Add_Click({
    $notifyIcon.Visible = $false
    [System.Windows.Forms.Application]::Exit()
  })
  $notifyIcon.Add_DoubleClick({
    Start-Process $ConsoleUrl
  })

  Write-Host "Sentinel Vault tray helper running. Use the tray icon context menu to open the console or clear Sentinel-owned clipboard values."
  [System.Windows.Forms.Application]::Run()
  $notifyIcon.Dispose()
}

function Protect-SentinelOfflineCache {
  param([Parameter(Mandatory = $true)][string]$InputPath)
  if (!(Test-Path -LiteralPath $InputPath)) {
    throw "Offline cache file not found: $InputPath"
  }
  New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
  $raw = Get-Content -LiteralPath $InputPath -Raw
  $parsed = $raw | ConvertFrom-Json
  if (!$parsed.cache.manifest.readOnly -or $parsed.cache.manifest.plaintextIncluded -ne $false) {
    throw "Offline cache artifact must be read-only and must not include plaintext."
  }
  $protected = Protect-SentinelBytes -Bytes ([System.Text.Encoding]::UTF8.GetBytes($raw))
  [System.IO.File]::WriteAllBytes($protectedOfflineCachePath, $protected)
  Write-Host "Protected offline cache for current Windows user:"
  Write-Host $protectedOfflineCachePath
}

function Read-SentinelOfflineCache {
  if (!(Test-Path -LiteralPath $protectedOfflineCachePath)) {
    throw "No DPAPI-protected offline cache found at $protectedOfflineCachePath"
  }
  $protected = [System.IO.File]::ReadAllBytes($protectedOfflineCachePath)
  $raw = [System.Text.Encoding]::UTF8.GetString((Unprotect-SentinelBytes -Bytes $protected))
  return $raw | ConvertFrom-Json
}

function Show-SentinelOfflineCache {
  $cache = Read-SentinelOfflineCache
  $manifest = $cache.cache.manifest
  $expired = [DateTimeOffset]::Parse($manifest.expiresAt) -le [DateTimeOffset]::UtcNow
  [ordered]@{
    format = $manifest.format
    readOnly = $manifest.readOnly
    exportedFor = $manifest.exportedFor
    exportedAt = $manifest.exportedAt
    expiresAt = $manifest.expiresAt
    expired = $expired
    keyVersion = $manifest.keyVersion
    vaults = $manifest.vaults
    secrets = $manifest.secrets
    plaintextIncluded = $manifest.plaintextIncluded
    protectedPath = $protectedOfflineCachePath
  } | ConvertTo-Json
}

function Open-SentinelOfflineCacheBrowser {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $cache = Read-SentinelOfflineCache
  $manifest = $cache.cache.manifest
  $expired = [DateTimeOffset]::Parse($manifest.expiresAt) -le [DateTimeOffset]::UtcNow
  $vaults = @{}
  foreach ($vault in @($manifest.index.vaults)) {
    $vaults[$vault.id] = $vault
  }

  $form = [System.Windows.Forms.Form]::new()
  $form.Text = "Sentinel Vault Offline Cache"
  $form.Width = 900
  $form.Height = 540
  $form.StartPosition = "CenterScreen"

  $summary = [System.Windows.Forms.Label]::new()
  $summary.Dock = "Top"
  $summary.Height = 48
  $summary.Padding = [System.Windows.Forms.Padding]::new(10)
  $summary.Text = "Read-only cache / Exported $($manifest.exportedAt) / Expires $($manifest.expiresAt) / Expired: $expired / Secrets: $($manifest.secrets)"
  $form.Controls.Add($summary)

  $list = [System.Windows.Forms.ListView]::new()
  $list.Dock = "Fill"
  $list.View = "Details"
  $list.FullRowSelect = $true
  $list.GridLines = $true
  [void]$list.Columns.Add("Name", 220)
  [void]$list.Columns.Add("User name", 160)
  [void]$list.Columns.Add("Vault", 160)
  [void]$list.Columns.Add("Risk", 80)
  [void]$list.Columns.Add("URL", 240)
  [void]$list.Columns.Add("Rotated", 130)

  foreach ($secret in @($manifest.index.secrets)) {
    $vaultName = if ($vaults.ContainsKey($secret.vaultId)) { $vaults[$secret.vaultId].name } else { $secret.vaultId }
    $item = [System.Windows.Forms.ListViewItem]::new($secret.name)
    [void]$item.SubItems.Add($secret.username)
    [void]$item.SubItems.Add($vaultName)
    [void]$item.SubItems.Add($secret.risk)
    [void]$item.SubItems.Add($secret.url)
    [void]$item.SubItems.Add($secret.rotatedAt)
    [void]$list.Items.Add($item)
  }
  $form.Controls.Add($list)

  [void]$form.ShowDialog()
  $form.Dispose()
}

function Remove-ExpiredSentinelOfflineCache {
  $cache = Read-SentinelOfflineCache
  $expiresAt = [DateTimeOffset]::Parse($cache.cache.manifest.expiresAt)
  if ($expiresAt -le [DateTimeOffset]::UtcNow) {
    Remove-Item -LiteralPath $protectedOfflineCachePath -Force
    Write-Host "Removed expired Sentinel offline cache."
    return
  }
  Write-Host "Offline cache is still valid until $($cache.cache.manifest.expiresAt)."
}

function Install-SentinelOfflineCacheCleanupTask {
  $scriptPath = $PSCommandPath
  if (!$scriptPath) {
    throw "Cannot install scheduled task because the helper script path is unavailable."
  }
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -RemoveExpiredOfflineCache"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1)
  $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel LeastPrivilege
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $offlineCleanupTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Write-Host "Installed scheduled task '$offlineCleanupTaskName' for hourly Sentinel offline cache cleanup."
}

function Remove-SentinelOfflineCacheCleanupTask {
  $task = Get-ScheduledTask -TaskName $offlineCleanupTaskName -ErrorAction SilentlyContinue
  if ($task) {
    Unregister-ScheduledTask -TaskName $offlineCleanupTaskName -Confirm:$false
    Write-Host "Removed scheduled task '$offlineCleanupTaskName'."
  } else {
    Write-Host "Scheduled task '$offlineCleanupTaskName' is not installed."
  }
}

if ($SelfTest) {
  $sample = "sentinel-self-test"
  $hash = Get-SentinelHash -Text $sample
  if ($hash.Length -ne 64) { throw "SHA-256 marker hash failed self-test." }
  $roundTrip = [System.Text.Encoding]::UTF8.GetString((Unprotect-SentinelBytes -Bytes (Protect-SentinelBytes -Bytes ([System.Text.Encoding]::UTF8.GetBytes($sample)))))
  if ($roundTrip -ne $sample) { throw "DPAPI round-trip failed self-test." }
  if ("Invoke-SentinelAutoType".Length -lt 1) { throw "Autotype function self-test failed." }
  if ($offlineCleanupTaskName -ne "SentinelVaultOfflineCacheCleanup") { throw "Offline cleanup task name self-test failed." }
  Write-Host "Sentinel Vault companion self-test passed."
  exit 0
}

Write-Host "Sentinel Vault Windows companion"
Write-Host "Console: $ConsoleUrl"

if ($ClearNow) {
  Clear-SentinelClipboard | Out-Null
  exit 0
}

if ($Tray) {
  Start-SentinelTray
  exit 0
}

if ($ProtectOfflineCache) {
  Protect-SentinelOfflineCache -InputPath $OfflineCachePath
  exit 0
}

if ($ShowOfflineCache) {
  Show-SentinelOfflineCache
  exit 0
}

if ($BrowseOfflineCache) {
  Open-SentinelOfflineCacheBrowser
  exit 0
}

if ($RemoveExpiredOfflineCache) {
  Remove-ExpiredSentinelOfflineCache
  exit 0
}

if ($InstallOfflineCacheCleanupTask) {
  Install-SentinelOfflineCacheCleanupTask
  exit 0
}

if ($RemoveOfflineCacheCleanupTask) {
  Remove-SentinelOfflineCacheCleanupTask
  exit 0
}

if ($AutoType) {
  Invoke-SentinelAutoType -TargetWindowTitle $WindowTitle -UserNameValue $Username -PasswordValue $Password
  exit 0
}

if ($Value) {
  Set-SentinelClipboard -SecretValue $Value
}

if ($Watch) {
  Watch-SentinelClipboard
} elseif (!$Value) {
  Write-Host "Use -Tray for the desktop helper UI, -ProtectOfflineCache to store an exported cache with DPAPI, -ShowOfflineCache or -BrowseOfflineCache to inspect its read-only metadata, -InstallOfflineCacheCleanupTask to schedule expiry cleanup, -Value to copy a Sentinel-owned value, -Watch to clear it after TTL, -ClearNow to clear the current Sentinel-owned value, or -AutoType with -IUnderstandAutotypeRisk for a guarded proof of concept."
}
