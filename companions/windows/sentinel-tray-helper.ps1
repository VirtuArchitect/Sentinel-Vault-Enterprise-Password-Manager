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
  [switch]$Watch,
  [switch]$ClearNow,
  [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$stateDir = Join-Path $env:LOCALAPPDATA "SentinelVault"
$markerPath = Join-Path $stateDir "clipboard-marker.json"

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

if ($SelfTest) {
  $sample = "sentinel-self-test"
  $hash = Get-SentinelHash -Text $sample
  if ($hash.Length -ne 64) { throw "SHA-256 marker hash failed self-test." }
  if ("Invoke-SentinelAutoType".Length -lt 1) { throw "Autotype function self-test failed." }
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
  Write-Host "Use -Tray for the desktop helper UI, -Value to copy a Sentinel-owned value, -Watch to clear it after TTL, -ClearNow to clear the current Sentinel-owned value, or -AutoType with -IUnderstandAutotypeRisk for a guarded proof of concept."
}
