param(
  [string]$ConsoleUrl = "http://127.0.0.1:5173",
  [int]$ClipboardTtlSeconds = 30,
  [string]$Value = "",
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

if ($SelfTest) {
  $sample = "sentinel-self-test"
  $hash = Get-SentinelHash -Text $sample
  if ($hash.Length -ne 64) { throw "SHA-256 marker hash failed self-test." }
  Write-Host "Sentinel Vault companion self-test passed."
  exit 0
}

Write-Host "Sentinel Vault Windows companion"
Write-Host "Console: $ConsoleUrl"

if ($ClearNow) {
  Clear-SentinelClipboard | Out-Null
  exit 0
}

if ($Value) {
  Set-SentinelClipboard -SecretValue $Value
}

if ($Watch) {
  Watch-SentinelClipboard
} elseif (!$Value) {
  Write-Host "Use -Value to copy a Sentinel-owned value, -Watch to clear it after TTL, or -ClearNow to clear the current Sentinel-owned value."
}
