param(
  [string]$ConsoleUrl = "http://127.0.0.1:5173",
  [int]$ClipboardTtlSeconds = 30
)

$ErrorActionPreference = "Stop"

Write-Host "Sentinel Vault tray helper prototype"
Write-Host "Console: $ConsoleUrl"
Write-Host "Clipboard TTL: $ClipboardTtlSeconds seconds"
Write-Host "Future implementation: tray icon, clipboard auto-clear timer, offline cache unlock, and native autotype broker."
