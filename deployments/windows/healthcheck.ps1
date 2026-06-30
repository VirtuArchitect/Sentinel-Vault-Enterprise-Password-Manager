param(
  [string]$Url = "http://127.0.0.1:5173/healthz",
  [int]$TimeoutSeconds = 5
)

$ErrorActionPreference = "Stop"

try {
  $response = Invoke-RestMethod -Uri $Url -TimeoutSec $TimeoutSeconds
  if ($response.ok -ne $true) {
    throw "Health endpoint returned an unhealthy payload."
  }
  Write-Host "Sentinel Vault is healthy at $Url"
  exit 0
} catch {
  Write-Error "Sentinel Vault health check failed: $($_.Exception.Message)"
  exit 1
}
