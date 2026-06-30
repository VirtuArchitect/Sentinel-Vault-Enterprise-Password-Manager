param(
  [string]$InstallDir = "$env:ProgramFiles\Sentinel Vault"
)

$ErrorActionPreference = "Stop"

$envFile = Join-Path $InstallDir "sentinel.env"
$logDir = Join-Path $InstallDir "logs"
$server = Join-Path $InstallDir "server.mjs"

if (!(Test-Path $server)) {
  throw "Sentinel Vault server was not found at $server"
}

New-Item -ItemType Directory -Path $logDir -Force | Out-Null

if (Test-Path $envFile) {
  Get-Content $envFile | ForEach-Object {
    if ($_ -match "^\s*#" -or $_ -notmatch "=") { return }
    $name, $value = $_.Split("=", 2)
    [Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), "Process")
  }
}

$env:NODE_ENV = "production"
$node = (Get-Command node -ErrorAction Stop).Source

while ($true) {
  $stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
  Add-Content -Path (Join-Path $logDir "sentinel-supervisor.log") -Value "$stamp starting Sentinel Vault"

  $process = Start-Process `
    -FilePath $node `
    -ArgumentList "server.mjs" `
    -WorkingDirectory $InstallDir `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $logDir "sentinel.out.log") `
    -RedirectStandardError (Join-Path $logDir "sentinel.err.log")

  $process.WaitForExit()
  $exitCode = $process.ExitCode
  $stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
  Add-Content -Path (Join-Path $logDir "sentinel-supervisor.log") -Value "$stamp Sentinel Vault exited with code $exitCode; restarting in 5 seconds"
  Start-Sleep -Seconds 5
}
