param(
  [string]$ArtifactsDir = "artifacts\windows",
  [switch]$RequireValid
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root $ArtifactsDir

if (!(Test-Path -LiteralPath $artifactRoot)) {
  throw "Artifacts directory not found: $artifactRoot"
}

$artifacts = Get-ChildItem -LiteralPath $artifactRoot -File |
  Where-Object { $_.Extension -in @(".zip", ".exe", ".msi", ".msix") }

if (!$artifacts) {
  throw "No Windows release artifacts found in $artifactRoot"
}

$results = foreach ($artifact in $artifacts) {
  $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
  [ordered]@{
    file = $artifact.Name
    path = $artifact.FullName
    status = [string]$signature.Status
    signer = $signature.SignerCertificate.Subject
    thumbprint = $signature.SignerCertificate.Thumbprint
    timestamp = $signature.TimeStamperCertificate.Subject
  }
}

$results | ConvertTo-Json | Write-Host

if ($RequireValid -and ($results | Where-Object { $_.status -ne "Valid" })) {
  throw "One or more Windows release artifacts are not signed with a valid Authenticode signature."
}
