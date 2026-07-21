param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath
)

$ErrorActionPreference = "Stop"

$Resolved = (Resolve-Path $DriverPath).Path
$Signature = Get-AuthenticodeSignature $Resolved

if ($Signature.Status -ne "Valid") {
    throw "The supplied driver does not have a valid Authenticode signature: $($Signature.Status)"
}

$DestinationDirectory = Join-Path $PSScriptRoot "..\SignedDriver"
$Destination = Join-Path $DestinationDirectory "DoubleGKernel.sys"

New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
Copy-Item $Resolved $Destination -Force

Write-Host "Signed driver imported: $Destination" -ForegroundColor Green
