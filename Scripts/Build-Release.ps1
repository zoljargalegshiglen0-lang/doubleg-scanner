$ErrorActionPreference = "Stop"
$Project = Join-Path $PSScriptRoot "..\DoubleGScanner\DoubleGScanner.csproj"
$Output = Join-Path $PSScriptRoot "..\Release\win-x64"

& dotnet restore $Project
if ($LASTEXITCODE -ne 0) {
    throw "dotnet restore failed with exit code $LASTEXITCODE."
}

& dotnet publish $Project -c Release -r win-x64 --self-contained true -o $Output `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:PublishTrimmed=false
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}

Write-Host "Release created: $Output" -ForegroundColor Green


$SignedDriver = Join-Path $PSScriptRoot "..\SignedDriver\DoubleGKernel.sys"
$DriverOutput = Join-Path $Output "Drivers"

if (Test-Path $SignedDriver) {
    $Signature = Get-AuthenticodeSignature $SignedDriver

    if ($Signature.Status -ne "Valid") {
        throw "SignedDriver\DoubleGKernel.sys is present but its signature is not valid: $($Signature.Status)"
    }

    New-Item -ItemType Directory -Path $DriverOutput -Force | Out-Null
    Copy-Item $SignedDriver (Join-Path $DriverOutput "DoubleGKernel.sys") -Force

    Copy-Item (Join-Path $PSScriptRoot "Install-DoubleGKernel.ps1") `
        (Join-Path $DriverOutput "Install-DoubleGKernel.ps1") -Force

    Copy-Item (Join-Path $PSScriptRoot "Uninstall-DoubleGKernel.ps1") `
        (Join-Path $DriverOutput "Uninstall-DoubleGKernel.ps1") -Force

    Write-Host "Valid signed DoubleGKernel.sys included." -ForegroundColor Green
}
else {
    Write-Warning "No Microsoft-signed DoubleGKernel.sys was supplied. The application will build, but kernel-level Forensic coverage will be unavailable."
}
