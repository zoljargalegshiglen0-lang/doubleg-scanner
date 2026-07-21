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

Write-Host "Kernel driver packaging is handled separately by the Build DoubleG Kernel Driver workflow." -ForegroundColor DarkGray
