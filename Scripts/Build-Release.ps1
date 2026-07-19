$ErrorActionPreference = "Stop"
$Project = Join-Path $PSScriptRoot "..\DoubleGScanner\DoubleGScanner.csproj"
$Output = Join-Path $PSScriptRoot "..\Release\win-x64"
dotnet restore $Project
dotnet publish $Project -c Release -r win-x64 --self-contained true -o $Output `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false
Write-Host "Release created: $Output" -ForegroundColor Green
