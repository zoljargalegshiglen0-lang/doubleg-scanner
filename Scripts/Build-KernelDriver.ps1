$ErrorActionPreference = "Stop"

$Project = Join-Path $PSScriptRoot "..\Driver\DoubleGKernel\DoubleGKernel.vcxproj"
$ReleaseRoot = Join-Path $PSScriptRoot "..\Release\KernelDriver\Unsigned"

$VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path $VsWhere)) {
    throw "vswhere.exe was not found. Install Visual Studio 2022 with Desktop development with C++."
}

$MsBuild = & $VsWhere -latest -products * -requires Microsoft.Component.MSBuild `
    -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1

if (-not $MsBuild) {
    throw "MSBuild.exe was not found."
}

& $MsBuild $Project /restore /t:Clean,Build `
    /p:Configuration=Release `
    /p:Platform=x64 `
    /m

if ($LASTEXITCODE -ne 0) {
    throw "Kernel driver build failed with exit code $LASTEXITCODE."
}

$Driver = Get-ChildItem (Join-Path $PSScriptRoot "..\Driver\DoubleGKernel") `
    -Filter DoubleGKernel.sys -File -Recurse |
    Where-Object { $_.FullName -match "\\Release\\" } |
    Select-Object -First 1

if (-not $Driver) {
    throw "DoubleGKernel.sys was not produced."
}

New-Item -ItemType Directory -Path $ReleaseRoot -Force | Out-Null
Copy-Item $Driver.FullName (Join-Path $ReleaseRoot "DoubleGKernel.sys") -Force

$Pdb = Get-ChildItem $Driver.Directory.FullName `
    -Filter DoubleGKernel.pdb -File -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($Pdb) {
    Copy-Item $Pdb.FullName (Join-Path $ReleaseRoot "DoubleGKernel.pdb") -Force
}

$Hash = (Get-FileHash (Join-Path $ReleaseRoot "DoubleGKernel.sys") -Algorithm SHA256).Hash
"$Hash  DoubleGKernel.sys" |
    Out-File (Join-Path $ReleaseRoot "DoubleGKernel.sys.sha256.txt") -Encoding ascii

@"
UNSIGNED DEVELOPMENT BUILD

This driver cannot be loaded on a normal production Windows installation.
Do not disable Secure Boot or Windows security protections to force-load it.

Submit the driver package through the Microsoft Hardware Developer Program,
then place the Microsoft-signed DoubleGKernel.sys in:

SignedDriver\DoubleGKernel.sys
"@ | Out-File (Join-Path $ReleaseRoot "README.txt") -Encoding utf8

Write-Host "Unsigned kernel-driver artifact: $ReleaseRoot" -ForegroundColor Yellow
