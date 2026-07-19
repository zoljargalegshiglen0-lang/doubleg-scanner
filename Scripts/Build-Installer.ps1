$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "Build-Release.ps1")

$Candidates = @(
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
    "C:\ProgramData\chocolatey\bin\iscc.exe"
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

$Command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($Command) {
    $Candidates = @($Command.Source) + $Candidates
}

$Iscc = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Iscc) {
    $Found = Get-ChildItem "C:\Program Files (x86)", "C:\Program Files", "C:\ProgramData\chocolatey" `
        -Filter ISCC.exe -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Found) { $Iscc = $Found.FullName }
}

if (-not $Iscc) {
    throw "Inno Setup 6 ISCC.exe was not found after installation."
}

& $Iscc (Join-Path $PSScriptRoot "..\Installer\DoubleGScanner.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compiler failed with exit code $LASTEXITCODE."
}
