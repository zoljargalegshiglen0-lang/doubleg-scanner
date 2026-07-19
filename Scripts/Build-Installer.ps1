$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "Build-Release.ps1")
$Candidates = @("$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe","$env:ProgramFiles\Inno Setup 6\ISCC.exe")
$Iscc = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Iscc) { throw "Inno Setup 6 not found. Install it, then rerun." }
& $Iscc (Join-Path $PSScriptRoot "..\Installer\DoubleGScanner.iss")
