param(
    [Parameter(Mandatory = $false)]
    [string]$DriverPath = (Join-Path $PSScriptRoot "..\SignedDriver\DoubleGKernel.sys")
)

$ErrorActionPreference = "Stop"

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

$Resolved = (Resolve-Path $DriverPath).Path
$Signature = Get-AuthenticodeSignature $Resolved

if ($Signature.Status -ne "Valid") {
    throw "Driver signature is not valid. Refusing to install: $($Signature.Status)"
}

$Destination = Join-Path $env:windir "System32\drivers\DoubleGKernel.sys"
Copy-Item $Resolved $Destination -Force

& sc.exe stop DoubleGKernel *> $null
& sc.exe delete DoubleGKernel *> $null
Start-Sleep -Milliseconds 500

& sc.exe create DoubleGKernel type= kernel start= demand `
    binPath= "`"$Destination`"" `
    DisplayName= "DoubleG Kernel Scanner"

if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create failed with exit code $LASTEXITCODE."
}

& sc.exe start DoubleGKernel

if ($LASTEXITCODE -ne 0) {
    throw "Driver service was created but could not be started. Windows may not trust this driver on the current system."
}

Write-Host "DoubleGKernel.sys installed and started." -ForegroundColor Green
