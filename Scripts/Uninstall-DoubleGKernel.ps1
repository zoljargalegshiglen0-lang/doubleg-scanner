$ErrorActionPreference = "Stop"

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

& sc.exe stop DoubleGKernel *> $null
& sc.exe delete DoubleGKernel *> $null

$Destination = Join-Path $env:windir "System32\drivers\DoubleGKernel.sys"

if (Test-Path $Destination) {
    Remove-Item $Destination -Force
}

Write-Host "DoubleGKernel service and file removed." -ForegroundColor Green
