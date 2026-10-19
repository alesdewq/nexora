# Запуск Nexora.exe без прав администратора (runas /trustlevel:0x20000, Basic User) с ожиданием файла-результата.
# Пример: build\run-limited.ps1 -Arguments '--scan "C:\out"' -WaitFor 'C:\out\scan.log'
param([Parameter(Mandatory)][string]$Arguments, [Parameter(Mandatory)][string]$WaitFor,
      [string]$Exe = "src\Nexora.App\bin\Debug\net10.0-windows\win-x64\Nexora.exe", [int]$TimeoutSec = 300)
$ErrorActionPreference = "Stop"
$exePath = (Resolve-Path $Exe).Path
Remove-Item -Force $WaitFor -EA SilentlyContinue
$out = runas /trustlevel:0x20000 "`"$exePath`" $Arguments" 2>&1
if ($LASTEXITCODE -ne 0) { "runas: $out"; exit 1 }
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while (-not (Test-Path $WaitFor) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
if (-not (Test-Path $WaitFor)) { "timeout: $WaitFor не появился за $TimeoutSec с"; exit 1 }
Start-Sleep -Seconds 1
"OK: $WaitFor"
