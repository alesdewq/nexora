# Smoke-тест NEXORA без прав администратора: runas /trustlevel:0x20000 (Basic User) запускает приложение
# с урезанным токеном — группа Administrators отключена, IsInRole(Administrator) = false. Системные настройки не меняются.
param([string]$Exe = "src\Nexora.App\bin\Debug\net10.0-windows\win-x64\Nexora.exe",
      [string]$Out = "artifacts\smoke-limited", [int]$TimeoutSec = 120)
$ErrorActionPreference = "Stop"
$exePath = (Resolve-Path $Exe).Path
$outPath = Join-Path (Get-Location).Path $Out
Remove-Item -Recurse -Force $outPath -EA SilentlyContinue
$log = Join-Path $outPath "smoke.log"
runas /trustlevel:0x20000 "`"$exePath`" --smoke-test `"$outPath`""
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while (-not (Test-Path $log) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
Start-Sleep -Seconds 1
if (-not (Test-Path $log)) { throw "smoke.log не появился за $TimeoutSec с" }
$lines = Get-Content -Encoding UTF8 $log
$lines
if (-not ($lines -match "elevated=False")) { throw "Процесс получил права администратора — проверка некорректна" }
if (-not ($lines -contains "SMOKE PASS")) { exit 1 }
