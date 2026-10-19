# Сборка с предупреждениями как ошибками + все тесты. Краткий вывод для запуска по SSH.
param([string]$Configuration = "Debug", [switch]$NoTests)
$ErrorActionPreference = "Continue"
$build = dotnet build Nexora.slnx -c $Configuration -warnaserror -nologo 2>&1
$errors = $build | Select-String -Pattern ": (error|warning) " | ForEach-Object { $_.Line.Trim() } | Sort-Object -Unique
$errors | Select-Object -First 40
if ($LASTEXITCODE -ne 0) { "BUILD FAILED ($($errors.Count) diagnostics)"; exit 1 }
"BUILD OK"
if ($NoTests) { exit 0 }
$test = dotnet test --solution Nexora.slnx -c $Configuration --no-build 2>&1
$code = $LASTEXITCODE
$test | Select-String -Pattern "failed|сбой|Assert|error|пройдено|итог|успешно|пропущено|Error Message|at Nexora|\[FAIL\]" | ForEach-Object { $_.Line } | Select-Object -First 80
if ($code -ne 0) { "TESTS FAILED"; exit 1 }
"TESTS OK"
