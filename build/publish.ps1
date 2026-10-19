# Сборка выпуска: тесты → самодостаточный однофайловый Nexora.exe (win-x64, .NET 10 внутри) → проверка опубликованного файла → ZIP + SHA256.
param([switch]$SkipTests)
$ErrorActionPreference = "Stop"
$version = ([xml](Get-Content Directory.Build.props)).Project.PropertyGroup.Version
$name = "NEXORA-$version-win-x64"
$pub = "artifacts\publish\$name"
if (-not $SkipTests) { powershell -NoProfile -ExecutionPolicy Bypass -File .\build\ci.ps1 -Configuration Release; if ($LASTEXITCODE -ne 0) { throw "тесты не прошли" } }
Remove-Item -Recurse -Force $pub -EA SilentlyContinue
dotnet publish src\Nexora.App\Nexora.App.csproj -c Release -r win-x64 --self-contained true -o $pub -nologo `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none | Select-Object -Last 2
if ($LASTEXITCODE -ne 0) { throw "publish failed" }
Copy-Item README-release.txt "$pub\README.txt"
Copy-Item THIRD-PARTY-NOTICES.txt "$pub\THIRD-PARTY-NOTICES.txt"

# Проверка именно опубликованного exe: окно + короткая настоящая проверка (только чтение, действия отклоняются).
$smoke = Join-Path (Get-Location) "artifacts\smoke-release"
Remove-Item -Recurse -Force $smoke -EA SilentlyContinue
$p = Start-Process -FilePath "$pub\Nexora.exe" -ArgumentList "--smoke-test", "`"$smoke`"", "--with-scan" -Wait -PassThru
Get-Content -Encoding UTF8 "$smoke\smoke.log" | Select-Object -Last 1
if ($p.ExitCode -ne 0) { throw "smoke-тест опубликованной сборки не прошёл" }

$zip = "artifacts\$name.zip"
Remove-Item -Force $zip -EA SilentlyContinue
Compress-Archive -Path "$pub\*" -DestinationPath $zip
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $name.zip" | Set-Content -Encoding ASCII "artifacts\$name.zip.sha256"
"{0}  {1:N1} MB  sha256={2}" -f $zip, ((Get-Item $zip).Length / 1MB), $hash
