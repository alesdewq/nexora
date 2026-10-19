#!/usr/bin/env bash
# Зеркально синхронизировать исходники (Linux-машина) → Windows-машина по SSH и выполнить там PowerShell-команду в каталоге проекта.
# Использование: build/sync-and-run.sh 'dotnet test'
# Настройки — переменные окружения или файл ${NEXORA_ENV:-~/.config/nexora/remote.env}:
#   NEXORA_REMOTE=user@host   NEXORA_WIN_DIR='C:\src\Nexora'   [NEXORA_WIN_STAGE='C:\src\.nexora-stage']
set -euo pipefail
ENV_FILE="${NEXORA_ENV:-$HOME/.config/nexora/remote.env}"
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE="${NEXORA_REMOTE:?задайте NEXORA_REMOTE=user@host}"
WIN_DIR="${NEXORA_WIN_DIR:?задайте NEXORA_WIN_DIR — каталог проекта на Windows}"
STAGE="${NEXORA_WIN_STAGE:-$WIN_DIR.stage}"
tar -C "$SRC" --exclude=.git --exclude='bin' --exclude='obj' --exclude='artifacts' --exclude='TestResults' \
    --exclude='reports' --exclude='logs' -czf - . \
  | ssh -o BatchMode=yes "$REMOTE" "powershell -NoProfile -Command \"Remove-Item -Recurse -Force '$STAGE' -EA SilentlyContinue; New-Item -ItemType Directory -Force '$STAGE' | Out-Null; tar -xzf - -C '$STAGE'; robocopy '$STAGE' '$WIN_DIR' /MIR /XD bin obj artifacts TestResults /NFL /NDL /NJH /NJS /NP | Out-Null; if (\$LASTEXITCODE -ge 8) { Write-Error 'robocopy failed'; exit 1 } else { exit 0 }\""
[ $# -eq 0 ] && exit 0
script="[Console]::OutputEncoding=[Text.Encoding]::UTF8; \$OutputEncoding=[Text.Encoding]::UTF8; \$ProgressPreference='SilentlyContinue'; \$ErrorActionPreference='Continue'
\$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'; \$env:DOTNET_NOLOGO='1'; \$env:PATH=\"\$env:USERPROFILE\\.dotnet;\$env:PATH\"; \$env:DOTNET_ROOT=\"\$env:USERPROFILE\\.dotnet\"; Set-Location '$WIN_DIR'; $*"
enc="$(printf '%s' "$script" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)"
exec ssh -o BatchMode=yes -o ConnectTimeout=15 "$REMOTE" "powershell -NoProfile -NonInteractive -EncodedCommand $enc"
