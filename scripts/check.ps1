$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
& '.\.venv\Scripts\python.exe' -m pytest -q
if ($LASTEXITCODE -ne 0) { throw '后端检查失败' }
Push-Location -LiteralPath 'frontend'
try {
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw '前端检查失败' }
} finally { Pop-Location }
