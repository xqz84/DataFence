$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw '虚拟环境创建失败' }
}
$dependencyFile = if (Test-Path -LiteralPath 'requirements.lock.txt') { 'requirements.lock.txt' } else { 'requirements.txt' }
& '.\.venv\Scripts\python.exe' -m pip install -r $dependencyFile -e .
if ($LASTEXITCODE -ne 0) { throw 'Python 依赖安装失败' }
Push-Location -LiteralPath 'frontend'
try {
    npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw '前端依赖安装失败' }
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw '前端构建失败' }
} finally { Pop-Location }
Write-Output '安装完成。运行 .\scripts\start.ps1 后打开 http://127.0.0.1:8765'
