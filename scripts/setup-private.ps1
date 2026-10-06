param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
& $Python -c 'import sys; assert sys.version_info >= (3,12), "Python 3.12+ required"'
if ($LASTEXITCODE -ne 0) { throw '请指定可用的 Python 3.12+：-Python C:\path\python.exe' }
if (!(Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    & $Python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw '创建Python环境失败' }
}
& '.\.venv\Scripts\python.exe' -m pip install -r requirements.lock.txt -e .
if ($LASTEXITCODE -ne 0) { throw '依赖安装失败' }
if (!(Test-Path -LiteralPath 'frontend\dist\index.html')) {
    throw '未发现构建后的界面；源码开发请运行scripts\setup.ps1，发布包应包含frontend/dist'
}
Write-Output '安装完成。运行 scripts\start-private.ps1，然后在本机网页设置首个管理员。'
