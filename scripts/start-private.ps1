param(
    [int]$Port = 8765,
    [string]$DataDirectory = '',
    [switch]$Lan,
    [string]$AllowedHosts = '',
    [string]$AllowedOrigins = '',
    [string]$Certificate = '',
    [string]$PrivateKey = '',
    [string]$RequiredModel = 'iforest-v2',
    [string]$RequiredModelSha256 = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (!(Test-Path -LiteralPath $pythonPath)) { throw '请先运行 scripts\setup-private.ps1' }
if (!$DataDirectory) { $DataDirectory = Join-Path $projectRoot 'runtime' }
$launchArgs = @('-m', 'datafence.server', '--data-dir', $DataDirectory, '--port', "$Port")
$launchArgs += @('--require-model', $RequiredModel)
if ($RequiredModelSha256) { $launchArgs += @('--require-model-sha256', $RequiredModelSha256) }
if ($Lan) {
    if (!$AllowedHosts -or !$AllowedOrigins -or !$Certificate -or !$PrivateKey) {
        throw '内网部署必须指定 AllowedHosts、HTTPS AllowedOrigins、Certificate 和 PrivateKey'
    }
    $launchArgs += @('--lan', '--allowed-hosts', $AllowedHosts, '--allowed-origins', $AllowedOrigins,
                     '--tls-cert', $Certificate, '--tls-key', $PrivateKey)
}
if (!$Lan) {
    $localUrl = "http://127.0.0.1:$Port"
    try {
        $live = Invoke-RestMethod -Uri "$localUrl/api/health/live" -TimeoutSec 2
        $authStatus = Invoke-RestMethod -Uri "$localUrl/api/auth/status" -TimeoutSec 2
        if ($live.status -eq 'ok' -and $authStatus.authentication_required -eq $true -and
            $authStatus.network_mode -eq 'local') {
            Write-Output "DataFence 已在 $localUrl 运行。请直接打开网页，不要重复启动。"
            return
        }
    } catch {
        # No matching local DataFence response: continue with normal startup.
    }
}
Set-Location -LiteralPath $projectRoot
$nativeExitCode = 1
$previousErrorAction = $ErrorActionPreference
try {
    # Windows PowerShell can surface a native process's stderr as an ErrorRecord.
    # The process exit code, rather than a log line, decides whether startup failed.
    $ErrorActionPreference = 'Continue'
    & $pythonPath @launchArgs
    $nativeExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousErrorAction
}
if ($nativeExitCode -ne 0) { throw "DataFence 服务退出：$nativeExitCode" }
