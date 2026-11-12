<#
.SYNOPSIS
    Rotate (re-generate) the FastGithub local CA.

.DESCRIPTION
    One-shot maintenance command. It stops a running instance, invokes
    `fastgithub.exe regen-ca` (which backs up and regenerates the 10-year CA),
    removes the OLD CA from CurrentUser\Root, imports the NEW one, and restarts
    the instance if it was running. The program itself never writes to the
    certificate store; this script does it explicitly, without UAC.

    IMPORTANT: every LAN client must re-import the new
    dist\cacert\fastgithub.cer afterwards. Never distribute fastgithub.key.

.PARAMETER SkipInstall
    Only rotate the files; do not touch the local certificate store.

.PARAMETER NoRestart
    Do not restart the program even if it was running before.

.PARAMETER ExeDir
    Directory containing fastgithub.exe (auto-detected by default).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\regen-ca.ps1
    powershell -ExecutionPolicy Bypass -File scripts\regen-ca.ps1 -SkipInstall -NoRestart
#>
[CmdletBinding()]
param(
    [switch] $SkipInstall,
    [switch] $NoRestart,
    [string] $ExeDir
)

$ErrorActionPreference = 'Stop'

# Auto-detect dist\ both from the source scripts dir and from dist\scripts.
if (-not $ExeDir) {
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) {
        $cmdPath = $MyInvocation.MyCommand.Path
        if (-not $cmdPath) { $cmdPath = $PSCommandPath }
        if ($cmdPath) { $scriptDir = Split-Path -Parent $cmdPath }
    }
    if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
    $parentDir = Split-Path -Parent $scriptDir
    foreach ($candidate in @((Join-Path $scriptDir '..\dist'), $parentDir, $scriptDir)) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'fastgithub.exe'))) {
            $ExeDir = $candidate
            break
        }
    }
    if (-not $ExeDir) { $ExeDir = Join-Path $scriptDir '..\dist' }
}

$resolvedExeDir = (Resolve-Path -LiteralPath $ExeDir -ErrorAction SilentlyContinue).Path
if (-not $resolvedExeDir) { Write-Error "未找到程序目录: $ExeDir"; exit 1 }
$exe = Join-Path $resolvedExeDir 'fastgithub.exe'
$cer = Join-Path $resolvedExeDir 'cacert\fastgithub.cer'
$installScript = Join-Path $resolvedExeDir 'scripts\install-ca.ps1'
if (-not (Test-Path -LiteralPath $exe)) { Write-Error "未找到 $exe"; exit 1 }

$oldThumb = $null
if (Test-Path -LiteralPath $cer) {
    $oldCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)
    $oldThumb = $oldCert.Thumbprint
    Write-Host "旧 CA Thumbprint: $oldThumb" -ForegroundColor Gray
}

# Only stop instances launched from THIS exe, so running the script against a
# test copy never kills the production background service.
$procs = @(Get-Process -Name fastgithub -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and ($_.Path -ieq $exe) } catch { $false }
})
if ($procs.Count -gt 0) {
    Write-Host "正在停止 $($procs.Count) 个运行中的实例 ..." -ForegroundColor Cyan
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
}

Write-Host '正在轮换本地 CA ...' -ForegroundColor Cyan
$proc = Start-Process -FilePath $exe -ArgumentList 'regen-ca' -WindowStyle Hidden -PassThru -Wait
if ($proc.ExitCode -ne 0) { Write-Error "regen-ca 退出码 $($proc.ExitCode)，详见 dist\logs"; exit 1 }
if (-not (Test-Path -LiteralPath $cer)) { Write-Error "新 CA 未生成: $cer"; exit 1 }

$newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)
$newThumb = $newCert.Thumbprint
Write-Host "新 CA Thumbprint: $newThumb" -ForegroundColor Green
if ($oldThumb -and $oldThumb -eq $newThumb) {
    Write-Warning 'Thumbprint 未变化，请检查 cacert 目录权限与日志。'
}

$backup = Get-ChildItem -LiteralPath (Join-Path $resolvedExeDir 'cacert') -Directory -Filter 'backup-*' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($backup) { Write-Host "旧 CA 备份: $($backup.FullName)" -ForegroundColor Gray }

if (-not $SkipInstall) {
    if ($oldThumb -and $oldThumb -ne $newThumb) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
        try {
            $store.Open('ReadWrite')
            $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $oldThumb }
            if ($existing) {
                $store.Remove($existing)
                Write-Host "已从 CurrentUser\Root 卸载旧 CA $oldThumb" -ForegroundColor Green
            }
        } catch {
            Write-Warning "卸载旧 CA 失败: $($_.Exception.Message)"
        } finally {
            $store.Close()
        }
    }
    if (Test-Path -LiteralPath $installScript) {
        & $installScript -CerPath $cer
    } else {
        Write-Warning "未找到 $installScript，请手动导入新 CA。"
    }
}

if ($procs.Count -gt 0 -and -not $NoRestart) {
    $restarted = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru
    Write-Host "已重新启动静默实例 PID $($restarted.Id)" -ForegroundColor Green
}

Write-Host ''
Write-Host '⚠️ 所有局域网客户端必须重新导入新的 fastgithub.cer，否则会出现证书告警。' -ForegroundColor Yellow
Write-Host "   仅分发: $cer" -ForegroundColor Yellow
Write-Host '   绝不分发: fastgithub.key（CA 私钥）' -ForegroundColor Yellow
Write-Host '   客户端: powershell -ExecutionPolicy Bypass -File .\install-ca.ps1 -CerPath .\fastgithub.cer' -ForegroundColor Yellow
