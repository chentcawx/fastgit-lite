<#
.SYNOPSIS
    One-off install (or removal) of the FastGithub local CA for MITM mode.

.DESCRIPTION
    The background service NEVER writes to the certificate store. Run this
    script explicitly, once. By default the CA goes into CurrentUser\Root, so
    no administrator rights and no UAC prompt are needed. Pass -Machine to
    install into LocalMachine\Root for all users (requires elevation).

    After installation the browser trusts locally issued leaf certificates and
    no runtime dialog appears.

.PARAMETER Machine
    Also install into LocalMachine\Root (requires Administrator).

.PARAMETER Uninstall
    Remove the CA from both scopes.

.PARAMETER ExeDir
    Directory containing fastgithub.exe (defaults to ..\dist).

.PARAMETER CerPath
    Full path to the CA public certificate. Use this on LAN client machines that
    do not have a local dist folder. Distribute only fastgithub.cer (public
    key) — NEVER distribute fastgithub.key (the CA private key).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-ca.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install-ca.ps1 -Uninstall
    powershell -ExecutionPolicy Bypass -File .\install-ca.ps1 -CerPath .\fastgithub.cer
#>
[CmdletBinding()]
param(
    [switch] $Uninstall,
    [switch] $Machine,
    [string] $CerPath,
    [string] $ExeDir
)

$ErrorActionPreference = 'Stop'

# Resolve the default inside the script body: $PSScriptRoot is not guaranteed
# to be set while param() default expressions are evaluated (e.g. `& $script`).
# Works both from source (`fastgithub-rs\scripts`) and from the staged copy
# (`dist\scripts`): probe for fastgithub.exe instead of assuming one layout.
if (-not $ExeDir) {
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) {
        $cmdPath = $MyInvocation.MyCommand.Path
        if (-not $cmdPath) { $cmdPath = $PSCommandPath }
        if ($cmdPath) { $scriptDir = Split-Path -Parent $cmdPath }
    }
    if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
    $parentDir = Split-Path -Parent $scriptDir
    $candidates = @(
        (Join-Path $scriptDir '..\dist'),
        $parentDir,
        $scriptDir
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'fastgithub.exe'))) {
            $ExeDir = $candidate
            break
        }
    }
    if (-not $ExeDir) { $ExeDir = Join-Path $scriptDir '..\dist' }
}

# PowerShell variable names are case-insensitive: $exeDir IS $ExeDir. Never
# assign the resolved value back to it, or a failed Resolve-Path erases the
# original path and every later Join-Path -Path gets an empty string.
$resolvedExeDir = (Resolve-Path -LiteralPath $ExeDir -ErrorAction SilentlyContinue).Path
if (-not $resolvedExeDir) { $resolvedExeDir = $ExeDir }
$caPem = Join-Path $resolvedExeDir 'cacert\fastgithub-ca.pem'
$exe = Join-Path $resolvedExeDir 'fastgithub.exe'

if ($CerPath) {
    # LAN client: import a copied public certificate, never generate a local CA.
    $caPath = (Resolve-Path -LiteralPath $CerPath -ErrorAction SilentlyContinue).Path
    if (-not $caPath) { Write-Error "未找到 CA 证书: $CerPath"; exit 1 }
} else {
    $caPath = Join-Path $resolvedExeDir 'cacert\fastgithub.cer'   # DER, .NET-friendly
}

if ($Machine) {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error '-Machine 需要管理员权限；或以默认方式安装到当前用户（无需提权）。'
        exit 1
    }
}

if (-not $CerPath -and -not (Test-Path -LiteralPath $caPath)) {
    if (-not (Test-Path -LiteralPath $exe)) {
        Write-Error "未找到 $exe，请先执行 scripts\build-x86.cmd 完成构建。"
        exit 1
    }
    Write-Host '本地 CA 尚未生成，启动程序数秒以生成 cacert ...' -ForegroundColor Cyan
    $proc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
}
if (-not (Test-Path -LiteralPath $caPath)) {
    Write-Error "CA 生成失败，未找到 $caPath"
    exit 1
}
Write-Host "CA 证书来源: $caPath" -ForegroundColor Gray

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPath)
$scopes = @('CurrentUser')
if ($Machine -or $Uninstall) { $scopes += 'LocalMachine' }

foreach ($scope in $scopes) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $scope)
    try {
        $store.Open('ReadWrite')
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if ($Uninstall) {
            if ($existing) {
                $store.Remove($existing)
                Write-Host "[$scope] 已卸载 FastGithub 本地 CA" -ForegroundColor Green
            }
        } elseif ($existing) {
            Write-Host "[$scope] 已安装，跳过 (Thumbprint $($cert.Thumbprint))" -ForegroundColor Green
        } else {
            $store.Add($cert)
            Write-Host "[$scope] 已安装到「受信任的根证书颁发机构」(Thumbprint $($cert.Thumbprint))" -ForegroundColor Green
        }
    } catch {
        Write-Warning "[$scope] 操作失败: $($_.Exception.Message)"
    } finally {
        $store.Close()
    }
}

if (-not $Uninstall) {
    Write-Host ''
    Write-Host '完成。请重启浏览器后访问 https://github.com/ 验证。' -ForegroundColor Cyan
    Write-Host '注：curl / PowerShell 等 Schannel 客户端需加 --ssl-no-revoke（自建 CA 无 CRL）；浏览器不受影响。' -ForegroundColor Yellow
    if (-not $CerPath -and $caPem -and (Test-Path -LiteralPath $caPem)) { Write-Host "CA 证书副本: $caPem" }
}
