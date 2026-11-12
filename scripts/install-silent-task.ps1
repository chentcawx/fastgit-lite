<#
.SYNOPSIS
  Optional silent logon autostart for fastgithub.exe. Never shows a UAC prompt.

.DESCRIPTION
  * If the current session is elevated: register a hidden scheduled task at logon
    with RunLevel Limited (no elevation at logon, no window).
  * If the session is NOT elevated: fall back to a Startup-folder shortcut,
    which requires no administrator rights. The executable is a GUI-subsystem
    binary, so either path produces no console window.
  * The script never launches the process itself and never modifies hosts,
    registry proxy settings, the root certificate store or git configuration.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-silent-task.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-silent-task.ps1 -Uninstall

.NOTES
  The scheduled task path is optional. Installing a Windows service instead is
  done explicitly with: fastgithub.exe start   (requires an elevated session).
#>
[CmdletBinding()]
param(
    [string] $ExePath,
    [string] $TaskName = 'FastGithub-Silent',
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'

if (-not $ExePath) {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $ExePath = Join-Path $projectRoot 'dist\fastgithub.exe'
}
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'FastGithub-Silent.lnk'

# --------------------------------------------------------------------------
# Removal
# --------------------------------------------------------------------------
if ($Uninstall) {
    $removed = $false
    try {
        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Output "Removed scheduled task '$TaskName'."
            $removed = $true
        }
    } catch {
        Write-Warning "Could not query/remove scheduled task: $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $shortcutPath) {
        Remove-Item -LiteralPath $shortcutPath -Force
        Write-Output "Removed startup shortcut '$shortcutPath'."
        $removed = $true
    }
    if (-not $removed) { Write-Output 'No silent autostart entry was registered.' }
    exit 0
}

# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
    Write-Error "Executable not found: $ExePath`nRun scripts\build-x86.cmd first."
    exit 1
}
$exe = (Resolve-Path -LiteralPath $ExePath).Path
$workDir = Split-Path -Parent $exe
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isElevated) {
    Write-Output "Elevated session detected: registering hidden scheduled task '$TaskName'."
    $action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $workDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $currentUser `
        -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -Hidden `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $taskPrincipal -Settings $settings -Force | Out-Null
    Write-Output 'Done. The task starts at logon with no window, no console and no UAC prompt.'
} else {
    Write-Output 'Non-elevated session: using a Startup-folder shortcut (no UAC needed).'
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcutPath)
    $link.TargetPath = $exe
    $link.WorkingDirectory = $workDir
    $link.WindowStyle = 7
    $link.Description = 'FastGithub silent background accelerator'
    $link.Save()
    Write-Output "Done. Shortcut: $shortcutPath"
}

Write-Output ''
Write-Output 'Verify after logon:'
Write-Output '  Get-Process fastgithub | Select-Object Id,MainWindowHandle,MainWindowTitle'
Write-Output '  # MainWindowHandle must be 0 and MainWindowTitle empty.'
