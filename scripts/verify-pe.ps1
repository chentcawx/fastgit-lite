<#
.SYNOPSIS
  Verify that fastgithub.exe is a 32-bit Windows GUI PE with an asInvoker manifest.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-pe.ps1 -Path dist\fastgithub.exe

.EXIT CODES
  0 = all checks passed (PE_VERDICT=PASS)
  1 = one or more checks failed (PE_VERDICT=FAIL)
#>
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Error "File not found: $Path"
    exit 1
}

$resolved = (Resolve-Path -LiteralPath $Path).Path
$bytes = [System.IO.File]::ReadAllBytes($resolved)
if ($bytes.Length -lt 256) {
    Write-Error "File is too small to be a PE image: $resolved"
    exit 1
}

$lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
if ($lfanew -le 0 -or ($lfanew + 96) -gt $bytes.Length) {
    Write-Error "Invalid e_lfanew offset: $lfanew"
    exit 1
}

$machine  = [BitConverter]::ToUInt16($bytes, $lfanew + 4)
$chars    = [BitConverter]::ToUInt16($bytes, $lfanew + 22)
$opt      = $lfanew + 24
$magic    = [BitConverter]::ToUInt16($bytes, $opt)
$subsys   = [BitConverter]::ToUInt16($bytes, $opt + 68)
$peSigOk  = ($bytes[$lfanew] -eq 0x50) -and ($bytes[$lfanew + 1] -eq 0x45) -and
            ($bytes[$lfanew + 2] -eq 0) -and ($bytes[$lfanew + 3] -eq 0)
$mzOk     = ($bytes[0] -eq 0x4D) -and ($bytes[1] -eq 0x5A)

$ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
$hasAsInvoker  = $ascii.Contains('asInvoker')
$hasWin10      = $ascii.Contains('8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a')
$hasRequireAdm = $ascii.Contains('requireAdministrator')
$mzText = if ($mzOk) { 'MZ' } else { 'bad' }
$peText = if ($peSigOk) { 'PE' } else { 'bad' }

$checks = @(
    [pscustomobject]@{ Name = 'DOS MZ';                  Actual = $mzText;                                     Expected = 'MZ';        OK = $mzOk }
    [pscustomobject]@{ Name = 'PE signature';            Actual = $peText;                                     Expected = 'PE';        OK = $peSigOk }
    [pscustomobject]@{ Name = 'Machine (I386)';          Actual = ('0x{0:X4}' -f $machine);                   Expected = '0x014C';    OK = ($machine -eq 0x014C) }
    [pscustomobject]@{ Name = 'Characteristics 32BIT';   Actual = ('0x{0:X4}' -f $chars);                     Expected = 'bit 0x100'; OK = (($chars -band 0x0100) -ne 0) }
    [pscustomobject]@{ Name = 'OptionalHeader PE32';     Actual = ('0x{0:X4}' -f $magic);                     Expected = '0x010B';    OK = ($magic -eq 0x010B) }
    [pscustomobject]@{ Name = 'Subsystem WINDOWS_GUI';   Actual = $subsys;                                     Expected = 2;           OK = ($subsys -eq 2) }
    [pscustomobject]@{ Name = 'manifest asInvoker';      Actual = $hasAsInvoker;                               Expected = $true;       OK = $hasAsInvoker }
    [pscustomobject]@{ Name = 'manifest supportedOS 10'; Actual = $hasWin10;                                   Expected = $true;       OK = $hasWin10 }
    [pscustomobject]@{ Name = 'no requireAdministrator'; Actual = $hasRequireAdm;                              Expected = $false;      OK = (-not $hasRequireAdm) }
)

$failed = @($checks | Where-Object { -not $_.OK })

if (-not $Quiet) {
    Write-Output ("File : {0}" -f $resolved)
    Write-Output ("Size : {0} bytes" -f $bytes.Length)
    Write-Output ('-' * 78)
    $checks | ForEach-Object {
        $mark = if ($_.OK) { 'PASS' } else { 'FAIL' }
        Write-Output ("[{0}] {1,-30} actual={2,-12} expected={3}" -f $mark, $_.Name, $_.Actual, $_.Expected)
    }
}

if ($failed.Count -gt 0) {
    Write-Output 'PE_VERDICT=FAIL'
    exit 1
}

Write-Output 'PE_VERDICT=PASS'
exit 0
