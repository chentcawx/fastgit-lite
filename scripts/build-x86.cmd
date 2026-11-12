@echo off
setlocal EnableExtensions
rem ---------------------------------------------------------------------------
rem One-shot 32-bit Release build + deployment staging + PE verification.
rem All messages are ASCII on purpose (no codepage dependency).
rem ---------------------------------------------------------------------------

for %%i in ("%~dp0..") do set "ROOT=%%~fi"
set "TARGET=i686-pc-windows-msvc"
set "OUT=%ROOT%\target\%TARGET%\release"
set "DIST=%ROOT%\dist"

echo [1/5] Checking Rust toolchain ...
where cargo >nul 2>nul || (echo ERROR: cargo not found in PATH & exit /b 1)
where rustup >nul 2>nul || (echo ERROR: rustup not found in PATH & exit /b 1)
rustup target list --installed | findstr /C:"%TARGET%" >nul || (
    echo ERROR: target %TARGET% is not installed.
    echo        Run: rustup target add %TARGET%
    exit /b 1
)

echo [2/5] cargo build --release --target %TARGET% ...
pushd "%ROOT%" || exit /b 1
cargo build --release --target %TARGET%
if errorlevel 1 (
    popd
    echo ERROR: cargo build failed.
    exit /b 1
)
popd

if not exist "%OUT%\fastgithub.exe" (
    echo ERROR: %OUT%\fastgithub.exe was not produced.
    exit /b 1
)

echo [3/5] Staging dist\ ...
if not exist "%DIST%" mkdir "%DIST%"
if not exist "%DIST%\config" mkdir "%DIST%\config"
if not exist "%DIST%\config\appsettings" mkdir "%DIST%\config\appsettings"
if not exist "%DIST%\resources" mkdir "%DIST%\resources"
if not exist "%DIST%\scripts" mkdir "%DIST%\scripts"

copy /Y "%OUT%\fastgithub.exe" "%DIST%\fastgithub.exe" >nul || (echo ERROR: copy exe failed & exit /b 1)
copy /Y "%ROOT%\config\appsettings.json" "%DIST%\config\appsettings.json" >nul || (echo ERROR: copy appsettings.json failed & exit /b 1)
copy /Y "%ROOT%\config\appsettings\*.json" "%DIST%\config\appsettings\" >nul || (echo ERROR: copy domain configs failed & exit /b 1)
copy /Y "%ROOT%\config\ad-domains.txt" "%DIST%\config\ad-domains.txt" >nul || (echo ERROR: copy ad-domains.txt failed & exit /b 1)
copy /Y "%ROOT%\resources\app.manifest" "%DIST%\resources\app.manifest" >nul
copy /Y "%ROOT%\README.md" "%DIST%\README.md" >nul
copy /Y "%ROOT%\scripts\install-ca.ps1" "%DIST%\scripts\install-ca.ps1" >nul
copy /Y "%ROOT%\scripts\regen-ca.ps1" "%DIST%\scripts\regen-ca.ps1" >nul

echo [4/5] Verifying PE32 / GUI subsystem / asInvoker manifest ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify-pe.ps1" -Path "%DIST%\fastgithub.exe"
if errorlevel 1 (
    echo ERROR: PE verification failed.
    exit /b 1
)

echo [5/5] Done.
echo.
echo   EXE  : %DIST%\fastgithub.exe
echo   CFG  : %DIST%\config\appsettings.json
echo   RUN  : start "" "%DIST%\fastgithub.exe"
echo   LOGS : %DIST%\logs\log-YYYY-MM-DD.txt
echo.
exit /b 0
