@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%run-vps-analysis.ps1"

if not exist "%PS_SCRIPT%" (
  echo [ERROR] No se encontro run-vps-analysis.ps1
  pause
  exit /b 1
)

if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
)

echo.
echo Proceso finalizado.
pause
