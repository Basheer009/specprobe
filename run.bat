@echo off
setlocal
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo Virtual env not found. Run setup.bat first.
    exit /b 1
)
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
"%~dp0.venv\Scripts\python.exe" -m specprobe.gui %*
endlocal
