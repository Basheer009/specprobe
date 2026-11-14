@echo off
setlocal
rem Stays in the caller's directory so relative paths like --json-file work.
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo Virtual env not found. Run setup.bat first.
    exit /b 1
)
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
"%~dp0.venv\Scripts\python.exe" -m specprobe %*
exit /b %errorlevel%
