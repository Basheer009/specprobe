@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Failed to create venv. Is Python 3.10+ installed and on PATH?
        exit /b 1
    )
)

".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -e ".[gui]"
if errorlevel 1 (
    echo Dependency install failed.
    exit /b 1
)

echo.
echo Setup complete.
echo   run.bat   - launch the desktop UI
echo   cli.bat   - run the CLI (e.g. cli.bat --url URL spec --table)
endlocal
