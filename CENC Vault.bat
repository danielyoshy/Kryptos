@echo off
rem Double-click to open the CENC File Vault desktop app.
rem A console window stays open while the app runs so any startup error is visible.
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel%==0 (
    python cenc_gui.py
) else (
    where py >nul 2>nul
    if errorlevel 1 (
        echo Python was not found. Install it from https://www.python.org/downloads/
        echo and tick "Add python.exe to PATH" during setup.
        pause
        exit /b 1
    )
    py cenc_gui.py
)

if errorlevel 1 (
    echo.
    echo The app failed to start. Read the message above.
    echo If it mentions "cryptography", run:  pip install -r requirements.txt
    pause
)
