@echo off
setlocal

cd /d "%~dp0"

echo Starting BBBL-Core...
echo Press Ctrl+C to stop, or just close this window.
echo.

bbbl-core.exe %*

echo.
echo BBBL-Core exited (exit code %errorlevel%).
echo This window stays open so you can read any errors above.
pause
