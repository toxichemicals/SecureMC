@echo off
timeout /t 2 /nobreak >nul
del "%~1"
move "%~2" "%~1"
start "" "%~1"