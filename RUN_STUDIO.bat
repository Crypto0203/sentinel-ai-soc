@echo off
title SURESH PRO STUDIO 2.0
color 0b
echo ===================================================
echo   SURESH PRO STUDIO 2.0 - UNIFIED ENGINE LAUNCHER
echo ===================================================
echo.
echo Starting Python Studio Engine...

set PYTHON_PATH=C:\Users\Suresh\AppData\Local\Programs\Python\Python311\python.exe

if exist "%PYTHON_PATH%" (
    "%PYTHON_PATH%" studio_app.py
) else (
    python studio_app.py
)

pause
