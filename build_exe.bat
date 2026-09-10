@echo off
title Building Suresh Pro Studio 2.0 Executable...
color 0a
echo ==========================================================
echo   COMPILING SURESH PRO STUDIO 2.0 STANDALONE EXECUTABLE
echo ==========================================================
echo.

set PYTHON_PATH=C:\Users\Suresh\AppData\Local\Programs\Python\Python311\python.exe

if not exist "%PYTHON_PATH%" (
    set PYTHON_PATH=python
)

echo Using Python at: %PYTHON_PATH%
echo Running PyInstaller build...
echo.

"%PYTHON_PATH%" -m PyInstaller Suresh_Pro_Studio_2.spec --clean --noconfirm

if %ERRORLEVEL% equ 0 (
    echo.
    echo ==========================================================
    echo   BUILD SUCCESSFUL!
    echo   Copying executable to Desktop...
    echo ==========================================================
    copy /y "dist\Suresh Pro Studio 2.0.exe" "C:\Users\Suresh\OneDrive - Parle Tech\Desktop\Suresh Pro Studio 2.0.exe"
    echo.
    echo Standalone executable is now live on your Desktop!
) else (
    echo.
    echo [ERROR] PyInstaller build failed. Check the error log above.
)

pause
