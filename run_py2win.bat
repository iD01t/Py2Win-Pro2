@echo off
title Py2Win Premium v5.0.0
echo ================================================
echo          Py2Win Premium v5.0.0
echo   Enterprise Python to Windows Converter
echo ================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://www.python.org/
    pause
    exit /b 1
)

:: Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Detected Python version: %PYTHON_VERSION%
echo.

:: Install dependencies if needed
echo Checking dependencies...
python -c "import customtkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing required dependencies...
    pip install -r requirements.txt
    echo.
)

:: Run the application
echo Starting Py2Win Premium...
echo.
python py2win_premium_v5.py %*

:: Check if the application exited with an error
if %errorlevel% neq 0 (
    echo.
    echo Application exited with error code: %errorlevel%
    pause
)
