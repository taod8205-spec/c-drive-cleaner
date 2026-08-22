@echo off
setlocal
cd /d "%~dp0"

where pyw.exe >nul 2>nul
if not errorlevel 1 (
    start "" pyw.exe -3 "%~dp0app.pyw"
    exit /b 0
)

where pythonw.exe >nul 2>nul
if not errorlevel 1 (
    start "" pythonw.exe "%~dp0app.pyw"
    exit /b 0
)

where py.exe >nul 2>nul
if not errorlevel 1 (
    py.exe -3 "%~dp0app.py"
    exit /b %errorlevel%
)

echo [错误] 未找到 Python 3。请先安装 Python 3.11 或更高版本。
echo 下载地址：https://www.python.org/downloads/windows/
pause
exit /b 1
