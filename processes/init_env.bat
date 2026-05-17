@echo off
:: 设置字符集为 UTF-8 避免中文显示乱码（如果保存为 UTF-8 的话）
:: chcp 65001 >nul

echo [1/3] Checking Python environment...

:: 1. 第一重检查：尝试直接运行命令（针对新窗口/已配置好环境的情况）
python --version >nul 2>nul
if %errorlevel% equ 0 goto :python_exists

:: 2. 第二重检查：如果命令失败，去 Windows Machine 级别的默认安装路径肉眼确认文件是否存在
:: Winget --scope machine 默认会将 Python 3.14 安装到以下路径：
if exist "C:\Program Files\Python314\python.exe" goto :python_exists
if exist "C:\Program Files\Python 3.14\python.exe" goto :python_exists

:: 3. 如果两重检查都挂了，才真正说明没安装，去执行安装
echo [!] Python not found or invalid. Installing via Winget...
winget install --id Python.Python.3.14 --interactive --scope machine --accept-source-agreements --accept-package-agreements

timeout /t 2 >nul
echo [!] Python installed! Please restart。
pause
exit /b 1


:python_exists
echo [+] Python detection passed!

echo [2/3] Creating virtual environment...
:: 使用 python -m venv 创建，避免直接写中文在命令里
python -m venv ..\.venv

echo [3/3] Installing dependencies...
..\.venv\Scripts\python.exe -m pip install --upgrade pip
..\.venv\Scripts\python.exe -m pip install -r ..\requirements.txt

echo ========================================
echo [OK] Environment initialized successfully!
echo ========================================
:: 如果你是通过 Rust 调用的，可以去掉 pause 让它自动返回
