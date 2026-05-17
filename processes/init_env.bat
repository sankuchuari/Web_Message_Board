@echo off
:: 设置字符集为 UTF-8 避免中文显示乱码（如果保存为 UTF-8 的话）
:: chcp 65001 >nul

echo [1/3] Checking Python environment...
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Python not found. Installing via Winget...
    winget install --id Python.Python.3.12 --silent --scope machine
    if %errorlevel% neq 0 (
        echo [X] Installation failed. Please install Python manually from python.org
        pause
        exit /b 1
    )
    echo [!] Python installed. Please RESTART this program.
    pause
    exit /b 1
)

echo [2/3] Creating virtual environment...
:: 使用 python -m venv 创建，避免直接写中文在命令里
python -m venv .venv

echo [3/3] Installing dependencies...
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\pip.exe install cryptography

echo ========================================
echo [OK] Environment initialized successfully!
echo ========================================
:: 如果你是通过 Rust 调用的，可以去掉 pause 让它自动返回
