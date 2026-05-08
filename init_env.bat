@echo off
@echo off
setlocal

:: 1. 检查 Python 是否安装
where python >nul 2>nul
if %errorlevel% equ 0 (
    echo [✓] 检测到 Python 已安装。
) else (
    echo [!] 未检测到 Python，准备自动安装...

    :: 尝试使用 winget 安装 (Windows 10/11 自带)
    :: --silent 表示静默安装，--scope machine 表示为所有用户安装
    winget install --id Python.Python.3.12 --silent --scope machine

    if %errorlevel% neq 0 (
        echo [X] 自动安装失败。请手动访问 python.org 安装。
        pause
        exit /b 1
    )
    echo [✓] Python 安装指令已发送，请稍等片刻后重启程序。
)

:: 2. 创建虚拟环境并安装依赖
echo [1/3] 正在创建虚拟环境...
python -m venv .venv

echo [2/3] 正在升级 pip...
.\.venv\Scripts\python.exe -m pip install --upgrade pip

echo [3/3] 正在根据 requirements.txt 安装依赖...
if exist requirements.txt (
    .\.venv\Scripts\pip.exe install -r requirements.txt
) else (
    echo 错误：未找到 requirements.txt，正在尝试直接安装 cryptography...
    .\.venv\Scripts\pip.exe install cryptography
)

echo ========================================
echo ✅ 环境初始化完成！
endlocal