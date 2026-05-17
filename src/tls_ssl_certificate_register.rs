use std::{fs, io};
use std::path::Path;
use std::process::Command;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

// --- bat 脚本生成环境 ---
///日志：
///     05.08构建函数
fn run_init_script() -> io::Result<()> {
    println!("正在运行初始化脚本...");

    // 在 Windows 上，我们需要调用 cmd /C 来运行批处理文件
    let status = Command::new("cmd")
        .args(["/C", "init_env.bat"]) // /C 表示执行完命令后关闭窗口
        .status()?;

    if status.success() {
        println!("✅ 初始化脚本执行成功");
    } else {
        eprintln!("❌ 初始化脚本执行失败");
    }

    // 检查 .venv 是否生成成功（作为安装成功的标志）
    if !Path::new(".venv").exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Python 虽已安装但环境未就绪，请重启电脑或终端后再运行。"
        ));
    }

    Ok(())
}

// --- SSL/TSL证书安装 ---
///日志：
///     05.08构建函数
fn install_cert_as_admin() -> io::Result<()> {
    println!("Requesting administrator privileges to install the certificate...");

    // 使用 PowerShell 启动进程
    // -Verb runAs 是关键，它会触发 UAC 弹窗
    let status = Command::new("powershell")
        .args([
            "Start-Process",
            "install_cert.bat",
            "-Verb",
            "runAs",
            "-Wait" // 等待 .bat 执行完再继续 Rust 逻辑
        ])
        .status()?;

    if status.success() {
        println!("✅ Administrative task completed.");
    } else {
        eprintln!("❌ Failed to get administrator privileges.");
    }

    Ok(())
}

// --- Python 脚本生成证书 ---
///日志：
///     05.08构建函数
pub(crate)fn run_python_setup() -> io::Result<()> {
    println!("正在调用本地虚拟环境中的 Python 配置 HTTPS...");

    run_init_script().expect("调用初始化脚本失败");
    // 根据操作系统确定本地 Python 的路径
    // Windows 路径是 .venv/Scripts/python.exe
    // Linux/macOS 路径是 .venv/bin/python
    let python_path = if cfg!(windows) {
        ".venv/Scripts/python.exe"
    } else {
        ".venv/bin/python"
    };

    // 检查本地 Python 是否存在，不存在则报错提醒
    if !Path::new(python_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "未找到虚拟环境！请先运行 'python -m venv .venv' 并安装依赖。"
        ));
    }

    let status = Command::new(python_path) // 使用本地路径
        .arg("./processes/setup_https.py")
        .status()?;

    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "Python 脚本执行失败"));
    }
    install_cert_as_admin().expect("install cert false");
    Ok(())
}

// --- 载入证书配置 ---
///日志：
///     05.08构建函数
pub(crate)fn load_rustls_config() -> ServerConfig {
    let mut cert_file = io::BufReader::new(fs::File::open("./static/cert.pem")
        .expect("无法找到 cert.pem，请确保 Python 脚本运行成功"));
    let mut key_file = io::BufReader::new(fs::File::open("./static/key.pem")
        .expect("无法找到 key.pem，请确保 Python 脚本运行成功"));

    let cert_chain = certs(&mut cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

    let mut keys = pkcs8_private_keys(&mut key_file).unwrap();

    if keys.is_empty() {
        panic!("key.pem 中没有找到有效的私钥");
    }

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKey(keys.remove(0)))
        .expect("构建 Rustls 配置失败")
}
