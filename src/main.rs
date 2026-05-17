use actix_web::{web, App, HttpServer, Responder, HttpResponse, get, post, cookie::Key, cookie::SameSite};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_multipart::Multipart;
use actix_files::Files;
use maud::{html, DOCTYPE, PreEscaped};
use pulldown_cmark::{Parser, Options, html::push_html};
use sqlx::{SqlitePool, sqlite::SqliteRow, Row};
use futures_util::TryStreamExt as _;
use uuid::Uuid;
use sanitize_filename::sanitize;
use std::{fs, io::Write, path::Path, io, time::Duration};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::Rng;
use ammonia::clean;
use std::process::Command;
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};

// --- 数据结构 ---

/// 存储在数据库中的留言信息结构体
struct StoredMessage {
    //日志ID
    id: i64,
    //用户名
    name: String,
    //渲染后的HTML文本内容
    message: String,
    //原始Markdown源码
    raw_message: String,
    //图片UUID
    image_path: Option<String>,
    //视频&其他媒体UUID
    video_path: Option<String>,
    //时间戳
    created_at: String,
}

/// 登录与注册表单接收模型
#[derive(serde::Deserialize)]
struct AuthForm {
    username: String,
    password: String,
}

/// 消息编辑表单接收模型
#[derive(serde::Deserialize)]
struct EditForm {
    message: String,
}

// --- Markdown 转 HTML ---
///日志：
///     04.26.2025构建函数
///     05.04.2026修复XSS漏洞
// 修复 XSS：Markdown 转 HTML 后必须经过 ammonia 清洗
fn markdown_to_html(input: &str) -> String {
    let mut html_output = String::new();
    let parser = Parser::new_ext(input, Options::all());
    push_html(&mut html_output, parser);
    // 使用 ammonia 清洗 HTML，防止存储型 XSS
    clean(&html_output)
}

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
    if !std::path::Path::new(".venv").exists() {
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
fn run_python_setup() -> io::Result<()> {
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
        .arg("setup_https.py")
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
fn load_rustls_config() -> ServerConfig {
    let mut cert_file = io::BufReader::new(fs::File::open("cert.pem")
        .expect("无法找到 cert.pem，请确保 Python 脚本运行成功"));
    let mut key_file = io::BufReader::new(fs::File::open("key.pem")
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

// --- 登录处理 ---
///日志：
///     05.03.2026构建函数
///     05.04.2026限制登录频率
#[post("/login")]
async fn login_handler(db: web::Data<SqlitePool>, session: Session, form: web::Form<AuthForm>) -> impl Responder {
    let delay = rand::thread_rng().gen_range(100..500);
    tokio::time::sleep(Duration::from_millis(delay)).await;

    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(db.get_ref())
        .await;

    let auth_failed = HttpResponse::Unauthorized().body("wrong_credentials");

    match row {
        Ok(Some(row)) => {
            let hash: String = row.get("password_hash");
            if let Ok(parsed_hash) = PasswordHash::new(&hash) {
                if Argon2::default().verify_password(form.password.as_bytes(), &parsed_hash).is_ok() {
                    let _ = session.insert("user", &form.username);
                    session.renew();
                    return HttpResponse::Ok().body("success");
                }
            }
            auth_failed
        }
        _ => auth_failed,
    }
}

// --- 账户验证处理 ---
///日志：
///     05.03.2026构建函数
///     05.04.2026模糊化登录错误反馈
#[post("/register")]
async fn register_handler(db: web::Data<SqlitePool>, form: web::Form<AuthForm>) -> impl Responder {
    if form.username.len() > 32 || form.password.len() > 128 {
        return HttpResponse::BadRequest().body("invalid_input");
    }

    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(form.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(&form.username)
        .bind(&password_hash)
        .execute(db.get_ref())
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("registered"),
        Err(_) => HttpResponse::Conflict().body("user_exists"),
    }
}

// --- 登出处理 ---
///日志：
///     05.03.2026构建函数
#[get("/logout")]
async fn logout_handler(session: Session) -> impl Responder {
    session.purge();
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

// --- 主页面渲染  ---
///日志：
///     04.26.2025构建函数
///     04.30.2026重构函数
///     04.30.2026重构UI样式
///     05.03.2026增加登录UI、增加I18n双语逻辑
///     05.07.2026增加编辑UI逻辑
///     05.08.2026增加LaTeX渲染逻辑
///     05.08.2026优化编辑UI
///     05.08.2026优化编辑功能，确保长文本能正常编辑和保存
#[get("/")]
async fn index(db: web::Data<SqlitePool>, session: Session) -> impl Responder {
    // 获取当前登录用户名
    let current_user = session.get::<String>("user").unwrap_or(None);
    // 从数据库查询所有留言
    let messages = sqlx::query("SELECT id, name, message, raw_message, image_path, video_path, created_at FROM messages ORDER BY id DESC")
        .map(|row: SqliteRow| {
            let time_str: String = row.try_get("created_at").unwrap_or_else(|_| "刚刚".to_string());
            StoredMessage {
                id: row.get("id"),
                name: row.get("name"),
                message: row.get("message"),
                raw_message: row.try_get("raw_message").unwrap_or_else(|_| "".to_string()),
                image_path: row.get("image_path"),
                video_path: row.get("video_path"),
                created_at: if time_str.len() > 16 { time_str[..16].to_string() } else { time_str },
            }
        })
        .fetch_all(db.get_ref()).await.unwrap_or_default();

    // 构建页面模板
    let markup = html! {
        (DOCTYPE)
        html lang="zh-CN" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title id="page-title" { "MESSAGE BOARD" }
                link rel="icon" type="image/x-icon" href="/static/icon-64x64.ico";

                // KaTeX CSS & JS (用于渲染 LaTeX)
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.10/dist/katex.min.css";
                script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.10/dist/katex.min.js" {}
                script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.10/dist/contrib/auto-render.min.js" onload=(PreEscaped("renderMathInElement(document.body, {delimiters:[{left:'$$',right:'$$',display:true},{left:'$',right:'$',display:false}]});")) {}

                script src="https://unpkg.com/jszip/dist/jszip.min.js" {}
                script src="https://unpkg.com/docx-preview/dist/docx-preview.min.js" {}

                // 引入 PDF.js 核心高兼容解析引擎库
                script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.4.120/pdf.min.js" {}

                style { (PreEscaped(r#"
                    :root { --bg-blur: rgba(255, 255, 255, 0.25); --text-color: #333; --overlay-opacity: 0; --modal-header-bg: rgba(0,0,0,0.05); --modal-control-color: #ffffff; }
                    .dark-mode { --bg-blur: rgba(0, 0, 0, 0.4); --text-color: #eee; --overlay-opacity: 0.6; --modal-header-bg: rgba(0,0,0,0.1); --modal-control-color: #ffffff; }
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body {
                        min-height: 100vh; font-family: -apple-system, sans-serif;
                        background: url('/static/back_image.png') fixed center/cover;
                        display: flex; flex-direction: column; align-items: center; padding: 40px 20px;
                        color: var(--text-color); transition: 0.3s; position: relative;
                    }
                    body::before { content: ""; position: fixed; inset: 0; background: black; opacity: var(--overlay-opacity); transition: 0.4s; z-index: -1; }
                    h1 { color: white; margin-bottom: 20px; letter-spacing: 4px; font-weight: 200; text-shadow: 0 2px 10px rgba(0,0,0,0.4); }
                    .glass {
                        background: var(--bg-blur); backdrop-filter: blur(25px) saturate(180%);
                        border: 1px solid rgba(255, 255, 255, 0.3); border-radius: 28px;
                        width: 100%; max-width: 500px; padding: 30px; margin-bottom: 25px; z-index: 1;
                    }
                    .input-box {
                        all: unset; display: block; width: 100%; padding: 12px 0;
                        border-bottom: 1px solid rgba(0,0,0,0.1); font-size: 1.1rem; margin-bottom: 20px;
                        white-space: pre-wrap; word-break: break-all; overflow-y: hidden; min-height: 40px;
                    }
                    .edit-area {
                          all: unset; width: 100%;
                          min-height: 220px;
                          padding: 15px;
                          background: rgba(255,255,255,0.1);
                          border: 1px solid rgba(110,142,251,0.4);
                          border-radius: 16px;
                          font-family: 'Fira Code', 'Courier New', monospace;
                          font-size: 1rem;
                          line-height: 1.5;
                          box-sizing: border-box;
                          display: block;
                          margin-bottom: 15px;
                          overflow-y: hidden;
                     }
                    .btn-submit {
                        all: unset; background: linear-gradient(135deg, #6e8efb, #a777e3);
                        color: white; padding: 10px 25px; border-radius: 20px; cursor: pointer; font-weight: 600; text-align: center;
                    }
                    .top-bar { display: flex; gap: 10px; margin-bottom: 20px; z-index: 1; }
                    .ctrl-btn { background: rgba(255,255,255,0.2); border: none; color: white; padding: 8px 15px; border-radius: 20px; cursor: pointer; text-decoration: none; font-size: 0.9rem; }
                    #file-list { margin-left: 15px; flex-grow: 1; font-size: 0.85rem; font-weight: 200; color: inherit; opacity: 0.9; display: flex; flex-direction: column; gap: 4px; }
                    .file-item { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 180px; }
                    .file-link { display: block; background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.2); padding: 12px 15px; border-radius: 12px; margin: 10px 0; text-decoration: none; color: inherit; font-size: 0.85rem; border-left: 4px solid #6e8efb; }
                    .media { width: 100%; border-radius: 18px; margin: 12px 0; display: block; }
                    .time { font-size: 0.7rem; opacity: 0.4; text-align: right; display: block; margin-top: 15px; }
                    .del-btn { color: #ff4757; border: none; background: none; cursor: pointer; opacity: 0.6; }

                    #toast {
                        visibility: hidden; min-width: 250px; background-color: rgba(0, 0, 0, 0.85); backdrop-filter: blur(10px);
                        color: #fff; text-align: center; border-radius: 25px; padding: 14px 24px;
                        position: fixed; z-index: 1000; left: 50%; bottom: -60px; transform: translateX(-50%);
                        font-size: 0.95rem; box-shadow: 0 4px 15px rgba(0,0,0,0.3); transition: 0.3s;
                    }
                    #toast.show {
                        visibility: visible; animation: slide-up-down 10s ease-in-out forwards;
                    }
                    @keyframes slide-up-down {
                        0% { bottom: -60px; opacity: 0; }
                        5% { bottom: 30px; opacity: 1; }
                        95% { bottom: 30px; opacity: 1; }
                        100% { bottom: -60px; opacity: 0; }
                    }

                    /* PDF 专属渲染器控制面板样式 */
                    .pdf-toolbar { display: flex; justify-content: center; align-items: center; gap: 12px; background: rgba(0,0,0,0.15); padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.15); color: white; font-size: 0.9rem; }
                    .pdf-btn { background: rgba(255,255,255,0.2); border: none; color: white; padding: 4px 12px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; transition: 0.2s; }
                    .pdf-btn:hover { background: rgba(255,255,255,0.35); }
                    .pdf-canvas-container { width: 100%; height: 100%; overflow: auto; display: flex; justify-content: center; align-items: flex-start; padding: 20px; box-sizing: border-box; }
                    .dark-mode-pdf { filter: invert(0.9) hue-rotate(180deg); }
                "#)) }
            }
            body {
                // 初始化暗色模式
                script { (PreEscaped(r#"if(localStorage.getItem("theme")==="dark")document.body.classList.add("dark-mode");"#)) }

                h1 id="main-title" { "MESSAGE BOARD" }

                div class="top-bar" {
                    button id="theme-toggle" class="ctrl-btn" onclick="toggleDarkMode()" { "🌓 Mode" }
                    button id="lang-toggle" class="ctrl-btn" onclick="toggleLang()" { "🌐 Lang" }
                    @if current_user.is_some() { a href="/logout" class="ctrl-btn" id="logout-btn" { "🚪 Logout" } }
                }

                div class="glass" {
                    @match current_user {
                        // 未登录状态：显示登录注册表单
                        None => {
                            form id="auth-form" method="post" action="/login" {
                                input type="text" name="username" id="login-user" class="input-box" placeholder="Username" required;
                                input type="password" name="password" id="login-pass" class="input-box" placeholder="Password" required;
                                div style="display:flex; gap:10px;" {
                                    button type="submit" id="signin-btn" class="btn-submit" style="flex:1" { "Sign In" }
                                    button type="submit" formaction="/register" id="signup-btn" class="btn-submit" style="flex:1; background:rgba(255,255,255,0.2)" { "Sign Up" }
                                }
                            }
                        }
                        // 已登录状态：显示发布留言表单
                        Some(ref user) => {
                            form method="post" action="/post" enctype="multipart/form-data" {
                                input type="text" name="user_name" class="input-box" value=(user) readonly;
                                textarea name="user_msg" id="grow-text" class="input-box" placeholder="Write some..." required {}
                                div style="display:flex; align-items:center;" {
                                    div style="position:relative; width:40px; height:40px; background:rgba(255,255,255,0.2); border-radius:50%; display:flex; align-items:center; justify-content:center; cursor:pointer; flex-shrink:0;" {
                                        span style="font-size:24px; color:white;" { "+" }
                                        input type="file" id="file-input" name="media" multiple style="position:absolute; inset:0; opacity:0; cursor:pointer;";
                                    }
                                    div id="file-list" {}
                                    button type="submit" id="btn-submit" class="btn-submit" { "Submit" }
                                }
                            }
                        }
                    }
                }

                // 只有登录用户可查看和管理留言
                @if let Some(ref user) = current_user {
                    h2 id="list-header" style="color:white; font-weight:200; margin-bottom:15px; width:100%; max-width:500px;" { "Message list：" }

                    @if messages.is_empty() {
                        div class="glass" id="empty-hint" style="text-align:center; color:white; font-style:italic;" { "No messages yet. Be the first!" }
                    } @else {
                        @for msg in &messages {
                            div class="glass" {
                                @if msg.name == *user {
                                    div style="float: right; display: flex; gap: 10px;" {
                                        // 编辑按钮
                                        button type="button" class="del-btn i18n-edit" onclick=(format!("editMsg({})", msg.id)) { "edit" }
                                        //删除按钮
                                        form method="post" action=(format!("/delete/{}", msg.id)) { button type="submit" class="del-btn i18n-del" { "delete" } }
                                    }
                                }
                                h3 { (msg.name) }
                                div {
                                    @if let Some(img_list) = &msg.image_path {
                                        @for img in img_list.split(',') {
                                            @if !img.is_empty() { img class="media" src=(format!("/uploads/{}", img)); }
                                        }
                                    }
                                    @if let Some(file_list) = &msg.video_path {
                                        @for path in file_list.split(',') {
                                            @if !path.is_empty() {
                                                @let ext = Path::new(path).extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                                                @if ["mp4", "webm", "mov"].contains(&ext.as_str()) {
                                                    video class="media" controls { source src=(format!("/uploads/{}", path)); }
                                                } @else if ["mp3", "wav", "ogg", "m4a", "flac", "aac"].contains(&ext.as_str()) {
                                                    audio controls style="width:100%; margin:10px 0; height:40px;" { source src=(format!("/uploads/{}", path)); }
                                                } @else {
                                                    a class="file-link" href="#" onclick=(format!("openPreview('/uploads/{}', '{}'); return false;", path, path)) {
                                                        span class="i18n-view" { "📄 View File: " } (path)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                // 将渲染后的 HTML 放入 div，并将原始源码存入 data-raw 属性以便编辑
                                div id=(format!("msg-text-{}", msg.id)) data-raw=(msg.raw_message) style="line-height:1.6; margin-top:10px;" { (PreEscaped(&msg.message)) }
                                span class="time" { (msg.created_at) }
                            }
                        }
                    }
                }

                div id="toast" {}

                div id="preview-modal" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); backdrop-filter:blur(12px); z-index:2000; align-items:center; justify-content:center; padding:20px;" {
                    div style="background:var(--bg-blur); backdrop-filter:blur(25px) saturate(180%); border:1px solid rgba(255,255,255,0.35); border-radius:24px; width:92%; max-width:1000px; height:85vh; display:flex; flex-direction:column; overflow:hidden; box-shadow:0 30px 60px rgba(0,0,0,0.25);" {
                        div style="display:flex; justify-content:space-between; align-items:center; padding:16px 24px; border-bottom:1px solid rgba(255,255,255,0.2); background:var(--modal-header-bg); transition: 0.3s;" {
                            span id="modal-filename" style="font-weight:600; color:white; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:70%;" { "File Name" }
                            div style="display:flex; gap:20px; align-items:center;" {
                                a id="modal-download-btn" href="#" download style="color:var(--modal-control-color); text-decoration:none; font-size:1.35rem; opacity:0.85; transition:0.2s;" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=0.85" { "📥" }
                                button onclick="closePreview()" style="background:none; border:none; color:var(--modal-control-color); font-size:1.45rem; cursor:pointer; opacity:0.85; transition:0.2s;" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=0.85" { "❌" }
                            }
                        }
                        div id="modal-body" style="flex-grow:1; width:100%; height:100%; position:relative; overflow:hidden;" {}
                    }
                }

                script { (PreEscaped("
                    const i18n = {
                        en: {
                            title: \"MESSAGE BOARD\", mode: \"🌓 Mode\", lang: \"🌐 Lang\",
                            loginUser: \"Username\", loginPass: \"Password\",
                            signin: \"Sign In\", signup: \"Sign Up\", logout: \"🚪 Logout\",
                            textPh: \"Write some...\", submit: \"Submit\", list: \"Message list：\",
                            del: \"delete\", edit: \"edit\", save: \"save\", cancel: \"cancel\",
                            empty: \"No messages yet. Be the first!\", view: \"📄 View File: \",
                            tipSuccess: \"✅ Login successful!\", tipNoUser: \"❌ Incorrect username or password.\", tipWrong: \"❌ Incorrect username or password.\", tipReg: \"📝 Registration successful! Now please Sign In.\", tipConflict: \"⚠️ Username already exists.\"
                        },
                        zh: {
                            title: \"留言板\", mode: \"🌓 模式\", lang: \"🌐 语言\",
                            loginUser: \"用户名\", loginPass: \"密码\",
                            signin: \"登录\", signup: \"注册\", logout: \"🚪 退出\",
                            textPh: \"说点什么...\", submit: \"发布留言\", list: \"历史留言：\",
                            del: \"删除\", edit: \"编辑\", save: \"保存\", cancel: \"取消\",
                            empty: \"暂无留言，快来抢沙发！\", view: \"📄 查看文件: \",
                            tipSuccess: \"✅ 登录成功！\", tipNoUser: \"❌ 用户名或密码错误\", tipWrong: \"❌ 用户名或密码错误\", tipReg: \"📝 注册成功！现在请登录。\", tipConflict: \"⚠️ 该用户名已被注册\"
                        }
                    };

                    // 初始化 PDF.js Worker 线程
                    if (window['pdfjs-dist/build/pdf']) {
                        pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.4.120/pdf.worker.min.js';
                    }

                    function showToast(msg) {
                        const t = document.getElementById(\"toast\");
                        t.textContent = msg;
                        t.classList.remove(\"show\");
                        void t.offsetWidth;
                        t.classList.add(\"show\");
                        setTimeout(() => t.classList.remove(\"show\"), 10000);
                    }

                    function updateUI() {
                        const lang = localStorage.getItem(\"lang\") || \"en\";
                        const t = i18n[lang];
                        document.getElementById(\"page-title\").textContent = t.title;
                        document.getElementById(\"main-title\").textContent = t.title;
                        document.getElementById(\"theme-toggle\").textContent = t.mode;
                        document.getElementById(\"lang-toggle\").textContent = t.lang;

                        const lUser = document.getElementById(\"login-user\"); if(lUser) lUser.placeholder = t.loginUser;
                        const lPass = document.getElementById(\"login-pass\"); if(lPass) lPass.placeholder = t.loginPass;
                        const siBtn = document.getElementById(\"signin-btn\"); if(siBtn) siBtn.textContent = t.signin;
                        const suBtn = document.getElementById(\"signup-btn\"); if(suBtn) suBtn.textContent = t.signup;

                        const logout = document.getElementById(\"logout-btn\"); if(logout) logout.textContent = t.logout;
                        const msgTa = document.getElementById(\"grow-text\"); if(msgTa) msgTa.placeholder = t.textPh;
                        const subBtn = document.getElementById(\"btn-submit\"); if(subBtn) subBtn.textContent = t.submit;
                        const listH = document.getElementById(\"list-header\"); if(listH) listH.textContent = t.list;
                        const emptyH = document.getElementById(\"empty-hint\"); if(emptyH) emptyH.textContent = t.empty;

                        document.querySelectorAll(\".i18n-del\").forEach(el => el.textContent = t.del);
                        document.querySelectorAll(\".i18n-edit\").forEach(el => el.textContent = t.edit);
                        document.querySelectorAll(\".i18n-view\").forEach(el => el.textContent = t.view);

                        // 每次UI更新后重新扫描渲染 LaTeX
                        if(window.renderMathInElement) renderMathInElement(document.body, {delimiters:[{left:'$$',right:'$$',display:true},{left:'$',right:'$',display:false}]});
                    }

                    function openPreview(fileUrl, fileName) {
                        const ext = fileName.split('.').pop().toLowerCase();
                        const modal = document.getElementById(\"preview-modal\");
                        const modalTitle = document.getElementById(\"modal-filename\");
                        const downloadBtn = document.getElementById(\"modal-download-btn\");
                        const modalBody = document.getElementById(\"modal-body\");

                        modalTitle.textContent = fileName;
                        downloadBtn.href = fileUrl;

                        const lang = localStorage.getItem(\"lang\") || \"en\";

                        if ([\"ppt\", \"pptx\"].includes(ext)) {
                            const msg = lang === \"zh\" ? \"该文件 (\" + fileName + \") 为 PPT 格式，无法直接预览。是否下载？\" : \"The file (\" + fileName + \") is in PPT format and cannot be previewed. Download it?\";
                            if (confirm(msg)) {
                                const a = document.createElement('a');
                                a.href = fileUrl;
                                a.download = fileName;
                                a.click();
                            }
                            return;
                        }

                        modalBody.innerHTML = \"\";

                        const isDark = document.body.classList.contains(\"dark-mode\");
                        const currentTextColor = isDark ? \"#ffffff\" : \"#222222\";
                        const currentBgColor = isDark ? \"transparent\" : \"rgba(255, 255, 255, 0.95)\";

                        if (ext === \"docx\") {
                            modalBody.innerHTML =
                                \"<div id=\\\"word-container\\\" style=\\\"width:100%; height:100%; overflow-y:auto; padding:35px; box-sizing:border-box; background:\" + currentBgColor + \"; transition: background 0.3s;\\\">\" +
                                    \"<div id=\\\"word-loading\\\" style=\\\"color:\" + currentTextColor + \"; opacity: 0.8; text-align:center; padding-top:50px; font-size:1rem;\\\">⌛ 正在解析 Word 文档，请稍候...</div>\" +
                                \"</div>\";
                            modal.style.display = \"flex\";

                            fetch(fileUrl)
                                .then(res => { if (!res.ok) throw new Error(\"Fetch failed\"); return res.blob(); })
                                .then(blob => {
                                    const container = document.getElementById(\"word-container\");
                                    docx.renderAsync(blob, container, null, {
                                        className: \"docx\",
                                        inWrapper: false,
                                        ignoreWidth: true,
                                        ignoreHeight: true,
                                        ignorePadding: false
                                    })
                                    .then(() => {
                                        const loadingEl = document.getElementById(\"word-loading\");
                                        if (loadingEl) loadingEl.remove();

                                        const allTexts = container.querySelectorAll(\"span, p, h1, h2, h3, h4, h5, h6, td\");
                                        allTexts.forEach(el => {
                                            if (!el.style.color || el.style.color === 'black' || el.style.color === 'rgb(0, 0, 0)' || el.style.color === '#000000') {
                                                el.style.color = currentTextColor;
                                            }
                                        });
                                        const allTables = container.querySelectorAll(\"table\");
                                        allTables.forEach(table => {
                                            table.style.backgroundColor = \"transparent\";
                                            table.style.borderColor = isDark ? \"rgba(255, 255, 255, 0.25)\" : \"rgba(0, 0, 0, 0.15)\";
                                        });
                                    })
                                    .catch(err => {
                                        container.innerHTML = \"<div style=\\\"color:red; padding:20px; text-align:center;\\\">❌ 渲染失败: \" + err.message + \"</div>\";
                                    });
                                })
                                .catch(() => {
                                    modalBody.innerHTML = \"<div style=\\\"color:var(--text-color, #ffffff); padding:20px; text-align:center;\\\">❌ 文件加载失败</div>\";
                                });
                        }
                        // 彻底切换为完全由前端沙盒渲染的 PDF.js 渲染引擎，摆脱浏览器和后端策略拦截
                        else if (ext === \"pdf\") {
                            modalBody.innerHTML =
                                \"<div style='display:flex; flex-direction:column; height:100%; width:100%;'>\" +
                                    \"<div class='pdf-toolbar'>\" +
                                        \"<button class='pdf-btn' id='pdf-prev'>⬅️ Prev</button>\" +
                                        \"<span>Page: <span id='pdf-num'>0</span> / <span id='pdf-count'>0</span></span>\" +
                                        \"<button class='pdf-btn' id='pdf-next'>Next ➡️</button>\" +
                                        \"<button class='pdf-btn' id='pdf-zoom-in'>➕</button>\" +
                                        \"<button class='pdf-btn' id='pdf-zoom-out'>➖</button>\" +
                                    \"</div>\" +
                                    \"<div class='pdf-canvas-container' style='background:\" + (isDark ? \"#222\" : \"#ccc\") + \";'>\" +
                                        \"<div id='pdf-loading' style='color:\" + (isDark?\"#fff\":\"#000\") + \"; margin:50px auto; text-align:center;'>⌛ Loading PDF...</div>\" +
                                        \"<canvas id='pdf-canvas' class='\" + (isDark ? \"dark-mode-pdf\" : \"\") + \"' style='box-shadow:0 4px 12px rgba(0,0,0,0.3); display:none;'></canvas>\" +
                                    \"</div>\" +
                                \"</div>\";
                            modal.style.display = \"flex\";

                            let pdfDoc = null, pageNum = 1, pageRendering = false, pageNumPending = null, scale = 1.3;
                            const canvas = document.getElementById('pdf-canvas'), ctx = canvas.getContext('2d');

                            function renderPage(num) {
                                pageRendering = true;
                                pdfDoc.getPage(num).then((page) => {
                                    const viewport = page.getViewport({ scale: scale });
                                    canvas.height = viewport.height;
                                    canvas.width = viewport.width;
                                    canvas.style.display = 'block';
                                    const loadingEl = document.getElementById('pdf-loading');
                                    if(loadingEl) loadingEl.style.display = 'none';

                                    const renderContext = { canvasContext: ctx, viewport: viewport };
                                    const renderTask = page.render(renderContext);

                                    renderTask.promise.then(() => {
                                        pageRendering = false;
                                        if (pageNumPending !== null) { renderPage(pageNumPending); pageNumPending = null; }
                                    });
                                });
                                document.getElementById('pdf-num').textContent = num;
                            }

                            function queueRenderPage(num) {
                                if (pageRendering) { pageNumPending = num; } else { renderPage(num); }
                            }

                            pdfjsLib.getDocument(fileUrl).promise.then((pdfDoc_) => {
                                pdfDoc = pdfDoc_;
                                document.getElementById('pdf-count').textContent = pdfDoc.numPages;
                                renderPage(pageNum);
                            }).catch(err => {
                                const loadEl = document.getElementById('pdf-loading');
                                if(loadEl) loadEl.textContent = \"❌ Failed to load PDF: \" + err.message;
                            });

                            document.getElementById('pdf-prev').addEventListener('click', () => { if (pageNum <= 1) return; pageNum--; queueRenderPage(pageNum); });
                            document.getElementById('pdf-next').addEventListener('click', () => { if (pageNum >= pdfDoc.numPages) return; pageNum++; queueRenderPage(pageNum); });
                            document.getElementById('pdf-zoom-in').addEventListener('click', () => { scale += 0.2; queueRenderPage(pageNum); });
                            document.getElementById('pdf-zoom-out').addEventListener('click', () => { if(scale <= 0.6) return; scale -= 0.2; queueRenderPage(pageNum); });
                        }
                        else if ([\"txt\", \"log\", \"md\", \"json\", \"js\", \"rs\", \"html\", \"css\"].includes(ext)) {
                            modalBody.innerHTML = \"<div style=\\\"color:var(--text-color); background:\" + currentBgColor + \"; padding:25px; font-family:monospace; white-space:pre-wrap; word-break:break-all; overflow-y:auto; height:100%; font-size: 0.95rem; transition: background 0.3s;\\\" id=\\\"text-loading\\\">加载中...</div>\";
                            modal.style.display = \"flex\";

                            fetch(fileUrl)
                                .then(res => res.text())
                                .then(text => {
                                    const el = document.getElementById(\"text-loading\");
                                    if(el) { el.textContent = text; el.id = \"\"; }
                                })
                                .catch(() => {
                                    document.getElementById(\"text-loading\").textContent = \"无法读取文本内容\";
                                });
                        }
                        else {
                            const hintText = lang === \"zh\" ? \"该文件格式不支持在线预览，请下载后查看。\" : \"Preview is not supported for this file format, please download to view.\";
                            const btnText = lang === \"zh\" ? \"下载文件\" : \"Download\";
                            modalBody.innerHTML =
                                \"<div style=\\\"display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; color:var(--text-color); background:\" + currentBgColor + \"; gap:20px; transition: background 0.3s;\\\">\" +
                                    \"<span style=\\\"font-size:3rem;\\\">📄</span>\" +
                                    \"<p style=\\\"opacity:0.7; font-size:0.95rem;\\\">\" + hintText + \"</p>\" +
                                    \"<a href=\\\"\" + fileUrl + \"\\\" download style=\\\"all: unset; background: linear-gradient(135deg, #6e8efb, #a777e3); color: white; padding: 12px 30px; border-radius: 20px; cursor: pointer; font-weight: 600;\\\" >\" + btnText + \"</a>\" +
                                \"</div>\";
                            modal.style.display = \"flex\";
                        }
                    }

                    function closePreview() {
                        const modal = document.getElementById(\"preview-modal\");
                        const modalBody = document.getElementById(\"modal-body\");
                        modal.style.display = \"none\";
                        modalBody.innerHTML = \"\";
                    }

                    document.addEventListener(\"click\", function(e) {
                        const modal = document.getElementById(\"preview-modal\");
                        if (e.target === modal) closePreview();
                    });

                    function editMsg(id) {
                          const container = document.getElementById(\"msg-text-\" + id);
                          if (container.querySelector('textarea')) return;

                          const rawContent = container.getAttribute(\"data-raw\");
                          const lang = localStorage.getItem(\"lang\") || \"en\";
                          const t = i18n[lang];

                          container.innerHTML =
                              \"<textarea id=\\\"edit-area-\" + id + \"\\\" class=\\\"edit-area\\\"></textarea>\" +
                              \"<div style=\\\"display:flex; gap:10px;\\\">\" +
                                  \"<button class=\\\"btn-submit\\\" style=\\\"padding:5px 15px; font-size:0.8rem;\\\" onclick=\\\"saveEdit(\" + id + \")\\\">\" + t.save + \"</button>\" +
                                  \"<button class=\\\"ctrl-btn\\\" style=\\\"padding:5px 15px; font-size:0.8rem; background:rgba(0,0,0,0.1);\\\" onclick=\\\"location.reload()\\\">\" + t.cancel + \"</button>\" +
                              \"</div>\";

                          const area = document.getElementById(\"edit-area-\" + id);
                          area.value = rawContent;

                          area.style.height = area.scrollHeight + \"px\";
                          area.addEventListener(\"input\", function() {
                              this.style.height = \"auto\";
                              this.style.height = this.scrollHeight + \"px\";
                          });

                          // 自动聚焦并光标移至末尾
                          area.focus();
                          area.setSelectionRange(area.value.length, area.value.length);
                     }

                    async function saveEdit(id) {
                        const newText = document.getElementById(\"edit-area-\" + id).value;
                        const formData = new URLSearchParams();
                        formData.append('message', newText);
                        try {
                            const res = await fetch(\"/edit/\" + id, { method: 'POST', body: formData });
                            if (res.ok) location.reload();
                            else alert(\"Edit failed\");
                        } catch (err) { console.error(err); }
                    }

                    document.addEventListener(\"submit\", async (e) => {
                        const form = e.target;
                        const action = e.submitter ? e.submitter.getAttribute(\"formaction\") || form.getAttribute(\"action\") : form.getAttribute(\"action\");

                        if (action === \"/login\" || action === \"/register\") {
                            e.preventDefault();
                            const lang = localStorage.getItem(\"lang\") || \"en\";
                            const t = i18n[lang];
                            const formData = new URLSearchParams(new FormData(form));

                            try {
                                const res = await fetch(action, { method: \"POST\", body: formData });
                                if (action === \"/login\") {
                                    if (res.ok) {
                                        showToast(t.tipSuccess);
                                        setTimeout(() => { window.location.href = \"/\"; }, 1500);
                                    } else {
                                        showToast(t.tipWrong);
                                    }
                                } else {
                                    if (res.ok) showToast(t.tipReg);
                                    else if (res.status === 409) showToast(t.tipConflict);
                                }
                            } catch (err) { console.error(err); }
                        }
                    });

                    function toggleLang() {
                        const current = localStorage.getItem(\"lang\") || \"en\";
                        localStorage.setItem(\"lang\", current === \"en\" ? \"zh\" : \"en\");
                        updateUI();
                    }

                    function toggleDarkMode() {
                        const isDark = document.body.classList.toggle(\"dark-mode\");
                        localStorage.setItem(\"theme\", isDark ? \"dark\" : \"light\");
                    }

                    updateUI();

                    const ta = document.getElementById(\"grow-text\");
                    if(ta) ta.addEventListener(\"input\", function() { this.style.height=\"auto\"; this.style.height=this.scrollHeight+\"px\"; });

                    const fileInput = document.getElementById(\"file-input\");
                    const fileList = document.getElementById(\"file-list\");
                    if(fileInput) fileInput.addEventListener(\"change\", function() {
                        fileList.innerHTML = \"\";
                        Array.from(this.files).forEach(file => {
                            const div = document.createElement(\"div\");
                            div.className = \"file-item\";
                            div.textContent = file.name;
                            fileList.appendChild(div);
                        });
                    });
                ")) }
            }
        }
    };
    HttpResponse::Ok().content_type("text/html").body(markup.into_string())
}

// --- 消息操作处理 ---
///日志：
///     04.26.2025构建函数
///     04.30.2026重构函数
///     04.30.2026扩充文件支持范围
///     05.03.2026优化用户名处理逻辑
///     05.04.2025修复存储型XSS漏洞
#[post("/post")]
async fn post_message(mut payload: Multipart, db: web::Data<SqlitePool>, session: Session) -> impl Responder {
    let user = match session.get::<String>("user").ok().flatten() {
        Some(u) => u,
        None => return HttpResponse::SeeOther().append_header(("Location", "/")).finish(),
    };
    let mut message = String::new();
    let mut images = Vec::new();
    let mut others = Vec::new();
    while let Ok(Some(mut field)) = payload.try_next().await {
        let disp = field.content_disposition();
        let field_name = disp.get_name().unwrap_or("").to_string();
        let filename = disp.get_filename().map(|s| s.to_string());
        if field_name == "user_msg" {
            while let Ok(Some(chunk)) = field.try_next().await {
                message.push_str(std::str::from_utf8(&chunk).unwrap_or(""));
            }
        } else if field_name == "media" {
            if let Some(name) = filename {
                if !name.is_empty() {
                    let ext = Path::new(&name).extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                    let fname = format!("{}.{}", Uuid::new_v4(), sanitize(&ext));
                    let _ = fs::create_dir_all("uploads");
                    let upload_path = format!("uploads/{}", fname);
                    if let Ok(mut f) = fs::File::create(&upload_path) {
                        while let Ok(Some(chunk)) = field.try_next().await { let _ = f.write_all(&chunk); }
                        if ["jpg","jpeg","png","gif","webp"].contains(&ext.as_str()) { images.push(fname); } else { others.push(fname); }
                    }
                }
            }
        }
    }

    if !message.trim().is_empty() || !images.is_empty() || !others.is_empty() {
        // XSS 防御：在存储前也进行一次清洗
        let safe_html = markdown_to_html(&message);
        let img_str = if images.is_empty() { None } else { Some(images.join(",")) };
        let other_str = if others.is_empty() { None } else { Some(others.join(",")) };
        let _ = sqlx::query("INSERT INTO messages (name, message, raw_message, image_path, video_path) VALUES (?, ?, ?, ?, ?)")
            .bind(user).bind(safe_html).bind(message).bind(img_str).bind(other_str).execute(db.get_ref()).await;
    }
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

// --- 消息编辑处理 ---
///日志：
///     05.07.2026构建函数支持Markdown源码更新
#[post("/edit/{id}")]
async fn edit_message(
    db: web::Data<SqlitePool>,
    id: web::Path<i64>,
    //sessionKey
    session: Session,
    //拦截Edit的POST数据，反序列化后注入from
    form: web::Form<EditForm>
) -> impl Responder {
    if let Some(user) = session.get::<String>("user").ok().flatten() {
        let safe_html = markdown_to_html(&form.message);
        let result = sqlx::query("UPDATE messages SET message = ?, raw_message = ? WHERE id = ? AND name = ?")
            .bind(safe_html)
            .bind(&form.message)
            .bind(*id)
            .bind(user)
            .execute(db.get_ref())
            .await;
        match result {
            Ok(_) => HttpResponse::Ok().body("success"),
            Err(_) => HttpResponse::InternalServerError().body("db_error"),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}
// --- 消息删除 ---
///日志：
///     04.26.2025构建函数
///     04.30.2026重构函数
///     05.04.2026修复IDOR漏洞
#[post("/delete/{id}")]
async fn delete_message(db: web::Data<SqlitePool>, id: web::Path<i64>, session: Session) -> impl Responder {
    //删除时校验用户名
    if let Some(user) = session.get::<String>("user").ok().flatten() {
        // 修复水平越权：SQL 语句中必须带上 name 校验
        let _ = sqlx::query("DELETE FROM messages WHERE id = ? AND name = ?").bind(*id).bind(user).execute(db.get_ref()).await;
    }
    //重定向到index
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

// --- 启动入口 ---
///日志：
///     04.26.2025构建函数
///     04.30.2026重构函数
///     04.30.2026维护数据库链接
///     05.03.2026增加登录和注册逻辑,新增自动建表字段
///     05.03.2026修复移动端网页跳转问题
///     05.07.2026动态升级表结构增加raw_message字段
///     05.08.2026增加全局配置appdata大小限制
#[actix_web::main]
async fn main() -> io::Result<()> {
    // 基础环境准备
    // 启动前调用 Python 生成/更新证书
    if let Err(e) = run_python_setup() {
        eprintln!("警告：自动生成证书失败: {}。尝试使用现有证书...", e);
    }
    //创建上传目录连接
    let _ = fs::create_dir_all("uploads");
    //创建数据库URL
    let db_url = format!("sqlite://{}", std::env::current_dir()?.join("guestbook.db").display());
    //与数据库链接
    let db = SqlitePool::connect(&db_url).await.expect("数据库启动失败");

    // 自动建表
    sqlx::query("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)").execute(&db).await.ok();
    sqlx::query("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, image_path TEXT, video_path TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&db).await.ok();
    // 自动升级表结构：增加 raw_message 字段（如果不存在）
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN raw_message TEXT").execute(&db).await;

    // Session 密钥生成（生产环境应从配置文件读取固定密钥）
    let key = Key::generate();
    //提示运行地址
    println!("Server ready at https://localhost:6790")
    //运行HTTP服务
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))                           //预拷贝数据库链接
            .app_data(web::FormConfig::default().limit(4 * 1024 * 1024))    //限制appdata数据块大小，保证编辑长文本时正常保存
            // Session 配置
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                    .cookie_secure(true)                // 仅通过 HTTPS 传输
                    .cookie_same_site(SameSite::Lax)    // 缓解 CSRF 攻击
                    .cookie_http_only(true)             // 禁止客户端 JS 读取 Session Cookie，防御 XSS 劫持
                    .build()
            )
            // 路由注册
            .service(index)             //根目录
            .service(login_handler)     //登录管理
            .service(register_handler)  //注册管理
            .service(logout_handler)    //登出管理
            .service(post_message)      //消息上传
            .service(edit_message)      //消息编辑
            .service(delete_message)    //消息删除
            // 静态资源与上传目录托管
            .service(Files::new("/uploads", "uploads")) //上传目录
            .service(Files::new("/static", "static"))   //静态目录
    }).bind_rustls_021("0.0.0.0:6790", load_rustls_config())?   //绑定本地IPV4端口
        .bind_rustls_021("[::]:6790", load_rustls_config())?    //绑定本地IPV6端口
        .run()
        .await
}