use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use actix_multipart::Multipart;
use actix_session::Session;
use actix_web::{get, post, web, HttpResponse, Responder};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use futures_util::{StreamExt, TryStreamExt};
use maud::{html, PreEscaped, DOCTYPE};
use rand::Rng;
use sanitize_filename::sanitize;
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use tokio::sync::broadcast;
use uuid::Uuid;
use crate::routing::process_func;
use crate::routing::process_func::markdown_to_html;
use crate::routing::structure::{ClientDeviceReportForm, EditMessageForm, StoredMessage, UnifiedAuthForm};

// --- 登录处理 ---
///日志：
///     05.03.2026构建函数
///     05.04.2026限制登录频率
///     05。19.2026增加后台反馈
#[post("/login")]
pub(crate) async fn login_handler(
    //数据库链接
    db: web::Data<SqlitePool>,
    //SessionKey
    session: Session,
    //前端钩子JSON反馈
    payload: web::Json<UnifiedAuthForm>,
    //日志异步广播
    tx: web::Data<broadcast::Sender<String>>
) -> impl Responder {
    //解析JSON
    let form = payload.into_inner();
    //随机休眠，模糊登录处理
    let delay = rand::thread_rng().gen_range(100..500);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    //读取user对应哈希化密钥
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(&form.username.trim().to_string())
        .fetch_optional(db.get_ref())
        .await;
    //登录失败反馈
    let auth_failed = {
        process_func::log_action(
            db.get_ref(),
            Some(&form.username),
            "USER_LOGIN_FAILED",
            "尝试使用错误凭据登录被拦截",
            form.client_ip.as_deref(),
            form.os.as_deref(),
            form.browser.as_deref(),
            Some(tx.get_ref())
        ).await;
        HttpResponse::Unauthorized().body("wrong_credentials")
    };
    
    let auth_succeed={
        process_func::log_action(
            db.get_ref(),
            Some(&form.username),
            "USER_LOGIN_SUCCESS",
            "会话鉴权成功并建立连接",
            form.client_ip.as_deref(),
            form.os.as_deref(),
            form.browser.as_deref(),
            Some(tx.get_ref())
        ).await;
        return HttpResponse::Ok().body("success");
    };
    match row {
        Ok(Some(row)) => {
            let hash: String = row.get("password_hash");
            if let Ok(parsed_hash) = PasswordHash::new(&hash) {
                if Argon2::default().verify_password(form.password.as_bytes(), &parsed_hash).is_ok() {
                    let _ = session.insert("user", &form.username);
                    session.renew();
                   auth_succeed
                }
            }
            auth_failed
        }
        _ => auth_failed,
    }
}

// --- 注册处理 ---
///日志：
///     05.03.2026构建函数
///     05.04.2026模糊化登录错误反馈
#[post("/register")]
pub(crate) async fn register_handler(
    db: web::Data<SqlitePool>,
    payload: web::Json<UnifiedAuthForm>, 
    tx: web::Data<broadcast::Sender<String>>
) -> impl Responder {
    let form = payload.into_inner();

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
        Ok(_) => {
            process_func::log_action(
                db.get_ref(),
                Some(&form.username),
                "USER_REGISTER",
                "新账户注册成功",
                form.client_ip.as_deref(),
                form.os.as_deref(),
                form.browser.as_deref(),
                Some(tx.get_ref())
            ).await;
            HttpResponse::Ok().body("registered")
        }
        Err(_) => {
            process_func::log_action(
                db.get_ref(),
                Some(&form.username),
                "REGISTER_CONFLICT",
                "尝试注册已存在的用户名",
                form.client_ip.as_deref(),
                form.os.as_deref(),
                form.browser.as_deref(),
                Some(tx.get_ref())
            ).await;
            HttpResponse::Conflict().body("user_exists")
        }
    }
}

// --- 登出处理 ---
///日志：
///     05.03.2026构建函数
#[get("/logout")]
pub(crate) async fn logout_handler(
    db: web::Data<SqlitePool>,
    session: Session,
    query: web::Query<crate::routing::structure::LogoutQuery>, // 接收 URL Query 参数
    tx: web::Data<broadcast::Sender<String>>
) -> impl Responder {
    let current_user = session.get::<String>("user").ok().flatten();

    if let Some(ref user) = current_user {
        process_func::log_action(
            db.get_ref(),
            Some(user),
            "USER_LOGOUT",
            "用户主动销毁 Session 会话并退出系统",
            query.client_ip.as_deref(),
            query.os.as_deref(),
            query.browser.as_deref(),
            Some(tx.get_ref())
        ).await;
    }

    session.purge(); // 销毁 Session

    // ✅ 关键：传统 GET 页面跳转，成功后 SeeOther 重定向回首页
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
///     05.17.2026增加前端预览文件逻辑
///     05.17.2026以/格式化重构JS部分
#[get("/")]
pub(crate) async fn index(
    //数据库连接
    db: web::Data<SqlitePool>,
    //sessionKey
    session: Session
) -> impl Responder {
    // 获取当前登录用户名
    let current_user = session.get::<String>("user").ok().flatten();
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
                           div id="auth-box" { // 改为普通的 div 容器，彻底防止原生表单刷新页面
                               input type="text" id="login-user" class="input-box" placeholder="Username" required;
                               input type="password" id="login-pass" class="input-box" placeholder="Password" required;
                            div style="display:flex; gap:10px;" {
                            // 绑定到同一个统一捕获函数，通过参数区分“登录”还是“注册”
                            button type="button" id="signin-btn" class="btn-submit" style="flex:1" onclick="handleAuth('login')" { "Sign In" }
                            button type="button" id="signup-btn" class="btn-submit" style="flex:1; background:rgba(255,255,255,0.2)" onclick="handleAuth('register')" { "Sign Up" }
                            }
                           }
                        }
                        // 已登录状态：显示发布留言表单
                        Some(ref user) => {
                            form method="post" action="/post" enctype="multipart/form-data" {
                                input type="text" name="user_name" class="input-box" value=(user) readonly;
                                textarea name="user_msg" id="grow-text" class="input-box" placeholder="Write some..." required {}
                                input type="hidden" name="client_ip" id="post-ip" value="0.0.0.0";
                                input type="hidden" name="os" id="post-os" value="Unknown OS";
                                input type="hidden" name="browser" id="post-browser" value="Unknown Browser";
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
                                        button type="button" class="del-btn i18n-del" onclick=(format!("deleteMessage({})", msg.id)) { "delete" }
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

                    const style = document.createElement(\"style\");
                    style.innerHTML = `
                        .custom-modal-overlay {
                            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                            background: rgba(0, 0, 0, 0.4); backdrop-filter: blur(8px);
                            display: flex; align-items: center; justify-content: center; z-index: 9999;
                            opacity: 0; transition: opacity 0.3s ease;
                        }
                        .custom-modal-box {
                            background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(16px);
                            border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 16px;
                            padding: 24px; width: 90%; max-width: 400px; text-align: center;
                            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
                            transform: scale(0.9); transition: transform 0.3s ease; color: #fff;
                        }
                        .custom-modal-box h3 { margin-top: 0; font-size: 1.2rem; color: #ff4d4d; }
                        .custom-modal-box p { color: rgba(255,255,255,0.8); font-size: 0.95rem; margin: 15px 0 25px 0; }
                        .custom-modal-btns { display: flex; gap: 12px; justify-content: center; }
                       .custom-modal-btn {
                            padding: 8px 20px; border: none; border-radius: 8px; cursor: pointer;
                            font-weight: bold; transition: background 0.2s;
                        }
                        .custom-modal-cancel { background: rgba(255,255,255,0.2); color: #fff; }
                        .custom-modal-cancel:hover { background: rgba(255,255,255,0.3); }
                        .custom-modal-confirm { background: #ff4d4d; color: #fff; }
                        .custom-modal-confirm:hover { background: #ff3333; }
                    `;
                    document.head.appendChild(style);


                    function fancyConfirm(message, onConfirm) {
                        const overlay = document.createElement(\"div\");
                        overlay.className = \"custom-modal-overlay\";


                        overlay.innerHTML = `
                            <div class=\"custom-modal-box\">
                                <h3>⚠️ Confirm Action</h3>
                                <p>${message}</p>
                                <div class=\"custom-modal-btns\">
                                    <button class=\"custom-modal-btn custom-modal-cancel\" id=\"modal-cancel\">Cancel</button>
                                    <button class=\"custom-modal-btn custom-modal-confirm\" id=\"modal-confirm\">Delete</button>
                                </div>
                            </div>
                        `;
                        document.body.appendChild(overlay);

                        // 动画入场
                        setTimeout(() => {
                            overlay.style.opacity = \"1\";
                            overlay.querySelector(\".custom-modal-box\").style.transform = \"scale(1)\";
                        }, 10);

                        const close = () => {
                            overlay.style.opacity = \"0\";
                            overlay.querySelector(\".custom-modal-box\").style.transform = \"scale(0.9)\";
                            setTimeout(() => overlay.remove(), 300);
                        };

                        overlay.querySelector(\"#modal-cancel\").onclick = close;
                        overlay.querySelector(\"#modal-confirm\").onclick = () => { close(); onConfirm(); };
                    }
                    const translations = {
                        en: {
                            confirmTitle: \"⚠️ Confirm Action\",
                            confirmContent: \"Are you sure you want to permanently delete this message? This action cannot be undone.\",
                            confirmCancel: \"Cancel\",
                            confirmDelete: \"Delete\"
                        },
                        zh: {
                            confirmTitle: \"⚠️ 确认操作\",
                            confirmContent: \"您确定要永久删除这条留言吗？此操作将无法撤销。\",
                            confirmCancel: \"取消\",
                            confirmDelete: \"删除\"
                        }
                    };
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

                    async function handleAuth(type) {
                        const username = document.getElementById(\"login-user\").value.trim();
                        const password = document.getElementById(\"login-pass\").value;

                        if (!username || !password) {
                            showToast(\"Please fill in username and password.\");
                            return;
                        }

                        // 1. 无感秒级捕捉操作系统与浏览器类型
                        let os = \"Unknown OS\";
                        let browser = \"Unknown Browser\";
                        const ua = navigator.userAgent.toLowerCase();
                        if (ua.indexOf(\"win\") !== -1) os = \"Windows\";
                        else if (ua.indexOf(\"mac\") !== -1) os = \"macOS\";
                        else if (ua.indexOf(\"linux\") !== -1) os = \"Linux\";

                        if (ua.indexOf(\"edg/\") !== -1) browser = \"Edge\";
                        else if (ua.indexOf(\"chrome\") !== -1 && ua.indexOf(\"chromium\") === -1) browser = \"Chrome\";
                        else if (ua.indexOf(\"firefox\") !== -1) browser = \"Firefox\";

                        // 2. 异步感知公网远程 IP
                        let clientIp = \"0.0.0.0\";
                        try {
                            const ipResponse = await fetch(\"https://api.ipify.org?format=json\");
                            const ipData = await ipResponse.json();
                            clientIp = ipData.ip;
                        } catch (e) {
                            clientIp = \"抓取失败\";
                        }

                        // 3. 构建完全满足后端 UnifiedAuthForm 的平铺式大 JSON 载荷
                        const compositePayload = {
                            username: username,
                            password: password,
                            client_ip: clientIp,
                            os: os,
                            browser: browser
                        };

                        // 4. 熔断式异步投递
                        try {
                            const response = await fetch(\"/\" + type, {
                                method: \"POST\",
                                headers: { \"Content-Type\": \"application/json\" },
                                body: JSON.stringify(compositePayload)
                            });

                            const result = await response.text();

                            if (result === \"success\") {
                                showToast(\"Success! Redirecting...\");
                                setTimeout(() => window.location.reload(), 800);
                            } else if (result === \"registered\") {
                                showToast(\"Account registered successfully! You can sign in now.\");
                            } else if (result === \"wrong_credentials\") {
                                showToast(\"Invalid username or password.\");
                            } else if (result === \"user_exists\") {
                                showToast(\"Username already exists.\");
                            } else {
                                showToast(result);
                            }
                        } catch (err) {
                            console.error(\"Authentication Error:\", err);
                            showToast(\"Network Error.\");
                        }
                    }

                    function handleLogout(e) {
                        e.preventDefault();
                        const ip = window.clientIp || \"0.0.0.0\";
                        const os = window.os || \"Unknown OS\";
                        const browser = window.browser || \"Unknown Browser\";

                        // 动态拼接 Query 参数发起 GET 跳转
                        window.location.href = \"/logout?client_ip=\" + encodeURIComponent(ip) + \"&os=\" + encodeURIComponent(os) + \"&browser=\" + encodeURIComponent(browser);
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
                        if (document.getElementById(\"post-ip\") && window.clientIp) {
                            document.getElementById(\"post-ip\").value = window.clientIp;
                            document.getElementById(\"post-os\").value = window.os;
                            document.getElementById(\"post-browser\").value = window.browser;
                        }
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

                    // 1. 彻底实现全字段 i18n 绑定的磨砂玻璃风格弹窗（完全移除 $ 符号，改用加号字符串拼接，彻底解决 Rust 编译报错）
                    function fancyConfirm(onConfirm) {
                        const overlay = document.createElement(\"div\");
                        overlay.className = \"custom-modal-overlay\";

                        // 🌍 获取当前系统选择的语言状态，默认降级为英文 'en'
                        const lang = window.currentLang || \"en\";
                        const t = translations[lang] || translations[\"en\"];

                        overlay.innerHTML =
                            \"<div class=\\\"custom-modal-box\\\">\" +
                                \"<h3>\" + t.confirmTitle + \"</h3>\" +
                                \"<p>\" + t.confirmContent + \"</p>\" +
                                \"<div class=\\\"custom-modal-btns\\\">\" +
                                    \"<button class=\\\"custom-modal-btn custom-modal-cancel\\\" id=\\\"modal-cancel\\\">\" + t.confirmCancel + \"</button>\" +
                                    \"<button class=\\\"custom-modal-btn custom-modal-confirm\\\" id=\\\"modal-confirm\\\">\" + t.confirmDelete + \"</button>\" +
                                \"</div>\" +
                            \"</div>\";

                        document.body.appendChild(overlay);

                        // 优雅缓动入场动画
                       setTimeout(() => {
                            overlay.style.opacity = \"1\";
                            overlay.querySelector(\".custom-modal-box\").style.transform = \"scale(1)\";
                        }, 10);

                        const close = () => {
                            overlay.style.opacity = \"0\";
                            overlay.querySelector(\".custom-modal-box\").style.transform = \"scale(0.9)\";
                            setTimeout(() => overlay.remove(), 300);
                        };

                        overlay.querySelector(\"#modal-cancel\").onclick = close;
                        overlay.querySelector(\"#modal-confirm\").onclick = () => { close(); onConfirm(); };
                    }

                    // 2. 对应的删除触发控制流
                    async function deleteMessage(id) {
                        const lang = window.currentLang || \"en\";

                        // 直接调用已经接入多语言字典的 fancyConfirm 弹窗组件
                        fancyConfirm(async () => {
                            const payload = {
                                client_ip: window.clientIp || \"0.0.0.0\",
                                os: window.os || \"Unknown OS\",
                                browser: window.browser || \"Unknown Browser\"
                            };

                            try {
                                const response = await fetch(\"/delete/\" + id, {
                                    method: \"POST\",
                                    headers: {
                                        \"Content-Type\": \"application/json\"
                                    },
                                    body: JSON.stringify(payload)
                                });

                                const result = await response.text();
                                if (result === \"success\") {
                                    // 成功删除的 Toast 提示同样实现双语切换
                                    showToast(lang === \"zh\" ? \"留言已成功删除！\" : \"Message deleted successfully!\");
                                    setTimeout(() => window.location.reload(), 600);
                                } else {
                                    showToast(lang === \"zh\" ? \"删除失败: \" + result : \"Delete failed: \" + result);
                                }
                            } catch (err) {
                                console.error(\"Delete error:\", err);
                                showToast(lang === \"zh\" ? \"网络错误，请稍后再试\" : \"Network error. Please try again.\");
                            }
                        });
                    }
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
                       // 1. 获取对应的 textarea 节点
                       const editArea = document.getElementById(\"edit-area-\" + id);
                       if (!editArea) {
                           showToast(\"Error: Edit area not found.\");
                           return;
                       }

                       const newText = editArea.value.trim();
                       if (!newText) {
                           showToast(\"Message cannot be empty.\");
                           return;
                       }

                       // 2. 严格对齐后端字段。这里主动使用字符串兜底，杜绝 JavaScript 传出 undefined 的可能
                       const payload = {
                           message: newText,
                           client_ip: String(window.clientIp || \"0.0.0.0\"),
                           os: String(window.os || \"Unknown OS\"),
                           browser: String(window.browser || \"Unknown Browser\")
                       };

                       try {
                           // 3. 发送纯净的 JSON 异步请求
                           const response = await fetch(\"/edit/\" + id, {
                               method: \"POST\",
                               headers: {
                                   \"Content-Type\": \"application/json\"
                               },
                               body: JSON.stringify(payload)
                           });

                           const result = await response.text();
                           if (result === \"success\") {
                               showToast(\"Message updated successfully!\");
                               setTimeout(() => window.location.reload(), 600); // 平滑刷新页面
                           } else {
                               showToast(\"Save failed: \" + result);
                          }
                       } catch (err) {
                           console.error(\"Edit error:\", err);
                           showToast(\"Network error.\");
                       }
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

                    document.addEventListener(\"DOMContentLoaded\", async function() {
                        // 1. 获取系统和浏览器
                        let os = \"Unknown OS\";
                        let browser = \"Unknown Browser\";
                        const ua = navigator.userAgent.toLowerCase();
                        if (ua.indexOf(\"win\") !== -1) os = \"Windows\";
                        else if (ua.indexOf(\"mac\") !== -1) os = \"macOS\";
                        else if (ua.indexOf(\"linux\") !== -1) os = \"Linux\";
                        if (ua.indexOf(\"edg/\") !== -1) browser = \"Edge\";
                        else if (ua.indexOf(\"chrome\") !== -1 && ua.indexOf(\"chromium\") === -1) browser = \"Chrome\";

                        // 2. 异步抓取 IP
                        let clientIp = \"0.0.0.0\";
                        try {
                            const ipResponse = await fetch(\"https://api.ipify.org?format=json\");
                            const ipData = await ipResponse.json();
                            clientIp = ipData.ip;
                        } catch(e) {}

                        // 3.注入给发布留言的隐藏表单
                        if (document.getElementById(\"post-ip\")) {
                            document.getElementById(\"post-ip\").value = clientIp;
                            document.getElementById(\"post-os\").value = os;
                            document.getElementById(\"post-browser\").value = browser;
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
pub(crate) async fn post_message(
    //MultipartFile
    mut payload: Multipart,
    //数据库连接
    db: web::Data<SqlitePool>,
    //sessionKey
    session: Session,
    tx: web::Data<broadcast::Sender<String>>
) -> impl Responder {
    //判别User
    let user = match session.get::<String>("user").ok().flatten() {
        Some(u) => u,
        None => return HttpResponse::Ok().body("faild"),
    };

    let mut client_ip_val: Option<String> = None;
    let mut os_val: Option<String> = None;
    let mut browser_val: Option<String> = None;

    //创建空容器
    let mut message = String::new();
    let mut images = Vec::new();
    let mut others = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await /*从payload中取出表单数据*/ {
        let disp = field.content_disposition();                         //获取field响应头
        let field_name = disp.get_name().unwrap_or("").to_string();     //获取上传类型
        let filename = disp.get_filename().map(|s| s.to_string());      //获取文件名
        //处理消息
        if field_name == "user_msg" {
            while let Ok(Some(chunk)) = field.try_next().await {
                message.push_str(std::str::from_utf8(&chunk).unwrap_or(""));
            }
        }
        //处理媒体
        else if field_name == "media" {
            if let Some(name) = filename {
                if !name.is_empty() {
                    //获取文件格
                    let ext = Path::new(&name).extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                    //获取文件名
                    let fname = format!("{}.{}", Uuid::new_v4(), sanitize(&ext));
                    //链接上传目录
                    let _ = fs::create_dir_all("uploads");
                    //指定文件上传地址
                    let upload_path = format!("uploads/{}", fname);
                    //确保上传地址已创建后写入
                    if let Ok(mut f) = fs::File::create(&upload_path) {
                        while let Ok(Some(chunk)) = field.try_next().await { let _ = f.write_all(&chunk); }
                        if ["jpg","jpeg","png","gif","webp"].contains(&ext.as_str()) { images.push(fname); } else { others.push(fname); }
                    }
                }
            }
        }
        // 在你的 while let Some(Ok(mut field)) = multipart.next().await 循环中解析：
        let name = field.name().to_string();
        match name.as_str() {
            "client_ip" => {
                let bytes = field.next().await.unwrap().unwrap();
                client_ip_val = Some(String::from_utf8_lossy(&bytes).into_owned());
            },
            "os" => {
                let bytes = field.next().await.unwrap().unwrap();
                os_val = Some(String::from_utf8_lossy(&bytes).into_owned());
            },
            "browser" => {
                let bytes = field.next().await.unwrap().unwrap();
                browser_val = Some(String::from_utf8_lossy(&bytes).into_owned());
            },
            // ... 其他原有的 user_msg 和媒体文件的处理逻辑 ...
            _ => {}
        }
    }

    //数据库写入
    if !message.trim().is_empty() || !images.is_empty() || !others.is_empty() {
        // 文本数据
        let safe_html = markdown_to_html(&message);
        //图片地址
        let img_str = if images.is_empty() { None } else { Some(images.join(",")) };
        //其他文件地址
        let other_str = if others.is_empty() { None } else { Some(others.join(",")) };
        //上传到数据库
        let _ = sqlx::query("INSERT INTO messages (name, message, raw_message, image_path, video_path) VALUES (?, ?, ?, ?, ?)")
            .bind(user)             //name
            .bind(safe_html)        //message
            .bind(message)          //raw_message
            .bind(img_str)          //image_path
            .bind(other_str)        //other_path
            .execute(db.get_ref()).await;
    }

    let user = session.get::<String>("user").ok().flatten().unwrap_or_else(|| "匿名游客".to_string());

    process_func::log_action(
        db.get_ref(),
        Some(&user),
        "MESSAGE_POST",
        "成功发布新留言（可能包含媒体文件附件）",
        client_ip_val.as_deref(),
        os_val.as_deref(),
        browser_val.as_deref(),
        Some(tx.get_ref())
    ).await;

    HttpResponse::Ok().body("success");
    //重定向到/
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

// --- 消息编辑处理 ---
///日志：
///     05.07.2026构建函数支持Markdown源码更新

#[post("/edit/{id}")]
pub(crate) async fn edit_message(
    db: web::Data<SqlitePool>,
    id: web::Path<i64>,
    session: Session,
    body: String, // 👈 放弃 web::Json，直接吃下原始字符串，确保 100% 进入函数体
    tx: web::Data<broadcast::Sender<String>>
) -> impl Responder {
    // 强制声明返回 text/plain 的内容类型，严防前端误解析
    let mut response = HttpResponse::Ok();
    response.insert_header(("content-type", "text/plain; charset=utf-8"));

    if let Some(user) = session.get::<String>("user").ok().flatten() {
        // 在内部手动、弹性地反序列化 JSON
        return if let Ok(form) = serde_json::from_str::<EditMessageForm>(&body) {
            let safe_html = markdown_to_html(&form.message);

            // 执行 SQL 变更
            let result = sqlx::query("UPDATE messages SET message = ?, raw_message = ? WHERE id = ? AND name = ?")
                .bind(safe_html)
                .bind(&form.message)
                .bind(*id)
                .bind(&user)
                .execute(db.get_ref())
                .await;

            if result.is_ok() {
                // 写入审计日志
                process_func::log_action(
                    db.get_ref(),
                    Some(&user),
                    "MESSAGE_EDIT",
                    &format!("成功修改留言内容，目标消息ID: {}", id),
                    form.client_ip.as_deref(),
                    form.os.as_deref(),
                    form.browser.as_deref(),
                    Some(tx.get_ref())
                ).await;

                // ✨ 明确无误地返回纯 success 字符串
                response.body("success")
            } else {
                response.body("database_error")
            }
        } else {
            response.body("json_parse_error_check_fields")
        }
    }
    response.body("unauthorized")
}
// --- 消息删除 ---
///日志：
///     04.26.2025构建函数
///     04.30.2026重构函数
///     05.04.2026修复IDOR漏洞

#[post("/delete/{id}")]
pub(crate) async fn delete_message(
    db: web::Data<SqlitePool>,
    id: web::Path<i64>,
    session: Session,
    body: String, // 👈 同样采用 String 弹性接收层
    tx: web::Data<broadcast::Sender<String>>
) -> impl Responder {
    let mut response = HttpResponse::Ok();
    response.insert_header(("content-type", "text/plain; charset=utf-8"));

    if let Some(user) = session.get::<String>("user").ok().flatten() {
        // 执行物理删除
        let result = sqlx::query("DELETE FROM messages WHERE id = ? AND name = ?")
            .bind(*id)
            .bind(&user)
            .execute(db.get_ref())
            .await;

        return if result.is_ok() {
            // 解析指纹载荷（哪怕解析失败，删除动作也已经完成了，提高了健壮性）
            let (ip, os, bws) = if let Ok(report) = serde_json::from_str::<ClientDeviceReportForm>(&body) {
                (Some(report.client_ip), Some(report.os), Some(report.browser))
            } else {
                (None, None, None)
            };

            process_func::log_action(
                db.get_ref(),
                Some(&user),
                "MESSAGE_DELETE",
                &format!("用户清除了其发布的留言，目标消息ID: {}", id),
                ip.as_deref(),
                os.as_deref(),
                bws.as_deref(),
                Some(tx.get_ref())
            ).await;

            response.body("success")
        } else {
            response.body("database_error")
        }
    }
    response.body("unauthorized")
}