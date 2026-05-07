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

// --- 数据结构 ---

/// 存储在数据库中的留言信息结构体
struct StoredMessage {
    //日志ID
    id: i64,
    //用户名
    name: String,
    //文本内容
    message: String,
    //图片UUID
    image_path: Option<String>,
    //视频&其他媒体UUID
    video_path: Option<String>,
    //时间戳
    created_at: String,
}

/// 登录与注册表单的接收模型
#[derive(serde::Deserialize)]
struct AuthForm {
    username: String,
    password: String,
}

// --- Markdown 转 HTML ---
///日志：
///     04.26.2026重构函数
///     05.04.2025修复XSS漏洞
// 修复 XSS：Markdown 转 HTML 后必须经过 ammonia 清洗
fn markdown_to_html(input: &str) -> String {
    let mut html_output = String::new();
    let parser = Parser::new_ext(input, Options::all());
    push_html(&mut html_output, parser);
    // 过滤掉所有 script, onerror, style 等危险标签和属性
    clean(&html_output)
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

#[get("/logout")]
async fn logout_handler(session: Session) -> impl Responder {
    session.purge();
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

// --- 主页面渲染  ---
///日志：
///     04.26.2026重构函数
///     04.30.2026重构UI样式
///     05.03.2026增加登录UI、增加I18n双语逻辑
#[get("/")]
async fn index(db: web::Data<SqlitePool>, session: Session) -> impl Responder {
    // 获取当前登录用户名
    let current_user = session.get::<String>("user").unwrap_or(None);
    // 从数据库查询所有留言
    let messages = sqlx::query("SELECT id, name, message, image_path, video_path, created_at FROM messages ORDER BY id DESC")
        .map(|row: SqliteRow| {
            let time_str: String = row.try_get("created_at").unwrap_or_else(|_| "刚刚".to_string());
            StoredMessage {
                id: row.get("id"),
                name: row.get("name"),
                message: row.get("message"),
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
                style { (PreEscaped(r#"
                    :root { --bg-blur: rgba(255, 255, 255, 0.25); --text-color: #333; --overlay-opacity: 0; }
                    .dark-mode { --bg-blur: rgba(0, 0, 0, 0.4); --text-color: #eee; --overlay-opacity: 0.6; }
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
                    .del-btn { float: right; color: #ff4757; border: none; background: none; cursor: pointer; opacity: 0.6; }

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
                                    form method="post" action=(format!("/delete/{}", msg.id)) { button type="submit" class="del-btn i18n-del" { "delete" } }
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
                                                    a class="file-link" href=(format!("/uploads/{}", path)) target="_blank" {
                                                        span class="i18n-view" { "📄 View File: " } (path)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                // XSS 修复点：markdown_to_html 内部现在会调用 ammonia::clean
                                // 渲染经过 Markdown 处理和防 XSS 清洗后的内容
                                div style="line-height:1.6; margin-top:10px;" { (PreEscaped(markdown_to_html(&msg.message))) }
                                span class="time" { (msg.created_at) }
                            }
                        }
                    }
                }

                div id="toast" {}

                // 客户端脚本：处理 i18n、主题切换、表单异步提交及动态 UI 效果
                script { (PreEscaped(r#"
                    const i18n = {
                        en: {
                            title: "MESSAGE BOARD", mode: "🌓 Mode", lang: "🌐 Lang",
                            loginUser: "Username", loginPass: "Password",
                            signin: "Sign In", signup: "Sign Up", logout: "🚪 Logout",
                            textPh: "Write some...", submit: "Submit", list: "Message list：",
                            del: "delete", empty: "No messages yet. Be the first!", view: "📄 View File: ",
                            tipSuccess: "✅ Login successful!", tipNoUser: "❌ Incorrect username or password.", tipWrong: "❌ Incorrect username or password.", tipReg: "📝 Registration successful! Now please Sign In.", tipConflict: "⚠️ Username already exists."
                        },
                        zh: {
                            title: "留言板", mode: "🌓 模式", lang: "🌐 语言",
                            loginUser: "用户名", loginPass: "密码",
                            signin: "登录", signup: "注册", logout: "🚪 退出",
                            textPh: "说点什么...", submit: "发布留言", list: "历史留言：",
                            del: "删除", edit: "编辑", save: "保存", cancel: "取消",
                            empty: "暂无留言，快来抢沙发！", view: "📄 查看文件: ",
                            tipSuccess: "✅ 登录成功！", tipNoUser: "❌ 用户名或密码错误", tipWrong: "❌ 用户名或密码错误", tipReg: "📝 注册成功！现在请登录。", tipConflict: "⚠️ 该用户名已被注册"
                        }
                    };

                    function showToast(msg) {
                        const t = document.getElementById("toast");
                        t.textContent = msg;
                        t.classList.remove("show");
                        void t.offsetWidth;
                        t.classList.add("show");
                        setTimeout(() => t.classList.remove("show"), 10000);
                    }

                    function updateUI() {
                        const lang = localStorage.getItem("lang") || "en";
                        const t = i18n[lang];
                        document.getElementById("page-title").textContent = t.title;
                        document.getElementById("main-title").textContent = t.title;
                        document.getElementById("theme-toggle").textContent = t.mode;
                        document.getElementById("lang-toggle").textContent = t.lang;

                        const lUser = document.getElementById("login-user"); if(lUser) lUser.placeholder = t.loginUser;
                        const lPass = document.getElementById("login-pass"); if(lPass) lPass.placeholder = t.loginPass;
                        const siBtn = document.getElementById("signin-btn"); if(siBtn) siBtn.textContent = t.signin;
                        const suBtn = document.getElementById("signup-btn"); if(suBtn) suBtn.textContent = t.signup;

                        const logout = document.getElementById("logout-btn"); if(logout) logout.textContent = t.logout;
                        const msgTa = document.getElementById("grow-text"); if(msgTa) msgTa.placeholder = t.textPh;
                        const subBtn = document.getElementById("btn-submit"); if(subBtn) subBtn.textContent = t.submit;
                        const listH = document.getElementById("list-header"); if(listH) listH.textContent = t.list;
                        const emptyH = document.getElementById("empty-hint"); if(emptyH) emptyH.textContent = t.empty;

                        document.querySelectorAll(".i18n-del").forEach(el => el.textContent = t.del);
                        document.querySelectorAll(".i18n-edit").forEach(el => el.textContent = t.edit);
                        document.querySelectorAll(".i18n-view").forEach(el => el.textContent = t.view);
                    }

                    // 编辑功能处理
                    function editMsg(id) {
                        const container = document.getElementById(`msg-text-${id}`);
                        if (container.querySelector('textarea')) return;
                        const rawContent = container.getAttribute("data-raw");
                        const lang = localStorage.getItem("lang") || "en";
                        const t = i18n[lang];
                        container.innerHTML = `
                            <textarea id="edit-area-${id}" class="input-box" style="width:100%; min-height:100px; border:1px solid rgba(110,142,251,0.3); border-radius:12px; padding:10px;">${rawContent}</textarea>
                            <div style="display:flex; gap:10px; margin-top:10px;">
                                <button class="btn-submit" style="padding:5px 15px; font-size:0.8rem;" onclick="saveEdit(${id})">${t.save}</button>
                                <button class="ctrl-btn" style="padding:5px 15px; font-size:0.8rem; background:rgba(0,0,0,0.1);" onclick="location.reload()">${t.cancel}</button>
                            </div>
                        `;
                    }

                    async function saveEdit(id) {
                        const newText = document.getElementById(`edit-area-${id}`).value;
                        const formData = new URLSearchParams();
                        formData.append('message', newText);
                        try {
                            const res = await fetch(`/edit/${id}`, { method: 'POST', body: formData });
                            if (res.ok) location.reload();
                            else alert("Edit failed");
                        } catch (err) { console.error(err); }
                    }

                    // 接管登录注册表单提交，实现无刷新反馈
                    document.addEventListener("submit", async (e) => {
                        const form = e.target;
                        const action = e.submitter ? e.submitter.getAttribute("formaction") || form.getAttribute("action") : form.getAttribute("action");

                        if (action === "/login" || action === "/register") {
                            e.preventDefault();
                            const lang = localStorage.getItem("lang") || "en";
                            const t = i18n[lang];
                            const formData = new URLSearchParams(new FormData(form));

                            try {
                                const res = await fetch(action, { method: "POST", body: formData });
                                if (action === "/login") {
                                    if (res.ok) {
                                        showToast(t.tipSuccess);
                                        setTimeout(() => { window.location.href = "/"; }, 1500);
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
                        const current = localStorage.getItem("lang") || "en";
                        localStorage.setItem("lang", current === "en" ? "zh" : "en");
                        updateUI();
                    }

                    function toggleDarkMode() {
                        const isDark = document.body.classList.toggle("dark-mode");
                        localStorage.setItem("theme", isDark ? "dark" : "light");
                    }

                    updateUI();

                    // 输入框自动高度调整
                    const ta = document.getElementById("grow-text");
                    if(ta) ta.addEventListener("input", function() { this.style.height="auto"; this.style.height=this.scrollHeight+"px"; });

                    // 文件预览列表刷新
                    const fileInput = document.getElementById("file-input");
                    const fileList = document.getElementById("file-list");
                    if(fileInput) fileInput.addEventListener("change", function() {
                        fileList.innerHTML = "";
                        Array.from(this.files).forEach(file => {
                            const div = document.createElement("div");
                            div.className = "file-item";
                            div.textContent = file.name;
                            fileList.appendChild(div);
                        });
                    });
                "#)) }
            }
        }
    };
    HttpResponse::Ok().content_type("text/html").body(markup.into_string())
}

// --- 消息操作处理 ---
///日志：
///     04.26.2026重构函数
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
async fn edit_message(db: web::Data<SqlitePool>, id: web::Path<i64>, session: Session, form: web::Form<EditForm>) -> impl Responder {
    if let Some(user) = session.get::<String>("user").ok().flatten() {
        let safe_html = markdown_to_html(&form.message);
        let _ = sqlx::query("UPDATE messages SET message = ?, raw_message = ? WHERE id = ? AND name = ?")
            .bind(safe_html).bind(&form.message).bind(*id).bind(user).execute(db.get_ref()).await;
        return HttpResponse::Ok().body("success");
    }
    HttpResponse::Unauthorized().finish()
}

// --- 消息删除 ---
///日志：
///     04.26.2026重构函数
///     05.04.2026修复IDOR漏洞
#[post("/delete/{id}")]
async fn delete_message(db: web::Data<SqlitePool>, id: web::Path<i64>, session: Session) -> impl Responder {
    if let Some(user) = session.get::<String>("user").ok().flatten() {
        // 修复水平越权：SQL 语句中必须带上 name 校验
        let _ = sqlx::query("DELETE FROM messages WHERE id = ? AND name = ?").bind(*id).bind(user).execute(db.get_ref()).await;
    }
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

// --- 启动入口 ---
///日志：
///     04.26.2026重构函数
///     04.30.2026维护数据库链接
///     05.03.2026增加登录和注册逻辑,新增自动建表字段
///     05.03.2026修复移动端网页跳转问题
///     05.07.2026动态升级表结构增加raw_message字段
#[actix_web::main]
async fn main() -> io::Result<()> {
    // 基础环境准备
    let _ = fs::create_dir_all("uploads");
    let db_url = format!("sqlite://{}", std::env::current_dir()?.join("guestbook.db").display());
    let db = SqlitePool::connect(&db_url).await.expect("数据库启动失败");

    // 自动建表
    sqlx::query("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)").execute(&db).await.ok();
    sqlx::query("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, image_path TEXT, video_path TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&db).await.ok();

    // 自动升级表结构：增加 raw_message 字段（如果不存在）
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN raw_message TEXT").execute(&db).await;

    // Session 密钥生成（生产环境应从配置文件读取固定密钥）
    let key = Key::generate();
    println!("Server ready at http://localhost:6790");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            // Session 配置
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                    .cookie_secure(true)// 仅通过 HTTPS 传输
                    .cookie_same_site(SameSite::Lax)// 缓解 CSRF 攻击
                    .cookie_http_only(true) // 禁止客户端 JS 读取 Session Cookie，防御 XSS 劫持
                    .build()
            )
            // 路由注册
            .service(index)
            .service(login_handler)
            .service(register_handler)
            .service(logout_handler)
            .service(post_message)
            .service(edit_message) // 注册编辑路由
            .service(delete_message)
            // 静态资源与上传目录托管
            .service(Files::new("/uploads", "uploads"))
            .service(Files::new("/static", "static"))
    }).bind("0.0.0.0:6790")?
        .bind("[::]:6790")?
        .run()
        .await
}