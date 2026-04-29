use actix_web::{web, App, HttpServer, Responder, HttpResponse, get, post};
use actix_multipart::Multipart;
use actix_files::Files;
use maud::{html, DOCTYPE, PreEscaped};
use pulldown_cmark::{Parser, Options, html::push_html};
use sqlx::{SqlitePool, sqlite::SqliteRow, Row};
use futures_util::TryStreamExt as _;
use uuid::Uuid;
use sanitize_filename::sanitize;
use std::{fs, io::Write, path::Path, io};

struct StoredMessage {
    id: i64,
    name: String,
    message: String,
    image_path: Option<String>,
    video_path: Option<String>,
    created_at: String,
}

fn markdown_to_html(input: &str) -> String {
    let mut html_output = String::new();
    let parser = Parser::new_ext(input, Options::all());
    push_html(&mut html_output, parser);
    html_output
}

#[get("/")]
async fn index(db: web::Data<SqlitePool>) -> impl Responder {
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
        .fetch_all(db.get_ref())
        .await
        .unwrap_or_default();

    let markup = html! {
        (DOCTYPE)
        html lang="zh-CN" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title id="page-title" { "MESSAGE BOARD" }

                link rel="icon" type="image/x-icon" href="/static/icon-64x64.ico";
                link rel="manifest" href="/static/manifest.json";
                meta name="theme-color" content="#121212";

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
                        color: white; padding: 10px 25px; border-radius: 20px; cursor: pointer; font-weight: 600;
                    }

                    /* 顶部按钮栏 */
                    .top-bar { display: flex; gap: 10px; margin-bottom: 20px; z-index: 1; }
                    .ctrl-btn { background: rgba(255,255,255,0.2); border: none; color: white; padding: 8px 15px; border-radius: 20px; cursor: pointer; transition: 0.3s; font-size: 0.9rem; }
                    .ctrl-btn:hover { background: rgba(255,255,255,0.3); }

                    #file-list {
                        margin-left: 15px; flex-grow: 1; font-size: 0.85rem; font-weight: 200;
                        color: inherit; opacity: 0.9; line-height: 1.4;
                        display: flex; flex-direction: column; gap: 4px;
                    }
                    .file-item { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 180px; }
                    .file-link {
                        display: block; background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.2);
                        padding: 12px 15px; border-radius: 12px; margin: 10px 0; text-decoration: none; color: inherit; font-size: 0.85rem;
                        transition: 0.2s; border-left: 4px solid #6e8efb;
                    }
                    .media { width: 100%; border-radius: 18px; margin: 12px 0; display: block; }
                    .time { font-size: 0.7rem; opacity: 0.4; text-align: right; display: block; margin-top: 15px; }
                    .del-btn { float: right; color: #ff4757; border: none; background: none; cursor: pointer; opacity: 0.6; }
                "#)) }
            }
            body {
                script { (PreEscaped(r#"if(localStorage.getItem("theme")==="dark")document.body.classList.add("dark-mode");"#)) }

                h1 id="main-title" { "MESSAGE BOARD" }

                div class="top-bar" {
                    button id="theme-toggle" class="ctrl-btn" onclick="toggleDarkMode()" { "🌓 Mode" }
                    button id="lang-toggle" class="ctrl-btn" onclick="toggleLang()" { "🌐 Lang" }
                }

                div class="glass" {
                    form method="post" action="/post" enctype="multipart/form-data" {
                        input type="text" name="user_name" id="input-name" class="input-box" placeholder="Name" required;
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

                h2 id="list-header" style="color:white; font-weight:200; margin-bottom:15px; width:100%; max-width:500px;" { "Message list：" }

                @if messages.is_empty() {
                    div class="glass" id="empty-hint" style="text-align:center; color:white; font-style:italic;" { "No messages yet. Be the first!" }
                } @else {
                    @for msg in &messages {
                        div class="glass" {
                            form method="post" action=(format!("/delete/{}", msg.id)) { button type="submit" class="del-btn i18n-del" { "delete" } }
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
                            div style="line-height:1.6; margin-top:10px;" { (PreEscaped(markdown_to_html(&msg.message))) }
                            span class="time" { (msg.created_at) }
                        }
                    }
                }

                script { (PreEscaped(r#"
                    const i18n = {
                        en: {
                            title: "MESSAGE BOARD",
                            namePh: "Name",
                            textPh: "Write some...",
                            submit: "Submit",
                            list: "Message list：",
                            empty: "No messages yet. Be the first!",
                            del: "delete",
                            view: "📄 View File: "
                        },
                        zh: {
                            title: "留言板",
                            namePh: "昵称",
                            textPh: "说点什么...",
                            submit: "发布留言",
                            list: "历史留言：",
                            empty: "暂无留言，快来抢沙发！",
                            del: "删除",
                            view: "📄 查看文件: "
                        }
                    };

                    function updateUI() {
                        const lang = localStorage.getItem("lang") || "en";
                        const t = i18n[lang];

                        document.getElementById("main-title").textContent = t.title;
                        document.getElementById("page-title").textContent = t.title;
                        document.getElementById("input-name").placeholder = t.namePh;
                        document.getElementById("grow-text").placeholder = t.textPh;
                        document.getElementById("btn-submit").textContent = t.submit;
                        document.getElementById("list-header").textContent = t.list;

                        const emptyHint = document.getElementById("empty-hint");
                        if(emptyHint) emptyHint.textContent = t.empty;

                        document.querySelectorAll(".i18n-del").forEach(el => el.textContent = t.del);
                        document.querySelectorAll(".i18n-view").forEach(el => el.textContent = t.view);
                    }

                    function toggleLang() {
                        const current = localStorage.getItem("lang") || "en";
                        localStorage.setItem("lang", current === "en" ? "zh" : "en");
                        updateUI();
                    }

                    // 初始化语言
                    updateUI();

                    // 自由缩放逻辑
                    const ta = document.getElementById("grow-text");
                    ta.addEventListener("input", function() {
                        this.style.height = "auto";
                        this.style.height = this.scrollHeight + "px";
                    });

                    // 文件名动态列表
                    const fileInput = document.getElementById("file-input");
                    const fileList = document.getElementById("file-list");
                    fileInput.addEventListener("change", function() {
                        fileList.innerHTML = "";
                        Array.from(this.files).forEach(file => {
                            const div = document.createElement("div");
                            div.className = "file-item";
                            div.textContent = file.name;
                            fileList.appendChild(div);
                        });
                    });

                    function toggleDarkMode() {
                        const isDark = document.body.classList.toggle("dark-mode");
                        localStorage.setItem("theme", isDark ? "dark" : "light");
                    }

                    if ('serviceWorker' in navigator) {
                        window.addEventListener('load', () => {
                            navigator.serviceWorker.register('/static/sw.js');
                        });
                    }
                "#)) }
            }
        }
    };
    HttpResponse::Ok().content_type("text/html").body(markup.into_string())
}

#[post("/post")]
async fn post_message(mut payload: Multipart, db: web::Data<SqlitePool>) -> impl Responder {
    let mut name = String::new();
    let mut message = String::new();
    let mut images = Vec::new();
    let mut others = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        let disp = field.content_disposition().clone();
        let field_name = disp.get_name().unwrap_or("");

        match field_name {
            "user_name" => { while let Ok(Some(chunk)) = field.try_next().await { name.push_str(std::str::from_utf8(&chunk).unwrap_or("")); } }
            "user_msg" => { while let Ok(Some(chunk)) = field.try_next().await { message.push_str(std::str::from_utf8(&chunk).unwrap_or("")); } }
            "media" => {
                if let Some(filename) = disp.get_filename() {
                    if !filename.is_empty() {
                        let ext = Path::new(filename).extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                        let fname = format!("{}-{}", Uuid::new_v4(), sanitize(filename));
                        let filepath = Path::new("uploads").join(&fname);
                        let _ = fs::create_dir_all("uploads");
                        if let Ok(mut f) = fs::File::create(&filepath) {
                            while let Ok(Some(chunk)) = field.try_next().await { let _ = f.write_all(&chunk); }
                            if ["jpg","jpeg","png","gif","webp"].contains(&ext.as_str()) { images.push(fname); } else { others.push(fname); }
                        }
                    }
                }
            }
            _ => ()
        }
    }

    if !name.trim().is_empty() {
        let img_str = if images.is_empty() { None } else { Some(images.join(",")) };
        let other_str = if others.is_empty() { None } else { Some(others.join(",")) };
        let _ = sqlx::query("INSERT INTO messages (name, message, image_path, video_path) VALUES (?, ?, ?, ?)")
            .bind(&name).bind(&message).bind(img_str).bind(other_str)
            .execute(db.get_ref()).await;
    }
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

#[post("/delete/{id}")]
async fn delete_message(db: web::Data<SqlitePool>, id: web::Path<i64>) -> impl Responder {
    let _ = sqlx::query("DELETE FROM messages WHERE id = ?").bind(*id).execute(db.get_ref()).await;
    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let _ = fs::create_dir_all("uploads");
    let db_url = format!("sqlite://{}", std::env::current_dir()?.join("guestbook.db").display());
    let db = SqlitePool::connect(&db_url).await.expect("DB连接失败");
    sqlx::query(r#"CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, message TEXT NOT NULL, image_path TEXT, video_path TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"#)
        .execute(&db).await.expect("建表失败");

    println!("🚀 Server ready at http://localhost:80");
    HttpServer::new(move || {
        App::new().app_data(web::Data::new(db.clone()))
            .service(index).service(post_message).service(delete_message)
            .service(Files::new("/uploads", "uploads").show_files_listing())
            .service(Files::new("/static", "static"))
    }).bind("0.0.0.0:80")?.run().await
}