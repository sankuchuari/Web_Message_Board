use actix_web::{web, App, HttpServer, Responder, HttpResponse, get, post, HttpRequest, cookie::{Cookie, CookieJar}};
use actix_multipart::Multipart;
use actix_files::Files;
use maud::{html, DOCTYPE, PreEscaped};
use pulldown_cmark::{Parser, Options, html::push_html};
use serde::Deserialize;
use sqlx::{SqlitePool, sqlite::SqliteRow, Row};
use futures_util::TryStreamExt as _;
use uuid::Uuid;
use sanitize_filename::sanitize;
use std::{fs, io::Write, path::Path, io};
use std::net::{UdpSocket, IpAddr};

struct StoredMessage {
    id: i64,
    name: String,
    message: String,
    image_path: Option<String>,
    video_path: Option<String>,
}

fn markdown_to_html(input: &str) -> String {
    let mut html_output = String::new();
    let parser = Parser::new_ext(input, Options::all());
    push_html(&mut html_output, parser);
    html_output
}

fn local_ip_via_udp() -> io::Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?; // 绑定到一个随机端口
    socket.connect("8.8.8.8:80")?; // 连接到 Google 的 DNS 服务器（8.8.8.8）
    Ok(socket.local_addr()?.ip()) // 获取本机的 IP 地址
}

#[get("/")]
async fn index(req: HttpRequest, db: web::Data<SqlitePool>) -> impl Responder {
    let dark_mode = req.cookie("theme").map(|c| c.value() == "dark").unwrap_or(false);

    let messages = sqlx::query("SELECT id, name, message, image_path, video_path FROM messages ORDER BY id DESC")
        .map(|row: SqliteRow| StoredMessage {
            id: row.get("id"),
            name: row.get("name"),
            message: row.get("message"),
            image_path: row.get("image_path"),
            video_path: row.get("video_path"),
        })
        .fetch_all(db.get_ref())
        .await
        .unwrap_or_default();

    let body_class = if dark_mode { "dark-mode" } else { "" };

    let markup = html! {
        (DOCTYPE)
        html lang="zh-CN" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "留言板" }

                // —— PWA 必要 —— 
                link rel="manifest" href="/static/manifest.json";
                meta name="theme-color" content="#121212";
                link rel="apple-touch-icon" href="/static/icons/icon-192x192.png";  // 给iOS用
                meta name="apple-mobile-web-app-capable" content="yes";
                meta name="apple-mobile-web-app-status-bar-style" content="black-translucent";

                // 注册 service worker
                script {
                    (r#"
                    if ('serviceWorker' in navigator) {
                        navigator.serviceWorker.register('/static/service-worker.js')
                          .then(reg => console.log('Service Worker 注册成功'))
                          .catch(err => console.error('Service Worker 注册失败', err));
                    }
                    "#)
                }
                style {
                    (r#"
                        body {
                            font-family: sans-serif;
                            max-width: 800px;
                            margin: 2em auto;
                            padding: 1em;
                            background-image: url('/static/back_image.png');
                            background-size: cover;
                            background-attachment: fixed;
                            color: var(--fg);
                            background-color: var(--bg);
                        }
                        :root {
                            --bg: #ffffff;
                            --fg: #000000;
                        }
                        .dark-mode {
                            --bg: #121212;
                            --fg: #ffffff;
                        }
                        form { margin-bottom: 2em; }
                        input, textarea { width: 100%; padding: 0.5em; margin: 0.5em 0; }
                        button { padding: 0.5em 1em; margin-left: 0.5em; }
                        .message { border: 1px solid #ccc; padding: 1em; border-radius: 8px; margin-bottom: 1em; background: #f9f9f9; }
                        .markdown p { margin: 0.5em 0; }
                        img.uploaded, video.uploaded { max-width: 200px; display: block; margin-top: 0.5em; }
                    "#)
                }
                script {
                    (r#"
                        function setTheme(dark) {
                            document.body.classList.toggle('dark-mode', dark);
                            document.cookie = "theme=" + (dark ? "dark" : "light") + "; path=/; max-age=31536000";
                        }
                        function toggleDarkMode() {
                            const dark = !document.body.classList.contains('dark-mode');
                            setTheme(dark);
                        }
                        window.onload = function() {
                            if (document.cookie.includes("theme=dark")) {
                                document.body.classList.add('dark-mode');
                            } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                                setTheme(true);
                            }
                        };
                    "#)
                }
            }
            body class=(body_class) {
                h1 { "留言板" }

                button onclick="toggleDarkMode()" { "切换夜间模式" }

                form method="post" action="/post" enctype="multipart/form-data" {
                    input type="text" name="name" placeholder="你的名字" required;
                    br;
                    textarea name="message" placeholder="写点什么..." required {};
                    br;
                    input type="file" name="media" accept="image/*,video/*";
                    br;
                    button type="submit" { "提交留言" }
                }

                h2 { "留言列表：" }
                @for msg in &messages {
                    div class="message" {
                        strong { (msg.name) }
                        div class="markdown" {
                            (PreEscaped(markdown_to_html(&msg.message)))
                        }
                        @if msg.image_path.is_some() {
                            img class="uploaded" src=(format!("/uploads/{}", msg.image_path.as_ref().unwrap())) alt="上传的图片";
                        }
                        @if msg.video_path.is_some() {
                            video class="uploaded" controls {
                                source src=(format!("/uploads/{}", msg.video_path.as_ref().unwrap())) type="video/mp4";
                                "您的浏览器不支持视频标签。"
                            }
                        }
                        form method="post" action=(format!("/delete/{}", msg.id)) {
                            button type="submit" { "删除" }
                        }
                    }
                }
            }
        }
    };

    HttpResponse::Ok()
        .content_type("text/html")
        .body(markup.into_string())
}

#[post("/post")]
async fn post_message(mut payload: Multipart, db: web::Data<SqlitePool>) -> impl Responder {
    let mut name = String::new();
    let mut message = String::new();
    let mut image_path: Option<String> = None;
    let mut video_path: Option<String> = None;

    while let Ok(Some(mut field)) = payload.try_next().await {
        let disp = field.content_disposition();
        match disp.get_name().unwrap() {
            "name" => {
                while let Some(chunk) = field.try_next().await.unwrap() {
                    name.push_str(std::str::from_utf8(&chunk).unwrap());
                }
            }
            "message" => {
                while let Some(chunk) = field.try_next().await.unwrap() {
                    message.push_str(std::str::from_utf8(&chunk).unwrap());
                }
            }
            "media" => {
                if let Some(filename) = disp.get_filename() {
                    let ext = Path::new(&filename).extension().and_then(|s| s.to_str()).unwrap_or("");
                    let is_image = ext == "jpg" || ext == "jpeg" || ext == "png" || ext == "gif";
                    let is_video = ext == "mp4" || ext == "mov" || ext == "avi" || ext == "webm";

                    if is_image {
                        let fname = format!("{}-{}", Uuid::new_v4(), sanitize(filename));
                        let filepath = Path::new("uploads").join(&fname);
                        fs::create_dir_all("uploads").unwrap();
                        let mut f = fs::File::create(&filepath).unwrap();
                        while let Some(chunk) = field.try_next().await.unwrap() {
                            f.write_all(&chunk).unwrap();
                        }
                        image_path = Some(fname);
                    } else if is_video {
                        let fname = format!("{}-{}", Uuid::new_v4(), sanitize(filename));
                        let filepath = Path::new("uploads").join(&fname);
                        fs::create_dir_all("uploads").unwrap();
                        let mut f = fs::File::create(&filepath).unwrap();
                        while let Some(chunk) = field.try_next().await.unwrap() {
                            f.write_all(&chunk).unwrap();
                        }
                        video_path = Some(fname);
                    }
                }
            }
            _ => {}
        }
    }

    let _ = sqlx::query("INSERT INTO messages (name, message, image_path, video_path) VALUES (?, ?, ?, ?)")
        .bind(&name)
        .bind(&message)
        .bind(&image_path)
        .bind(&video_path)
        .execute(db.get_ref())
        .await;

    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

#[post("/delete/{id}")]
async fn delete_message(
    db: web::Data<SqlitePool>,
    id: web::Path<i64>,
) -> impl Responder {
    let _ = sqlx::query("DELETE FROM messages WHERE id = ?")
        .bind(*id)
        .execute(db.get_ref())
        .await;

    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let cwd = std::env::current_dir()?;
    let db_path = cwd.join("guestbook.db");
    let db_url = format!("sqlite://{}", db_path.display());
    println!("使用数据库文件：{}", db_url);

    let db = SqlitePool::connect(&db_url)
        .await
        .expect("连接数据库失败，请检查路径和权限");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            message     TEXT    NOT NULL,
            image_path  TEXT,
            video_path  TEXT
        )
    "#)
        .execute(&db)
        .await
        .expect("建表失败");

    println!("打开浏览器访问：http://localhost:80");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(Files::new("/uploads", "uploads"))
            .service(Files::new("/static", "static")) // 提供 static 文件夹的内容
            .service(index)
            .service(post_message)
            .service(delete_message)
    })
        .bind("127.0.0.1:80")?
        .run()
        .await
}
