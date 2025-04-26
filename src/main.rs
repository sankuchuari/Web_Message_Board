use actix_web::{web, App, HttpServer, Responder, HttpResponse, post, get, HttpRequest, cookie::{Cookie, CookieJar}};
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
}

fn markdown_to_html(input: &str) -> String {
    let mut html_output = String::new();
    let parser = Parser::new_ext(input, Options::all());
    push_html(&mut html_output, parser);
    html_output
}

fn local_ip_via_udp() -> io::Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    Ok(socket.local_addr()?.ip())
}

#[get("/")]
async fn index(req: HttpRequest, db: web::Data<SqlitePool>) -> impl Responder {
    let dark_mode = req.cookie("theme").map(|c| c.value() == "dark").unwrap_or(false);

    let messages = sqlx::query("SELECT id, name, message, image_path FROM messages ORDER BY id DESC")
        .map(|row: SqliteRow| StoredMessage {
            id: row.get("id"),
            name: row.get("name"),
            message: row.get("message"),
            image_path: row.get("image_path"),
        })
        .fetch_all(db.get_ref())
        .await
        .unwrap_or_default();

    let body_class = if dark_mode { "dark-mode" } else { "" };

    let markup = html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                title { "留言板" }
                style {
                    (r#"
                        body {
                            font-family: sans-serif;
                            max-width: 800px;
                            margin: 2em auto;
                            padding: 1em;
                            background-image: url('/static/back_image.png');
                            background-size: cover;
                            color: var(--fg);
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
                        img.uploaded { max-width: 200px; display: block; margin-top: 0.5em; }
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
                    input type="file" name="image" accept="image/*";
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
                        form method="post" action=(format!("/delete/{}", msg.id)) {
                            button type="submit" { "删除" }
                        }
                    }
                }
            }
        }
    };

    HttpResponse::Ok().content_type("text/html").body(markup.into_string())
}

/// 处理表单提交和文件上传
#[post("/post")]
async fn post_message(mut payload: Multipart, db: web::Data<SqlitePool>) -> impl Responder {
    let mut name = String::new();
    let mut message = String::new();
    let mut image_path: Option<String> = None;

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
            "image" => {
                if let Some(filename) = disp.get_filename() {
                    let fname = format!("{}-{}", Uuid::new_v4(), sanitize(filename));
                    let filepath = Path::new("uploads").join(&fname);
                    fs::create_dir_all("uploads").unwrap();
                    let mut f = fs::File::create(&filepath).unwrap();
                    while let Some(chunk) = field.try_next().await.unwrap() {
                        f.write_all(&chunk).unwrap();
                    }
                    image_path = Some(fname);
                }
            }
            _ => {}
        }
    }

    let _ = sqlx::query("INSERT INTO messages (name, message, image_path) VALUES (?, ?, ?)")
        .bind(&name)
        .bind(&message)
        .bind(&image_path)
        .execute(db.get_ref())
        .await;

    HttpResponse::SeeOther().append_header(("Location", "/")).finish()
}

/// 删除留言
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
    if let Ok(ip) = local_ip_via_udp() {
        println!("本机 IP: {}", ip);
    }
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
            image_path  TEXT
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
            .service(Files::new("/static", "static"))  // 服务 static 文件夹中的所有内容
            .service(index)
            .service(post_message)
            .service(delete_message)
    })
        .bind(("0.0.0.0", 80))?
        .run()
        .await
}
