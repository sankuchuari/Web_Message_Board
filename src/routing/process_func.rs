use crate::routing::structure::AuditLog;
use actix_session::Session;
use actix_web::HttpResponse;
use ammonia::clean;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use pulldown_cmark::html::push_html;
use pulldown_cmark::{Options, Parser};
use rand::Rng;
use sqlx::{Row, SqlitePool};

// --- Markdown 转 HTML ---
///日志：
///     04.26.2025构建函数
///     05.04.2026修复XSS漏洞
// 修复 XSS：Markdown 转 HTML 后必须经过 ammonia 清洗
pub(crate) fn markdown_to_html(input: &str) -> String {
    let mut html_output = String::new();
    let parser = Parser::new_ext(input, Options::all());
    push_html(&mut html_output, parser);
    // 使用 ammonia 清洗 HTML，防止存储型 XSS
    clean(&html_output)
}

// --- 异步用户行为日志记录 ---
///     05.19.2025构建函数
pub async fn log_action(
    db: &sqlx::SqlitePool,
    username: Option<&str>,
    action: &str,
    details: &str,
    ip: Option<&str>,
    os: Option<&str>,
    browser: Option<&str>,
    tx: Option<&tokio::sync::broadcast::Sender<String>>,
) {
    // 1. 严格持久化到数据库
    let _ = sqlx::query(
        "INSERT INTO audit_logs (username, action, details, ip_address, os, browser) VALUES (?, ?, ?, ?, ?, ?)"
    )
        .bind(username)
        .bind(action)
        .bind(details)
        .bind(ip)
        .bind(os)
        .bind(browser)
        .execute(db)
        .await;

    // 2. 组装并广播 JSON
    if let Some(sender) = tx {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // ✨ 请确保这里的字段名与你的 src/routing/structure.rs 中的 AuditLog 保持绝对一致
        let log_payload = AuditLog {
            username: username.map(|s| s.to_string()),
            action: action.to_string(),
            details: Some(details.to_string()),
            ip_address: ip.map(|s| s.to_string()), // 👈 如果结构体里叫 client_ip，请将其改为 client_ip
            os: os.map(|s| s.to_string()),
            browser: browser.map(|s| s.to_string()),
            created_at: now,
        };

        if let Ok(json_str) = serde_json::to_string(&log_payload) {
            let _ = sender.send(json_str);
        }
    }
}
// --- 鉴权辅助函数 ---
///     05.19.2025构建函数
pub(crate) async fn check_admin(db: &SqlitePool, session: &Session) -> Result<String, HttpResponse> {
    if let Some(user) = session.get::<String>("user").ok().flatten() {
        let row = sqlx::query("SELECT is_admin FROM users WHERE username = ?")
            .bind(&user)
            .fetch_optional(db)
            .await;
        if let Ok(Some(r)) = row {
            let is_admin: i64 = r.get("is_admin");
            if is_admin == 1 {
                return Ok(user);
            }
        }
    }
    Err(HttpResponse::SeeOther().append_header(("Location", "/")).finish())
}

// --- 管理员账户保障函数 ---
///     05.19.2025构建函数
pub(crate) async fn ensure_admin_exists(db: &SqlitePool) {
    let count_row = sqlx::query("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(db)
        .await;

    if let Ok(row) = count_row {
        let admin_count: i64 = row.get(0);
        if admin_count == 0 {
            let default_admin_user = "admin";
            let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            let mut rng = rand::thread_rng();
            let default_admin_pass: String = (0..12)
                .map(|_| {
                    let idx = rng.gen_range(0..charset.len());
                    charset[idx] as char
                })
                .collect();

            let salt = SaltString::generate(&mut rand::thread_rng());
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(default_admin_pass.as_bytes(), &salt)
                .expect("管理员密码哈希失败")
                .to_string();

            let result = sqlx::query(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1) \
                 ON CONFLICT(username) DO UPDATE SET is_admin = 1, password_hash = ?"
            )
                .bind(default_admin_user)
                .bind(&password_hash)
                .bind(&password_hash)
                .execute(db)
                .await;

            if result.is_ok() {
                println!("+--------------------------------------------------------+");
                println!("| [警告] 系统未检测到管理员账户，已自动初始化默认管理员！ |");
                println!("| 账号 (Username): {}                                  |", default_admin_user);
                println!("| 密码 (Password): {}                           |", default_admin_pass);
                println!("| 请在登录后台后及时修改密码或创建新的管理员账户。       |");
                println!("+--------------------------------------------------------+");
            }
        }
    }
}