pub mod tls_ssl_certificate_register;
pub mod routing;
use tls_ssl_certificate_register::{run_python_setup, load_rustls_config};
use routing::*;
use actix_web::{cookie::Key, cookie::SameSite, web, App, HttpServer};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_files::Files;
use sqlx::{Row, SqlitePool};
use futures_util::TryStreamExt as _;
use std::{fs, io, io::Write};
use argon2::{PasswordHasher, PasswordVerifier};
use rand::Rng;
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
    println!("Server ready at https://localhost:6790");
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