pub mod tls_ssl_certificate_register;
pub mod routing;
pub mod backend_dashboard;
pub mod infront_dashboard;
//自建函数引用
use {
    //管理员创建与保障
    crate::routing::process_func::ensure_admin_exists,
    //前台面板
    infront_dashboard::{
        //面板主路由
        index,
        //用户状态处理
        login_handler,logout_handler,register_handler,
        //留言基本行为（发送、编辑、删除）
        post_message,edit_message,delete_message
    },
    //后台面板
    backend_dashboard::{
        //面板主路由
        admin_dashboard,
        //管理员基本行为
        admin_delete_user,toggle_user_role,
        //邮件配置
        save_smtp_config,
        //日志流处理
        audit_log_stream
    }
    //辅助路由
    routing::{
        //前端钩子状态接收
        report_device_handler
    }
    //TLS_SSL自动化创建和注册
    tls_ssl_certificate_register::{
        //签名创建（Python)
        run_python_setup,
        //签名注册（命令行）
        load_rustls_config
    }
};
//库引用
use{
    //异步web框架
    actix_web::{
        cookie::{
            Key,SameSite
        },
        web, App, HttpServer
    }
    //Actix_Web会话管理
    actix_session::{
        storage::CookieSessionStore, SessionMiddleware
    }
    //Actix_Web静态文件服务扩展
    actix_files::{
        Files
    }
    //SQL工具包
    sqlx::{
        SqlitePool
    }
    tokio::{
        sync::broadcast
    }
    std::{
        fs, io
    }
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
///     05.19.2026增加管理员账户自维护逻辑，users表新增is_admin字段
///     05.19.2026增加后台管理相关路由
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
    // 表结构动态升级与新表创建
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0").execute(&db).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)").execute(&db).await;
    let _ = sqlx::query("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT NOT NULL, details TEXT, ip_address TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)").execute(&db).await;

    // 自动检测与保护管理员账户
    ensure_admin_exists(&db).await;
    let _config = load_rustls_config();

    //为日志流创建异步广播通道
    let (tx, _rx) = broadcast::channel::<String>(100);
    let shared_tx = web::Data::new(tx); // 包装为 Actix 共享原子指针


    // Session 密钥生成（生产环境应从配置文件读取固定密钥）
    let key = Key::generate();
    //提示运行地址
    println!("Server ready at https://localhost:6790");
    //运行HTTP服务
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))                           //预拷贝数据库链接
            .app_data(shared_tx.clone())                                    //绑定日志流消息通道
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
            .service(index)                 //前端面板
            .service(login_handler)         //登录管理
            .service(register_handler)      //注册管理
            .service(logout_handler)        //登出管理
            .service(post_message)          //消息上传
            .service(edit_message)          //消息编辑
            .service(delete_message)        //消息删除
            .service(admin_dashboard)       //管理面板
            .service(save_smtp_config)      //SMTP保存
            .service(admin_delete_user)     //用户删除
            .service(toggle_user_role)      //用户提权
            .service(report_device_handler) //钩子接收
            .service(audit_log_stream)      //日志接收
            // 静态资源与上传目录托管
            .service(Files::new("/uploads", "uploads")) //上传目录
            .service(Files::new("/static", "static"))   //静态目录
    }).bind_rustls_021("0.0.0.0:6790", load_rustls_config())?   //绑定本地IPV4端口
        .bind_rustls_021("[::]:6790", load_rustls_config())?    //绑定本地IPV6端口
        .run()
        .await
}