use crate::routing::structure::{ClientDeviceReportForm};
use actix_web::{post, web, HttpResponse, Responder};
use sqlx:: SqlitePool;
use tokio::sync::broadcast;
pub mod structure;
pub mod process_func;
use structure::{AuthForm,StoredMessage,EditForm};
use process_func::markdown_to_html;


// --- 登录处理 ---
///日志：
///     05.03.2026构建函数
///     05.04.2026限制登录频率
#[post("/login")]
pub(crate) async fn login_handler(
    //数据库连接
    db: web::Data<SqlitePool>,
    //sessionKey
    session: Session,
    //拦截POST数据，反序列化后注入form
    form: web::Form<AuthForm>
) -> impl Responder {
    let delay = rand::thread_rng().gen_range(100..500);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    //获取用户对应原始数据
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(db.get_ref())
        .await;
    //缺失返回
    let auth_failed = HttpResponse::Unauthorized().body("wrong_credentials");
    //判别正误
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
pub(crate) async fn register_handler(
    //数据库连接
    db: web::Data<SqlitePool>,
    //拦截POST数据，反序列化后注入form
    form: web::Form<AuthForm>
) -> impl Responder {
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

// --- 接收前端钩子上报的设备状态与前端IP ---
#[post("/api/report_device")]
pub(crate) async fn report_device_handler(
    //数据库链接
    db: web::Data<SqlitePool>,
    //SessionKey
    session: actix_session::Session,
    //接收前端打包过来的 JSON 对象
    payload: web::Json<ClientDeviceReportForm>,
    tx: web::Data<broadcast::Sender<String>>,
) -> impl Responder {
    let report = payload.into_inner();

    // 获取当前登录的用户（如果是未登录状态则记录为匿名游客）
    let current_user = session.get::<String>("user")
        .ok()
        .flatten()
        .unwrap_or_else(|| "匿名游客".to_string());

    // 记录一条全生命周期审计日志，展示前端抓到的 IP 和系统环境
    let log_details = format!(
        "前端感知上报 -> 操作系统: {}, 浏览器: {}, 前端抓取IP: {}",
        report.os, report.browser, report.client_ip
    );

    // 写入数据库并推送看板
    process_func::log_action(
        db.get_ref(),
        Some(&current_user),
        "前端设备审计",
        &log_details,
        Some(&report.client_ip), // 这里直接存入前端钩子抓到的IP
        Some(&report.os),
        Some(&report.browser),
        Some(tx.get_ref()),
    ).await;

    HttpResponse::Ok().body("report_success")
}