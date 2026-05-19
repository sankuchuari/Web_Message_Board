use futures_util::StreamExt;
use std::convert::Infallible;
use actix_session::Session;
use actix_web::{get, post, web, HttpResponse, Responder};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use maud::{html, PreEscaped, DOCTYPE};
use sqlx::{Row, SqlitePool};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use crate::routing::process_func;
use crate::routing::process_func::check_admin;
use crate::routing::structure::{AdminUserItem, AuditLog, ClientDeviceReportForm, SmtpConfigForm};

// --- 后台主页 ---
///日志：
///     05.19.2025构建函数
#[get("/admin")]
pub(crate) async fn admin_dashboard(
    db: web::Data<SqlitePool>,
    session: Session,
) -> impl Responder {
    // 1. 超级管理员鉴权
    let admin_user = match check_admin(db.get_ref(), &session).await {
        Ok(user) => user,
        Err(err_response) => return err_response,
    };

    // 2. 初始加载：稳健获取审计日志（降序排列，最多 100 条）
    let log_rows = sqlx::query("SELECT username, action, details, ip_address, os, browser, created_at FROM audit_logs ORDER BY id DESC LIMIT 100")
        .fetch_all(db.get_ref())
        .await
        .unwrap_or_else(|_| vec![]);

    let mut logs = Vec::new();
    for row in log_rows {
        logs.push(AuditLog {
            username: row.get::<Option<String>, _>("username"),
            action: row.get::<String, _>("action"),
            details: row.get::<Option<String>, _>("details"),
            ip_address: row.get::<Option<String>, _>("ip_address"),
            os: row.get::<Option<String>, _>("os"),
            browser: row.get::<Option<String>, _>("browser"),
            created_at: row.get::<String, _>("created_at"),
        });
    }

    // 3. 初始加载：按 ID 升序获取系统所有注册用户
    let user_rows = sqlx::query("SELECT id, username, is_admin FROM users ORDER BY id ASC")
        .fetch_all(db.get_ref())
        .await
        .unwrap_or_else(|_| vec![]);

    let mut users = Vec::new();
    for row in user_rows {
        let id: i64 = row.try_get::<i64, _>("id")
            .unwrap_or_else(|_| row.try_get::<i32, _>("id").map(|n| n as i64).unwrap_or(0));
        let username: String = row.try_get::<String, _>("username").unwrap_or_else(|_| "未知用户".to_string());
        let is_admin: i64 = row.try_get::<i64, _>("is_admin")
            .unwrap_or_else(|_| {
                row.try_get::<i32, _>("is_admin").map(|n| n as i64).unwrap_or_else(|_| {
                    row.try_get::<bool, _>("is_admin").map(|b| if b { 1 } else { 0 }).unwrap_or(0)
                })
            });

        let created_at: String = logs.iter()
            .find(|l| l.username.as_deref() == Some(&username) && l.action.contains("REGISTER"))
            .map(|l| l.created_at.clone())
            .unwrap_or_else(|| "早期导入/系统".to_string());

        users.push(AdminUserItem { id, username, is_admin, created_at });
    }

    // 4. 获取 SMTP 中继配置
    let smtp_row = sqlx::query("SELECT smtp_host, smtp_port, username FROM smtp_config WHERE id = 1")
        .fetch_optional(db.get_ref())
        .await
        .unwrap_or(None);

    let (s_host, s_port, s_user) = match smtp_row {
        Some(row) => (
            row.get::<String, _>("smtp_host"),
            row.get::<i64, _>("smtp_port").to_string(),
            row.get::<String, _>("username"),
        ),
        None => ("".to_string(), "".to_string(), "".to_string()),
    };

    let markup = html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                title { "安全生命周期行为审计看板" }
                style { (PreEscaped(r#"
                    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8f9fa; padding: 40px; color: #333; }
                    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 35px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
                    h1 { color: #1e1e24; border-bottom: 3px solid #4c6ef5; padding-bottom: 10px; margin-bottom: 30px; }
                    h2 { margin-top: 40px; color: #2b2d42; border-left: 5px solid #4c6ef5; padding-left: 10px; display: flex; justify-content: space-between; align-items: center; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; border-radius: 8px; overflow: hidden; }
                    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #dee2e6; }
                    th { background: #f1f3f5; font-weight: 600; color: #495057; }
                    .btn { background: #4c6ef5; color: white; padding: 6px 12px; border: none; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 13px; display: inline-flex; align-items: center; gap: 4px; }
                    .btn:hover { background: #3b5bdb; }
                    .btn-danger { background: #fa5252; }
                    .btn-danger:hover { background: #e03131; }
                    .btn-warn { background: #fcc419; color: #212529; }
                    .status-indicator { font-size: 12px; color: #0ca678; background: #e6fcf5; padding: 4px 10px; border-radius: 12px; font-weight: bold; display: inline-flex; align-items: center; gap: 6px; }
                    .pulse-dot { width: 8px; height: 8px; background: #0ca678; border-radius: 50%; animation: pulseGlow 1.5s infinite; }
                    @keyframes pulseGlow {
                        0% { transform: scale(0.9); opacity: 0.6; }
                        50% { transform: scale(1.2); opacity: 1; }
                        100% { transform: scale(0.9); opacity: 0.6; }
                    }
                "#)) }

                // ⚡ 真正的全自动、零按钮、无感刷新无死锁引擎
                script { (PreEscaped(r#"
                    document.addEventListener("DOMContentLoaded", function() {

                        // 封装真正的全自动化静默刷新函数
                        async function startTrueAutoRefresh() {
                            try {
                                // 悄悄请求当前看板页面
                                const response = await fetch(window.location.href);
                                if (!response.ok) return;

                                const htmlText = await response.text();
                                const parser = new DOMParser();
                                const doc = parser.parseFromString(htmlText, 'text/html');

                                // 1. 【用户看板】无感局部刷新替换
                                const freshUserBody = doc.getElementById("user-table-body");
                                const localUserBody = document.getElementById("user-table-body");
                                if (freshUserBody && localUserBody) {
                                    if (localUserBody.innerHTML !== freshUserBody.innerHTML) {
                                        localUserBody.innerHTML = freshUserBody.innerHTML;
                                    }
                                }

                                // 2. 【审计日志】无感局部刷新替换（保持最新顺序）
                                const freshLogBody = doc.getElementById("log-table-body");
                                const localLogBody = document.getElementById("log-table-body");
                                if (freshLogBody && localLogBody) {
                                    if (localLogBody.innerHTML !== freshLogBody.innerHTML) {
                                        localLogBody.innerHTML = freshLogBody.innerHTML;
                                    }
                                }
                                console.log("真正的行为日志实时看板：同步成功 🟢");
                            } catch (err) {
                                console.error("自动化拉取遇到闪断异常:", err);
                            }
                        }

                        // 每 2 秒完全自动化在后台对齐一次数据库列表，用户不需要进行任何操作
                        setInterval(startTrueAutoRefresh, 2000);
                    });
                "#)) }
            }
            body {
                div class="container" {
                    h1 { "🛡️ 系统高级管理与全生命周期行为审计中心" }
                    p { "当前管理员账户: " strong { (admin_user) } " | 看板状态: "
                        div class="status-indicator" {
                            div class="pulse-dot" {}
                            "真正的后台列表秒级全自动同步中"
                        }
                    }

                    // --- 模块 1：SMTP 配置 ---
                    h2 { "⚙️ 安全联发中继 SMTP 服务配置" }
                    form method="POST" action="/admin/config/smtp" style="margin-bottom: 30px;" {
                        div style="margin-bottom:10px;" {
                            label { "SMTP 发信服务器主机 (Host)" }
                            input type="text" name="smtp_host" value=(s_host) required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px;";
                        }
                        div style="margin-bottom:10px;" {
                            label { "SMTP 端口 (Port)" }
                            input type="number" name="smtp_port" value=(s_port) required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px;";
                        }
                        div style="margin-bottom:10px;" {
                            label { "SMTP 授权账户 (User Email)" }
                            input type="text" name="smtp_user" value=(s_user) required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px;";
                        }
                        div style="margin-bottom:15px;" {
                            label { "SMTP 授权密钥/密码 (Password)" }
                            input type="password" name="smtp_pass" placeholder="⚠️ 留空表示不修改原安全密钥" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px;";
                        }
                        button type="submit" class="btn" { "保存中继通信配置并下发" }
                    }

                    // --- 模块 2：用户生命周期看板 ---
                    h2 { "👥 注册账户生命周期看板" }
                    table {
                        thead {
                            tr { th { "用户ID" } th { "账户名" } th { "安全权限组" } th { "注册于" } th { "强力管制操作" } }
                        }
                        tbody id="user-table-body" {
                            @for user in &users {
                                tr id=(format!("urow_{}", user.username)) {
                                    td { (user.id) }
                                    td { (user.username) }
                                    td { @if user.is_admin == 1 { "👑 系统超级管理员" } @else { "👤 普通前台用户" } }
                                    td { (user.created_at) }
                                    td {
                                        @if user.username == admin_user {
                                            span style="color: #adb5bd; font-size: 14px;" { "🔒 自身账户锁定保护" }
                                        } @else {
                                            form method="POST" action=(format!("/admin/users/delete/{}", user.username)) style="display:inline;margin-right:5px;" {
                                                button type="submit" class="btn btn-danger" onclick="return confirm('⚠️ 确认彻底抹除该用户？')" { "彻底抹除账户" }
                                            }
                                            form method="POST" action=(format!("/admin/users/toggle_role/{}", user.username)) style="display:inline;" {
                                                @if user.is_admin == 1 {
                                                    button type="submit" class="btn btn-warn" { "降级账户" }
                                                } @else {
                                                    button type="submit" class="btn" { "提权管理员" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // --- 模块 3：安全行为审计日志 (真正的全自动化局部替换区) ---
                    h2 { "📋 全生命周期安全行为审计日志" }
                    table {
                        thead {
                            tr { th { "发生时间" } th { "行为主体" } th { "安全动作" } th { "详细变更载荷" } th { "远程源IP地址" } th { "操作系统" } th { "浏览器" } }
                        }
                        tbody id="log-table-body" {
                            @for log in &logs {
                                tr {
                                    td { strong { (log.created_at) } }
                                    td { (log.username.as_deref().unwrap_or("匿名游客")) }
                                    td { span style="background:#f1f3f5;padding:2px 6px;border-radius:4px;" { (log.action) } }
                                    td { (log.details.as_deref().unwrap_or("")) }
                                    td { code { (log.ip_address.as_deref().unwrap_or("未知IP")) } }
                                    td { (log.os.as_deref().unwrap_or("未知系统")) }
                                    td { (log.browser.as_deref().unwrap_or("未知浏览器")) }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(markup.into_string())
}
// --- 邮件通用协议配置落地与测试机制 ---
#[post("/admin/config/smtp")]
pub(crate) async fn save_smtp_config(
    db: web::Data<SqlitePool>,
    session: Session,
    form: web::Form<SmtpConfigForm>,
    payload: web::Json<ClientDeviceReportForm>,
    tx: web::Data<broadcast::Sender<String>>
) -> impl Responder {
    let admin_user = match check_admin(db.get_ref(), &session).await {
        Ok(u) => u,
        Err(res) => return res,
    };

    let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES ('smtp_host', ?)")
        .bind(&form.smtp_host).execute(db.get_ref()).await;
    let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES ('smtp_port', ?)")
        .bind(form.smtp_port.to_string()).execute(db.get_ref()).await;
    let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES ('smtp_user', ?)")
        .bind(&form.smtp_user).execute(db.get_ref()).await;
    if !form.smtp_pass.is_empty() {
        let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES ('smtp_pass', ?)")
            .bind(&form.smtp_pass).execute(db.get_ref()).await;
    }

    // 记录管理员配置变更日志
    let report = payload.into_inner();
    process_func::log_action(
        db.get_ref(),
        Some(&admin_user),
        "UPDATE_SMTP_CONFIG",
        &format!("SMTP Host: {}", form.smtp_host),
        Some(&report.client_ip),
        Some(&report.os),
        Some(&report.browser),
        Some(tx.get_ref())).await;

    // 构建邮件信体
    let creds = Credentials::new(form.smtp_user.clone(), form.smtp_pass.clone());
    let mailer = SmtpTransport::relay(&form.smtp_host)
        .unwrap()
        .credentials(creds)
        .port(form.smtp_port)
        .build();

    let email = Message::builder()
        .from(form.smtp_user.parse().unwrap())
        .to(form.smtp_user.parse().unwrap())
        .subject("系统公共邮箱功能绑定成功")
        .body(String::from("如果您收到了这封邮件，说明系统后台通用邮件协议（SMTP）绑定成功。未来添加新账户注册校验、更改密码发送验证码功能时，将使用此通信通道。"))
        .unwrap();

    match mailer.send(&email) {
        Ok(_) => HttpResponse::Ok().body("配置本地持久化成功，且握手测试信成功投递，请去您的收件箱查收。"),
        Err(e) => HttpResponse::Ok().body(format!("本地配置已保存，但向目标邮件服务器握手发信时遭遇网络或认证阻断，技术报错: {}", e)),
    }
}

// --- 账户动态删除决策 ---
///日志：
///     05.19.2025构建函数
#[post("/admin/users/delete/{username}")]
pub(crate) async fn admin_delete_user(
    db: web::Data<SqlitePool>,
    session: Session,
    path: web::Path<String>,
    tx: web::Data<broadcast::Sender<String>>,
) -> impl Responder {
    // 1. 严格越权拦截
    let admin_user = match check_admin(db.get_ref(), &session).await {
        Ok(user) => user,
        // 如果鉴权失败，直接返回对应的拦截响应
        Err(err_response) => return err_response,
    };

    let target_username = path.into_inner();

    // 防止管理员不小心抹除自己
    if target_username == admin_user {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body("<h3>⚠️ 鉴权中心拒绝了请求：安全系统禁止抹除当前登录的自身账户！</h3>");
    }

    // 2. 执行物理抹除
    let result = sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(&target_username)
        .execute(db.get_ref())
        .await;

    if result.is_ok() {
        // 3. 记录审计日志
        process_func::log_action(
            db.get_ref(),
            Some(&admin_user),
            "ACCOUNT_ERASE",
            &format!("管理员彻底抹除了违规账户: {}", target_username),
            None, None, None,
            Some(tx.get_ref())
        ).await;

        // 重定向到/admin
        return HttpResponse::SeeOther()
            .insert_header(("Location", "/admin"))
            .finish();
    }

    HttpResponse::InternalServerError().body("数据库抹除执行异常")
}

// --- 日志流处理 ---
///日志：
///     05.19.2025构建函数
#[get("/api/audit_logs/stream")]
pub(crate) async fn audit_log_stream(
    tx: web::Data<broadcast::Sender<String>>,
) -> impl Responder {
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).map(|res| {
        match res {
            Ok(msg) => Ok::<_, Infallible>(web::Bytes::from(format!("data: {}\n\n", msg))),
            Err(_) => Ok::<_, Infallible>(web::Bytes::from("")),
        }
    });

    HttpResponse::Ok()
        .insert_header(("content-type", "text/event-stream"))
        .insert_header(("cache-control", "no-cache"))
        .insert_header(("connection", "keep-alive"))
        .streaming(stream)
}

// --- 用户权限控制 ---
///日志：
///     05.19.2025构建函数
#[post("/admin/users/toggle_role/{username}")]
pub(crate) async fn toggle_user_role(
    db: web::Data<SqlitePool>,
    session: Session,
    path: web::Path<String>,
    tx: web::Data<broadcast::Sender<String>>,
) -> impl Responder {
    // 1. 严格越权与自身保护拦截
    let admin_user = match check_admin(db.get_ref(), &session).await {
        Ok(user) => user,
        Err(err_response) => return err_response,
    };

    let target_username = path.into_inner();

    if target_username == admin_user {
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body("<h3>⚠️ 鉴权中心拒绝了请求：安全系统禁止对当前登录的自身账户进行降级或权限变更！</h3>");
    }

    // 2. 查询当前目标用户的真实权限状态
    let user_row = sqlx::query("SELECT is_admin FROM users WHERE username = ?")
        .bind(&target_username)
        .fetch_optional(db.get_ref())
        .await
        .unwrap_or(None);

    if let Some(row) = user_row {
        // 兼容处理 SQLite 中可能存在的各种 is_admin 类型 (i64 / i32 / bool)
        let current_is_admin: i64 = row.try_get::<i64, _>("is_admin")
            .unwrap_or_else(|_| {
                row.try_get::<i32, _>("is_admin").map(|n| n as i64).unwrap_or_else(|_| {
                    row.try_get::<bool, _>("is_admin").map(|b| if b { 1 } else { 0 }).unwrap_or(0)
                })
            });

        // 3. 计算翻转后的新状态
        let new_status: i64 = if current_is_admin == 1 { 0 } else { 1 };
        let action_tag = if new_status == 1 { "ROLE_UPGRADE" } else { "ROLE_DOWNGRADE" };
        let action_details = if new_status == 1 {
            format!("管理员将账户 {} 提权至超级管理组", target_username)
        } else {
            format!("管理员将账户 {} 降级至普通前台组", target_username)
        };

        // 4. 执行状态更新
        let update_result = sqlx::query("UPDATE users SET is_admin = ? WHERE username = ?")
            .bind(new_status)
            .bind(&target_username)
            .execute(db.get_ref())
            .await;

        return match update_result {
            Ok(_) => {
                // 5. 记录审计日志
                process_func::log_action(
                    db.get_ref(),
                    Some(&admin_user),
                    action_tag,
                    &action_details,
                    None, None, None,
                    Some(tx.get_ref())
                ).await;

                // 重定向到 /admin
                HttpResponse::SeeOther()
                    .insert_header(("Location", "/admin"))
                    .finish()
            },
            Err(db_err) => {
                eprintln!("数据库更新用户权限失败: {:?}", db_err);
                HttpResponse::InternalServerError().body(format!("数据库执行错误: {:?}", db_err))
            }
        }
    }

    // 如果找不到该用户，也安全重定向回去，防止卡死
    HttpResponse::SeeOther()
        .insert_header(("Location", "/admin"))
        .finish()
}