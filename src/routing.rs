use crate::routing::structure::{ClientDeviceReportForm};
use actix_web::{post, web, HttpResponse, Responder};
use sqlx:: SqlitePool;
use tokio::sync::broadcast;
pub mod structure;
pub mod process_func;

// --- 前端钩子上报接收 ---
///日志：
///     05.19.2025构建函数
#[post("/api/report_device")]
pub(crate) async fn report_device_handler(
    //数据库链接
    db: web::Data<SqlitePool>,
    //SessionKey
    session: actix_session::Session,
    //接收前端打包过来的 JSON 对象
    payload: web::Json<ClientDeviceReportForm>,
    //日志异步广播
    tx: web::Data<broadcast::Sender<String>>,
) -> impl Responder {
    //解析JSON
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
        Some(&report.client_ip),
        Some(&report.os),
        Some(&report.browser),
        Some(tx.get_ref()),
    ).await;

    HttpResponse::Ok().body("report_success")
}