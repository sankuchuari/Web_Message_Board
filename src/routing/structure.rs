use serde::{Deserialize, Serialize};
// --- 数据结构 ---

/// 存储在数据库中的留言信息结构体
pub(crate) struct StoredMessage {
    //日志ID
    pub(crate) id: i64,
    //用户名
    pub(crate) name: String,
    //渲染后的HTML文本内容
    pub(crate) message: String,
    //原始Markdown源码
    pub(crate) raw_message: String,
    //图片UUID
    pub(crate) image_path: Option<String>,
    //视频&其他媒体UUID
    pub(crate) video_path: Option<String>,
    //时间戳
    pub(crate) created_at: String,
}

/// 审计日志映射结构体
#[derive(serde::Serialize, sqlx::FromRow, Clone)]
pub(crate) struct AuditLog {
    pub(crate) username: Option<String>,
    pub(crate) action: String,
    pub(crate) details: Option<String>,
    pub(crate) ip_address: Option<String>,
    pub(crate) os: Option<String>,
    pub(crate) browser: Option<String>,
    pub(crate) created_at: String,
}

/// 后台用户管理列表项
#[derive(serde::Serialize, sqlx::FromRow, Clone)]
pub(crate) struct AdminUserItem {
    pub(crate) id: i64,
    pub(crate) username: String,
    pub(crate) is_admin: i64,
    pub(crate) created_at: String,
}

/// SMTP 邮件服务配置表单接收模型
#[derive(serde::Deserialize)]
pub(crate) struct SmtpConfigForm {
    pub(crate) smtp_host: String,
    pub(crate) smtp_port: u16,
    pub(crate) smtp_user: String,
    pub(crate) smtp_pass: String,
}

/// 用户状态日志模型
#[derive(Debug, Serialize, Deserialize)]
pub struct UnifiedAuthForm {
    // --- 账号安全凭证 ---
    pub username: String,
    pub password: String,

    // --- 前端无感指纹载荷 ---
    pub client_ip: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

/// 访问端设备快照模型
#[derive(serde::Deserialize, Debug)]
pub(crate) struct ClientDeviceReportForm {
    pub(crate) client_ip: String,
    pub(crate) os: String,
    pub(crate) browser: String,
}
/// 日志编辑日志模型
#[derive(Debug, serde::Deserialize)]
pub struct EditMessageForm {
    // 业务字段
    pub message: String,

    // 感知环境字段（专门留给前端 Hook 填充）
    #[serde(default)]
    pub client_ip: Option<String>,

    #[serde(default)]
    pub os: Option<String>,

    #[serde(default)]
    pub browser: Option<String>,
}

/// 登出日志模型
#[derive(Debug, serde::Deserialize)]
pub struct LogoutQuery {
    pub client_ip: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}