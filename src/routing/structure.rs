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

/// 登录与注册表单接收模型
#[derive(serde::Deserialize)]
pub(crate) struct AuthForm {
    pub(crate) username: String,
    pub(crate) password: String,
}

/// 消息编辑表单接收模型
#[derive(serde::Deserialize)]
pub(crate)struct EditForm {
    pub(crate) message: String,
}