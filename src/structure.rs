// --- 数据结构 ---

/// 存储在数据库中的留言信息结构体
struct StoredMessage {
    //日志ID
    id: i64,
    //用户名
    name: String,
    //渲染后的HTML文本内容
    message: String,
    //原始Markdown源码
    raw_message: String,
    //图片UUID
    image_path: Option<String>,
    //视频&其他媒体UUID
    video_path: Option<String>,
    //时间戳
    created_at: String,
}

/// 登录与注册表单接收模型
#[derive(serde::Deserialize)]
struct AuthForm {
    username: String,
    password: String,
}

/// 消息编辑表单接收模型
#[derive(serde::Deserialize)]
struct EditForm {
    message: String,
}