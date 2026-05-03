# 🚀 Rust Glassy Message Board (PWA)

一个基于 **Rust + Actix-web** 构建的极简毛玻璃风格留言板系统。支持多媒体上传、Markdown 渲染、多语言切换，并具备完整 PWA 原生应用体验。

---

## ✨ 功能特性

* 🎨 毛玻璃（Glassmorphism）UI + 深色模式
* 🌍 中英文双语切换（i18n）
* 📱 PWA 支持（可安装为桌面/手机应用）
* 📝 Markdown 留言渲染
* 📁 图片 / 视频 / 音频上传与预览
* 💾 SQLite 数据持久化
* 🛠️ 自适应输入框（聊天式体验）

---

## 🛠️ 技术栈

**后端 (Backend)**
*   **Rust**: 核心逻辑处理
*   **Actix-web**: 高性能异步 Web 框架
*   **SQLx + SQLite**: 异步数据库操作与持久化
*   **Argon2**: 工业级密码哈希加密
*   **Actix-session**: 基于 Cookie 的加密会话控制

**前端 (Frontend)**
*   **JavaScript**: 原生异步交互 (Fetch API)
*   **Maud**: 强类型 HTML 模板引擎
*   **CSS3**: Flexbox 布局 + Keyframes 动画（无外部依赖）

**PWA**

* manifest.json
* Service Worker

---
## ⚙️ 核心设计说明

### 📌 1. 交互设计：10秒智能平滑弹窗
项目弃用了传统的页面重定向反馈，采用 CSS3 `keyframes` 实现非阻塞式提醒。
- **触发机制**：通过 JavaScript 拦截表单提交，根据后端返回的 HTTP 状态码（200/401/404）触发。
- **动画表现**：弹窗从浏览器底沿平滑弹出，并在 10 秒后自动向下收回，确保用户有充足时间阅读反馈信息而不中断浏览体验。

### 📌 2. 安全与存储策略
- **身份验证**：数据库严禁存储明文密码，统一使用 Argon2 进行单向高强度哈希。
- **会话持久化**：使用加密 Cookie 维护登录状态，确保留言板的“发布”与“删除”功能仅对合法所有者开放。
- **IO 安全**：对所有上传的文件名进行 `sanitize` 过滤，并使用 UUID 重新命名，彻底杜绝路径穿越攻击。

### 📌 3. PWA 原生化
- 通过 `manifest.json` 定义应用色彩与图标。
- 配置 Service Worker 确保应用在移动端具备独立运行的能力，提升加载性能。

---

## 🚀 快速开始

### 1️⃣ 安装环境

确保已安装：

* Rust（stable）
* Cargo

---

### 2️⃣ 克隆项目

git clone https://github.com/sankuchuari/Web_Message_Board.git
cd Web_Message_Board

---

### 3️⃣ 运行项目

cargo run

---

### 4️⃣ 打开浏览器

http://localhost:6790

---

## 📁 项目结构

.
├── main.rs  
├── Cargo.toml  
├── guestbook.db  
│  
├── static/  
│   ├── back_image.png  
│   ├── manifest.json  
│   ├── sw.js  
│   ├── icon-64x64.ico  
│   │  
│   └── icons/  
│       ├── icon-192x192.png  
│       └── icon-512x512.png  
│  
└── uploads/  

---

## ⚙️ 配置说明

### 📌 PWA 配置（static/manifest.json）

{
"name": "Message Board",
"short_name": "MsgBoard",
"start_url": "/",
"display": "standalone",
"background_color": "#121212",
"theme_color": "#121212",
"icons": [
{
"src": "/static/icons/icon-192x192.png",
"sizes": "192x192",
"type": "image/png"
},
{
"src": "/static/icons/icon-512x512.png",
"sizes": "512x512",
"type": "image/png"
}
]
}

---

### 📌 Service Worker（static/sw.js）

self.addEventListener('fetch', function(event) {
// 空实现即可启用 PWA 安装
});

---

## 📱 安装方式

### 💻 桌面端（Chrome / Edge）

* 打开网站
* 点击地址栏安装按钮

### 📱 移动端

**Android**

* 添加到主屏幕

**iOS**

* Safari → 分享 → 添加到主屏幕

---

## 📦 项目亮点

* 🚀 Rust 高性能后端
* 🎨 Glassmorphism 现代 UI
* 📱 PWA 原生应用体验
* 📝 Markdown 即时渲染
* 📁 多媒体留言系统
* 💾 SQLite 本地持久化
