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

**Backend**

* Rust
* Actix-web
* SQLx
* SQLite

**Frontend**

* 原生 JavaScript
* CSS（无框架）
* Maud 模板

**PWA**

* manifest.json
* Service Worker

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
