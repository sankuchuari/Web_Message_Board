import sqlite3
import os

db_path = "./static/guestbook.db"

try:
    if os.path.exists(db_path):
        os.remove(db_path)
except:
    pass

conn = sqlite3.connect(db_path)
cur = conn.cursor()

schema = """
-- 1. 核心业务：留言板消息表
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    message      TEXT NOT NULL,
    raw_message  TEXT NOT NULL,
    image_path   TEXT,
    video_path   TEXT,
    created_at   TEXT DEFAULT (datetime('now', 'localtime'))
);

-- 2. 安全核心：全新架构的审计日志表（支持前端钩子精准分列）
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT,                              -- 操作用户（允许为NULL，代表系统或游客）
    action      TEXT NOT NULL,                     -- 行为名称
    details     TEXT,                              -- 详情描述
    ip_address  TEXT,                              -- 📍 纯前端钩子捕获的真实公网IP
    os          TEXT,                              -- 🖥️ 纯前端钩子解析的操作系统
    browser     TEXT,                              -- 🌐 纯前端钩子解析的浏览器内核
    created_at  TEXT DEFAULT (datetime('now', 'localtime')) -- 自动生成本地时间
);

-- 3. 运维配置：SMTP 发信中继表
CREATE TABLE IF NOT EXISTS smtp_config (
    id        INTEGER PRIMARY KEY CHECK (id = 1), -- 保证只有单条全局配置
    smtp_host TEXT NOT NULL,
    smtp_port INTEGER NOT NULL,
    encryption TEXT NOT NULL,
    username  TEXT NOT NULL,
    password  TEXT NOT NULL
);

-- 4. 权限核心：全局用户权限表
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    is_admin   INTEGER DEFAULT 0 -- 1代表管理员，0代表普通用户
);
"""

cur.executescript(schema)

conn.commit()
conn.close()

print("SQLite database generated successfully.")
print(db_path)
