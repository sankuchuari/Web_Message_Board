use ammonia::clean;
use pulldown_cmark::{Options, Parser};
use pulldown_cmark::html::push_html;

// --- Markdown 转 HTML ---
///日志：
///     04.26.2025构建函数
///     05.04.2026修复XSS漏洞
// 修复 XSS：Markdown 转 HTML 后必须经过 ammonia 清洗
pub(crate) fn markdown_to_html(input: &str) -> String {
    let mut html_output = String::new();
    let parser = Parser::new_ext(input, Options::all());
    push_html(&mut html_output, parser);
    // 使用 ammonia 清洗 HTML，防止存储型 XSS
    clean(&html_output)
}