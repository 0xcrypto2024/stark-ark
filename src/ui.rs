use serde::Serialize;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

pub static JSON_MODE: AtomicBool = AtomicBool::new(false);

/// 设置全局 JSON 模式
pub fn set_json_mode(enable: bool) {
    JSON_MODE.store(enable, Ordering::Relaxed);
}

/// 检查是否处于 JSON 模式
pub fn is_json_mode() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// 打印 ASCII Banner
pub fn print_banner() {
    if is_json_mode() { return; }
    
    let banner = r#"
   _____ __             __      ___       __
  / ___// /_____ ______/ /__   /   | ____/ /__
  \__ \/ __/ __ `/ ___/ //_/  / /| |/ __/ //_/
 ___/ / /_/ /_/ / /  / ,<    / ___ / / / ,<
/____/\__/\__,_/_/  /_/|_|  /_/  |_\/_/_/|_|
    "#;
    println!("{}", banner.bright_cyan().bold());
    println!("{}", "   Secure Starknet Wallet CLI  ".italic().dimmed());
    println!();
}

/// 打印普通信息步骤
pub fn print_step(msg: &str) {
    if is_json_mode() { return; }
    println!("{} {}", "ℹ️ ".blue(), msg);
}

/// 打印成功信息
pub fn print_success(msg: &str) {
    if is_json_mode() { return; }
    println!("{} {}", "✅".green(), msg.bold());
}

/// 打印错误信息
pub fn print_error(msg: &str) {
    // 即使在 JSON 模式下，如果不是结构化错误输出，可能也需要打印到 stderr
    if is_json_mode() {
         eprintln!("Error: {}", msg);
    } else {
        println!("{} {}", "❌".red(), msg.bold());
    }
}

/// 打印警告信息
pub fn print_warning(msg: &str) {
    if is_json_mode() { return; }
    println!("{} {}", "⚠️ ".yellow(), msg);
}

/// 运行带 Spinner 的任何异步任务
pub async fn with_spinner<F, T>(msg: &str, future: F) -> T
where
    F: Future<Output = T>,
{
    if is_json_mode() {
        return future.await;
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let result = future.await;

    pb.finish_and_clear();
    result
}

/// 统一输出结果 (JSON 或 文本)
pub fn print_output<T: Serialize + std::fmt::Display>(data: &T) {
    if is_json_mode() {
        match serde_json::to_string(data) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("JSON Serialization Error: {}", e),
        }
    } else {
        println!("{}", data);
    }
}

/// 仅用于 JSON 输出的数据包装器
pub fn print_json_obj<T: Serialize>(data: &T) {
     if is_json_mode() {
        match serde_json::to_string(data) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("JSON Serialization Helper Error: {}", e),
        }
    }
}
