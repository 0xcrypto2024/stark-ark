use std::env;
use anyhow::{Result, Context};
use dotenv::{dotenv, from_path};
use crate::i18n::Messages;

pub struct Config {
    pub rpc_url: String,
    pub keystore_file: String,
    pub strk_contract_address: String,
    pub oz_class_hash: String,
    pub messages: Messages,
}

impl Config {
    // 加载并检查所有环境变量
    pub fn load() -> Result<Self> {
        // 加载 .env 文件
        // 1. 尝试从当前工作目录加载
        dotenv().ok();

        // 2. 尝试从可执行文件所在目录加载 (解决在其他目录运行 binary 时找不到 .env 的问题)
        if let Ok(exe_path) = env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                from_path(exe_dir.join(".env")).ok();
            }
        }

        // 优先读取 APP_LANGUAGE，防止与系统 LANGUAGE 环境变量冲突
        let lang = env::var("APP_LANGUAGE")
            .or_else(|_| env::var("LANGUAGE"))
            .unwrap_or_else(|_| "en".to_string());

        let messages = if lang == "zh" {
            Self::load_messages(&lang).unwrap_or_else(|_| Messages::default_zh())
        } else {
            // 默认英文
            Self::load_messages(&lang).unwrap_or_else(|_| Messages::default())
        };

        Ok(Self {
            rpc_url: env::var("STARKNET_RPC_URL")
                .context("❌ 未在 .env 中找到 STARKNET_RPC_URL")?,
            
            keystore_file: env::var("KEYSTORE_FILE")
                .unwrap_or_else(|_| "keystore.json".to_string()),
            
            strk_contract_address: env::var("STRK_CONTRACT_ADDRESS")
                .context("❌ 未在 .env 中找到 STRK_CONTRACT_ADDRESS")?,
            
            oz_class_hash: env::var("OZ_CLASS_HASH")
                .context("❌ 未在 .env 中找到 OZ_CLASS_HASH")?,
            
            messages,
        })
    }

    fn load_messages(lang: &str) -> Result<Messages> {
        let content = std::fs::read_to_string(format!("i18n/{}.json", lang))?;
        let m: Messages = serde_json::from_str(&content)?;
        Ok(m)
    }
}