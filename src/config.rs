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

        // 3. 尝试从用户配置目录加载 (例如 ~/.config/stark-ark/.env)
        if let Some(proj_dirs) = directories::ProjectDirs::from("", "", "stark-ark") {
            let config_dir = proj_dirs.config_dir();
            from_path(config_dir.join(".env")).ok();
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

    // 查找当前生效的配置文件路径
    pub fn find_active_config_path() -> Option<std::path::PathBuf> {
        // 1. 当前目录
        if let Ok(p) = std::env::current_dir() {
            let current = p.join(".env");
            if current.exists() { return Some(current); }
        }

        // 2. 可执行文件目录
        if let Ok(exe_path) = env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let exe_config = exe_dir.join(".env");
                if exe_config.exists() { return Some(exe_config); }
            }
        }

        // 3. 用户配置目录
        if let Some(proj_dirs) = directories::ProjectDirs::from("", "", "stark-ark") {
            let config_dir = proj_dirs.config_dir();
            let user_config = config_dir.join(".env");
            if user_config.exists() { return Some(user_config); }
        }

        None
    }

    pub fn get_default_config_path() -> Result<std::path::PathBuf> {
        let proj_dirs = directories::ProjectDirs::from("", "", "stark-ark")
            .ok_or_else(|| anyhow::anyhow!("无法获取系统配置目录"))?;
        
        let config_dir = proj_dirs.config_dir();
        std::fs::create_dir_all(config_dir)?;
        
        Ok(config_dir.join(".env"))
    }

    pub fn write_default_config(path: &std::path::Path) -> Result<()> {
        let content = r#"# ================= 配置中心 =================

# 1. RPC 节点地址 (请填入你的 Alchemy v0.10 URL)
STARKNET_RPC_URL=
# 2. 钱包存储文件名
KEYSTORE_FILE=keystore.json

# 3. STRK 代币合约地址 (Sepolia)
STRK_CONTRACT_ADDRESS=0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d

# 4. OpenZeppelin 账户合约 Class Hash (v0.8.1)
# ⚠️ 注意：修改此值会改变派生的钱包地址！
OZ_CLASS_HASH=0x061dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f
LANGUAGE=en
"#;
        
        std::fs::write(path, content)?;
        Ok(())
    }
}