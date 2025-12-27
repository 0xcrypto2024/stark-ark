use std::env;
use anyhow::{Result, Context};
use dotenv::dotenv;

pub struct Config {
    pub rpc_url: String,
    pub keystore_file: String,
    pub strk_contract_address: String,
    pub oz_class_hash: String,
}

impl Config {
    // 加载并检查所有环境变量
    pub fn load() -> Result<Self> {
        // 加载 .env 文件
        dotenv().ok();

        Ok(Self {
            rpc_url: env::var("STARKNET_RPC_URL")
                .context("❌ 未在 .env 中找到 STARKNET_RPC_URL")?,
            
            keystore_file: env::var("KEYSTORE_FILE")
                .unwrap_or_else(|_| "keystore.json".to_string()),
            
            strk_contract_address: env::var("STRK_CONTRACT_ADDRESS")
                .context("❌ 未在 .env 中找到 STRK_CONTRACT_ADDRESS")?,
            
            oz_class_hash: env::var("OZ_CLASS_HASH")
                .context("❌ 未在 .env 中找到 OZ_CLASS_HASH")?,
        })
    }
}