mod keystore;
mod network;
mod config;

use clap::{Parser, Subcommand};
use keystore::Keystore;
use config::Config;
use anyhow::Result;
use std::path::Path;
use std::io::{self, Write};
use starknet::core::types::Felt;
use starknet::signers::SigningKey;

// ==================== CLI 定义 ====================

#[derive(Parser)]
#[command(name = "stark-ark")]
#[command(about = "Starknet CLI Wallet in Rust", long_about = None)]
struct Cli {
    /// 指定 keystore 文件路径
    #[arg(short, long, global = true)]
    keystore: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 📜 列出所有账户
    List,
    /// ✨ 创建新账户
    New,
    /// 💰 查询余额 (需要指定账户序号)
    Balance {
        #[arg(short, long)]
        index: usize,
    },
    /// 🚀 激活/部署账户 (需要指定账户序号)
    Deploy {
        #[arg(short, long)]
        index: usize,
    },
    /// 💸 转账
    Transfer {
        /// 发送方账户序号
        #[arg(short, long)]
        from_index: usize,
        /// 接收方地址 (Hex)
        #[arg(short, long)]
        to: String,
        /// 金额 (STRK)
        #[arg(short, long)]
        amount: f64,
    },
}

// ==================== 主入口 ====================

#[tokio::main]
async fn main() -> Result<()> {
    let mut cfg = Config::load()?;
    let cli = Cli::parse();

    if let Some(path) = cli.keystore {
        cfg.keystore_file = path;
    }

    // 如果没有 keystore，先初始化
    if !Path::new(&cfg.keystore_file).exists() {
        println!("⚠️  未找到钱包文件，正在初始化...");
        initialize_new_wallet(&cfg.keystore_file)?;
    }

    // 根据是否有参数决定运行模式
    match &cli.command {
        Some(cmd) => run_cli_mode(cmd, &cfg).await?,
        None => run_interactive_mode_real(&cfg).await?,
    }

    Ok(())
}

// ==================== CLI 模式逻辑 ====================

async fn run_cli_mode(cmd: &Commands, cfg: &Config) -> Result<()> {
    // 修复点：这里接收 3 个返回值，忽略密码 (_)
    let (keystore, private_keys, password) = load_and_decrypt(&cfg.keystore_file)?;

    match cmd {
        Commands::List => {
            println!("📋 账户列表:");
            for (i, pk) in private_keys.iter().enumerate() {
                let addr = Keystore::derive_address(pk, &cfg.oz_class_hash)?;
                println!("   [{}] {}", i, addr);
            }
        },
        Commands::New => {
            println!("⚙️  正在生成新账户...");
            // 使用刚才读取到的密码直接加密
            let updated = Keystore::add_new_account(&keystore, &password)?;
            save_keystore(&cfg.keystore_file, &updated)?;
            println!("🎉 新账户已创建！");
        },
        Commands::Balance { index } => {
            let (addr, _, _) = get_account_info(index, &private_keys, cfg)?;
            let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr).await?;
            println!("💰 账户 [{}] 余额: {:.4} STRK", index, balance);
        },
        Commands::Deploy { index } => {
            let (addr, priv_felt, pub_felt) = get_account_info(index, &private_keys, cfg)?;
            println!("🚀 正在激活账户: {}", addr);
            let tx = network::deploy_account(&cfg.rpc_url, &cfg.oz_class_hash, priv_felt, pub_felt).await?;
            println!("✅ 交易已发送: {}", tx);
        },
        Commands::Transfer { from_index, to, amount } => {
            validate_target_address(to)?;
            let (addr, priv_felt, _) = get_account_info(from_index, &private_keys, cfg)?;
            println!("💸 正在从 [{}] 发送 {} STRK 到 {}", from_index, amount, to);
            let tx = network::transfer_strk(
                &cfg.rpc_url, 
                &cfg.strk_contract_address, 
                &addr, 
                priv_felt, 
                to, 
                *amount
            ).await?;
            println!("✅ 转账成功: {}", tx);
        }
    }
    Ok(())
}

// 辅助：从索引获取账户信息
fn get_account_info(index: &usize, keys: &[String], cfg: &Config) -> Result<(String, Felt, Felt)> {
    if *index >= keys.len() {
        return Err(anyhow::anyhow!("索引越界！你有 {} 个账户，最大索引是 {}", keys.len(), keys.len() - 1));
    }
    let pk_hex = &keys[*index];
    let addr = Keystore::derive_address(pk_hex, &cfg.oz_class_hash)?;
    let priv_felt = Felt::from_hex(pk_hex)?;
    let signer = SigningKey::from_secret_scalar(priv_felt);
    let pub_felt = signer.verifying_key().scalar();
    Ok((addr, priv_felt, pub_felt))
}

fn validate_target_address(addr: &str) -> Result<()> {
    if !addr.starts_with("0x") {
        return Err(anyhow::anyhow!("❌ 地址必须以 0x 开头"));
    }
    if addr.len() < 50 {
        return Err(anyhow::anyhow!("❌ 地址长度过短，请检查是否完整"));
    }
    Felt::from_hex(addr).map_err(|_| anyhow::anyhow!("❌ 地址格式无效 (非 Hex)"))?;
    Ok(())
}

// ==================== 交互模式逻辑 ====================

async fn run_interactive_mode_real(cfg: &Config) -> Result<()> {
    println!("🚀 StarkArk CLI Wallet (Interactive)");
    println!("===================================");
    
    // 修复点：正确解包 3 个返回值
    let (current_keystore, private_keys, password) = load_and_decrypt(&cfg.keystore_file)?;
    println!("✅ 解密成功！当前管理 {} 个账户。", private_keys.len());

    let mut keys = private_keys;
    let mut keystore_obj = current_keystore;
    let pass = password; 

    loop {
        println!("\n📋 账户列表:");
        for (i, pk) in keys.iter().enumerate() {
            let addr = Keystore::derive_address(pk, &cfg.oz_class_hash)?;
            println!("   [{}] {}", i, &addr[0..10]);
        }
        println!("   [N] ✨ 创建新账户");
        println!("   [Q] 🚪 退出");
        
        print!("\n👉 选择: ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim().to_uppercase();

        if choice == "Q" {
            break;
        } else if choice == "N" {
            println!("⚙️  生成新账户...");
            let updated = Keystore::add_new_account(&keystore_obj, &pass)?;
            save_keystore(&cfg.keystore_file, &updated)?;
            // 更新内存状态
            keystore_obj = updated;
            keys = keystore_obj.decrypt(&pass)?; 
            println!("🎉 成功！");
        } else if let Ok(index) = choice.parse::<usize>() {
            if index < keys.len() {
                // 进入单账户操作
                if let Err(e) = process_single_account_interactive(&keys[index], index, &keys, cfg).await {
                    println!("❌ 错误: {}", e);
                }
            }
        }
    }
    Ok(())
}

// 交互模式下的单账户操作
async fn process_single_account_interactive(
    priv_key: &str, 
    idx: usize, 
    all_keys: &[String],
    cfg: &Config
) -> Result<()> {
    let addr = Keystore::derive_address(priv_key, &cfg.oz_class_hash)?;
    println!("\n--- 账户 [{}] ---", idx);
    println!("📍 地址: {}", addr);
    
    let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr).await?;
    println!("💰 余额: {:.4}", balance);
    
    let deployed = network::is_account_deployed(&cfg.rpc_url, &addr).await?;
    
    println!("操作: [T]转账 [A]激活 [B]返回");
    print!("👉 ");
    io::stdout().flush()?;
    let mut c = String::new();
    io::stdin().read_line(&mut c)?;
    match c.trim().to_uppercase().as_str() {
        "T" => {
            if !deployed { println!("未激活！"); return Ok(()); }
            print!("接收地址 (输入 Hex 地址或本地账户序号): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            let to_addr = if let Ok(target_idx) = input.parse::<usize>() {
                if target_idx < all_keys.len() {
                    let target_pk = &all_keys[target_idx];
                    let addr = Keystore::derive_address(target_pk, &cfg.oz_class_hash)?;
                    println!("   -> 选中本地账户 [{}]: {}", target_idx, addr);
                    addr
                } else {
                    println!("❌ 索引越界！最大索引是 {}", all_keys.len() - 1);
                    return Ok(());
                }
            } else {
                if let Err(e) = validate_target_address(input) {
                    println!("{}", e);
                    return Ok(());
                }
                input.to_string()
            };
            
            print!("金额: ");
            io::stdout().flush()?;
            let mut amt_s = String::new();
            io::stdin().read_line(&mut amt_s)?;
            let amt: f64 = match amt_s.trim().parse() {
                Ok(f) => f,
                Err(_) => { println!("金额无效"); return Ok(()); }
            };
            
            let pk_felt = Felt::from_hex(priv_key)?;
            let tx = network::transfer_strk(&cfg.rpc_url, &cfg.strk_contract_address, &addr, pk_felt, &to_addr, amt).await?;
            println!("✅ Hash: {}", tx);
        },
        "A" => {
            if deployed { println!("已激活"); return Ok(()); }
            let pk_felt = Felt::from_hex(priv_key)?;
            let signer = SigningKey::from_secret_scalar(pk_felt);
            let pub_felt = signer.verifying_key().scalar();
            let tx = network::deploy_account(&cfg.rpc_url, &cfg.oz_class_hash, pk_felt, pub_felt).await?;
            println!("✅ Hash: {}", tx);
        },
        _ => {}
    }
    Ok(())
}

// ==================== 通用辅助函数 ====================

/// 加载并解密，返回 (Keystore对象, 私钥列表, 密码字符串)
fn load_and_decrypt(filepath: &str) -> Result<(Keystore, Vec<String>, String)> {
    print!("🔑 请输入密码解锁: ");
    io::stdout().flush()?;
    let password = prompt_password()?;

    let content = std::fs::read_to_string(filepath)?;
    let keystore: Keystore = serde_json::from_str(&content)?;
    
    let keys = keystore.decrypt(&password)
        .map_err(|_| anyhow::anyhow!("❌ 密码错误！"))?;
    
    Ok((keystore, keys, password))
}

fn prompt_password() -> Result<String> {
    Ok(rpassword::read_password()?.trim().to_string())
}

fn save_keystore(filepath: &str, keystore: &Keystore) -> Result<()> {
    let json = serde_json::to_string_pretty(keystore)?;
    std::fs::write(filepath, json)?;
    Ok(())
}

fn initialize_new_wallet(filename: &str) -> Result<()> {
    let priv_key = Keystore::generate_new_key();
    println!("🛡️ 初始化新钱包...");
    print!("请设置密码: ");
    io::stdout().flush()?;
    let password = prompt_password()?;
    
    let keys = vec![priv_key];
    let keystore = Keystore::encrypt(&password, &keys)?;
    save_keystore(filename, &keystore)?;
    println!("🎉 钱包初始化完成！");
    Ok(())
}