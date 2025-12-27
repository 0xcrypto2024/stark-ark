mod keystore;
mod network;
mod config;
mod i18n;

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
    /// Specify keystore file path
    #[arg(short, long, global = true)]
    keystore: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 📜 List all accounts
    List,
    /// ✨ Create new account
    New,
    /// 💰 Check balance (requires account index)
    Balance {
        #[arg(short, long)]
        index: usize,
    },
    /// 🚀 Activate/Deploy account (requires account index)
    Deploy {
        #[arg(short, long)]
        index: usize,
    },
    /// 💸 Transfer funds
    Transfer {
        /// Sender account index
        #[arg(short, long)]
        from_index: usize,
        /// Recipient address (Hex)
        #[arg(short, long)]
        to: String,
        /// Amount (STRK)
        #[arg(short, long)]
        amount: f64,
    },
    /// 🔑 Export private key (Unsafe!)
    Export {
        #[arg(short, long)]
        index: usize,
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
        println!("{}", cfg.messages.wallet_not_found);
        initialize_new_wallet(&cfg.keystore_file, &cfg.messages)?;
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
    let (keystore, private_keys, password) = load_and_decrypt(&cfg.keystore_file, &cfg.messages)?;

    match cmd {
        Commands::List => {
            println!("{}", cfg.messages.account_list);
            for (i, pk) in private_keys.iter().enumerate() {
                let addr = Keystore::derive_address(pk, &cfg.oz_class_hash)?;
                println!("   [{}] {}", i, addr);
            }
        },
        Commands::New => {
            println!("{}", cfg.messages.generating_new_account);
            // 使用刚才读取到的密码直接加密
            let updated = Keystore::add_new_account(&keystore, &password)?;
            save_keystore(&cfg.keystore_file, &updated)?;
            println!("{}", cfg.messages.new_account_created);
        },
        Commands::Balance { index } => {
            let (addr, _, _) = get_account_info(index, &private_keys, cfg)?;
            let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr).await?;
            let msg = cfg.messages.balance_fmt
                .replace("{index}", &index.to_string())
                .replace("{balance}", &format!("{:.4}", balance));
            println!("{}", msg);
        },
        Commands::Deploy { index } => {
            let (addr, priv_felt, pub_felt) = get_account_info(index, &private_keys, cfg)?;
            println!("{}{}", cfg.messages.activating_account, addr);
            let tx = network::deploy_account(&cfg.rpc_url, &cfg.oz_class_hash, priv_felt, pub_felt, &cfg.messages.network_deploying).await?;
            println!("{}{}", cfg.messages.tx_sent, tx);
        },
        Commands::Transfer { from_index, to, amount } => {
            validate_target_address(to, &cfg.messages)?;
            let (addr, priv_felt, _) = get_account_info(from_index, &private_keys, cfg)?;
            let msg = cfg.messages.sending_transfer_fmt
                .replace("{from}", &from_index.to_string())
                .replace("{amount}", &amount.to_string())
                .replace("{to}", to);
            println!("{}", msg);
            
            let tx = network::transfer_strk(
                &cfg.rpc_url, 
                &cfg.strk_contract_address, 
                &addr, 
                priv_felt, 
                to, 
                *amount,
                (&cfg.messages.network_building_tx, &cfg.messages.network_target_label, &cfg.messages.network_amount_label)
            ).await?;
            println!("{}{}", cfg.messages.transfer_success, tx);
        },
        Commands::Export { index } => {
            if *index >= private_keys.len() {
                println!("{}", cfg.messages.index_out_of_bounds);
                return Ok(());
            }
            println!("{}", cfg.messages.export_warning);
            let pk = &private_keys[*index];
            println!("{}", cfg.messages.export_result_fmt
                .replace("{index}", &index.to_string())
                .replace("{key}", pk));
        }
    }
    Ok(())
}

// 辅助：从索引获取账户信息
fn get_account_info(index: &usize, keys: &[String], cfg: &Config) -> Result<(String, Felt, Felt)> {
    if *index >= keys.len() {
        return Err(anyhow::anyhow!("{}", cfg.messages.index_out_of_bounds));
    }
    let pk_hex = &keys[*index];
    let addr = Keystore::derive_address(pk_hex, &cfg.oz_class_hash)?;
    let priv_felt = Felt::from_hex(pk_hex)?;
    let signer = SigningKey::from_secret_scalar(priv_felt);
    let pub_felt = signer.verifying_key().scalar();
    Ok((addr, priv_felt, pub_felt))
}

fn validate_target_address(addr: &str, msgs: &i18n::Messages) -> Result<()> {
    if !addr.starts_with("0x") {
        return Err(anyhow::anyhow!("{}", msgs.address_must_start_with_0x));
    }
    if addr.len() < 50 {
        return Err(anyhow::anyhow!("{}", msgs.address_too_short));
    }
    Felt::from_hex(addr).map_err(|_| anyhow::anyhow!("{}", msgs.address_invalid_hex))?;
    Ok(())
}

// ==================== 交互模式逻辑 ====================

async fn run_interactive_mode_real(cfg: &Config) -> Result<()> {
    println!("{}", cfg.messages.interactive_welcome);
    println!("===================================");
    
    // 修复点：正确解包 3 个返回值
    let (current_keystore, private_keys, password) = load_and_decrypt(&cfg.keystore_file, &cfg.messages)?;
    println!("{}", cfg.messages.decrypt_success_fmt.replace("{count}", &private_keys.len().to_string()));

    let mut keys = private_keys;
    let mut keystore_obj = current_keystore;
    let pass = password; 

    loop {
        println!("\n{}", cfg.messages.account_list);
        for (i, pk) in keys.iter().enumerate() {
            let addr = Keystore::derive_address(pk, &cfg.oz_class_hash)?;
            println!("   [{}] {}", i, &addr[0..10]);
        }
        println!("   {}", cfg.messages.menu_create_account);
        println!("   {}", cfg.messages.menu_quit);
        
        print!("\n{}", cfg.messages.menu_choice);
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim().to_uppercase();

        if choice == "Q" {
            break;
        } else if choice == "N" {
            println!("{}", cfg.messages.generating_new_account);
            let updated = Keystore::add_new_account(&keystore_obj, &pass)?;
            save_keystore(&cfg.keystore_file, &updated)?;
            // 更新内存状态
            keystore_obj = updated;
            keys = keystore_obj.decrypt(&pass)?; 
            println!("{}", cfg.messages.new_account_created);
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
    println!("\n{}", cfg.messages.account_details_title.replace("{index}", &idx.to_string()));
    println!("{}{}", cfg.messages.address_label, addr);
    
    let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr).await?;
    println!("{}{:.4}", cfg.messages.balance_label, balance);
    
    let deployed = network::is_account_deployed(&cfg.rpc_url, &addr).await?;
    
    // 动态修改操作提示，增加 [E]Export
    println!("{} [E]Export", cfg.messages.operations_label.replace(" [B]Back", ""));
    print!("{}", cfg.messages.menu_choice);
    io::stdout().flush()?;
    let mut c = String::new();
    io::stdin().read_line(&mut c)?;
    match c.trim().to_uppercase().as_str() {
        "T" => {
            if !deployed { println!("{}", cfg.messages.not_activated); return Ok(()); }
            print!("{}", cfg.messages.input_receiver);
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            let to_addr = if let Ok(target_idx) = input.parse::<usize>() {
                if target_idx < all_keys.len() {
                    let target_pk = &all_keys[target_idx];
                    let addr = Keystore::derive_address(target_pk, &cfg.oz_class_hash)?;
                    println!("{}", cfg.messages.selected_local_account
                        .replace("{index}", &target_idx.to_string())
                        .replace("{addr}", &addr));
                    addr
                } else {
                    println!("{}", cfg.messages.index_out_of_bounds);
                    return Ok(());
                }
            } else {
                if let Err(e) = validate_target_address(input, &cfg.messages) {
                    println!("{}", e);
                    return Ok(());
                }
                input.to_string()
            };
            
            print!("{}", cfg.messages.input_amount);
            io::stdout().flush()?;
            let mut amt_s = String::new();
            io::stdin().read_line(&mut amt_s)?;
            let amt: f64 = match amt_s.trim().parse() {
                Ok(f) => f,
                Err(_) => { println!("{}", cfg.messages.amount_invalid); return Ok(()); }
            };
            
            let pk_felt = Felt::from_hex(priv_key)?;
            let tx = network::transfer_strk(&cfg.rpc_url, &cfg.strk_contract_address, &addr, pk_felt, &to_addr, amt, (&cfg.messages.network_building_tx, &cfg.messages.network_target_label, &cfg.messages.network_amount_label)).await?;
            println!("{}{}", cfg.messages.tx_sent, tx);
        },
        "A" => {
            if deployed { println!("{}", cfg.messages.already_activated); return Ok(()); }
            let pk_felt = Felt::from_hex(priv_key)?;
            let signer = SigningKey::from_secret_scalar(pk_felt);
            let pub_felt = signer.verifying_key().scalar();
            let tx = network::deploy_account(&cfg.rpc_url, &cfg.oz_class_hash, pk_felt, pub_felt, &cfg.messages.network_deploying).await?;
            println!("{}{}", cfg.messages.tx_sent, tx);
        },
        "E" => {
            println!("{}", cfg.messages.export_warning);
            println!("{}", cfg.messages.export_result_fmt
                .replace("{index}", &idx.to_string())
                .replace("{key}", priv_key));
        },
        _ => {}
    }
    Ok(())
}

// ==================== 通用辅助函数 ====================

/// 加载并解密，返回 (Keystore对象, 私钥列表, 密码字符串)
fn load_and_decrypt(filepath: &str, msgs: &i18n::Messages) -> Result<(Keystore, Vec<String>, String)> {
    print!("{}", msgs.enter_password);
    io::stdout().flush()?;
    let password = prompt_password()?;

    let content = std::fs::read_to_string(filepath)?;
    let keystore: Keystore = serde_json::from_str(&content)?;
    
    let keys = keystore.decrypt(&password)
        .map_err(|_| anyhow::anyhow!("{}", msgs.password_error))?;
    
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

fn initialize_new_wallet(filename: &str, msgs: &i18n::Messages) -> Result<()> {
    let priv_key = Keystore::generate_new_key();
    println!("{}", msgs.init_new_wallet);
    print!("{}", msgs.set_password);
    io::stdout().flush()?;
    let password = prompt_password()?;
    
    let keys = vec![priv_key];
    let keystore = Keystore::encrypt(&password, &keys)?;
    save_keystore(filename, &keystore)?;
    println!("{}", msgs.wallet_init_complete);
    Ok(())
}