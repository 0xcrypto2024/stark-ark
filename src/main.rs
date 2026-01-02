use comfy_table::{Table, presets::UTF8_FULL, Cell, Color, Attribute}; // Added comfy_table
use clap::{Parser, Subcommand};
use stark_ark::keystore::{Keystore, AccountConfig};
use stark_ark::config::Config;
use stark_ark::network;
use stark_ark::i18n;
use stark_ark::backup::GoogleDriveBackend;
use stark_ark::ui;
use anyhow::Result;
use std::path::Path;
use std::io::{self, Write};
use chrono::{Utc, TimeZone}; // Added chrono
use starknet::core::types::Felt;
use serde_json::json;
use starknet::signers::SigningKey;
use qrcode::QrCode;
use qrcode::render::unicode;
use inquire::{Password, Select};
use std::env;
use stark_ark::avnu::{AvnuClient, AvnuNetwork, Token};

use starknet::providers::Provider;

// ==================== CLI 定义 ====================

#[derive(Parser)]
#[command(name = "stark-ark")]
#[command(about = "Starknet CLI Wallet in Rust", long_about = None)]
struct Cli {
    /// Specify keystore file path
    #[arg(short, long, global = true)]
    keystore: Option<String>,

    /// Output JSON instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

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
    /// 📥 Import account
    Import {
        /// Private Key (Hex) or JSON Config
        #[arg(short, long)]
        key: Option<String>,
    },
    /// 📤 Distribute funds from one account to many
    Distribute {
        /// Sender account index
        #[arg(short, long)]
        from_index: usize,
        /// Start index of recipient accounts
        #[arg(long)]
        start_index: usize,
        /// End index of recipient accounts (inclusive)
        #[arg(long)]
        end_index: usize,
        /// Amount per recipient (STRK)
        #[arg(short, long)]
        amount: f64,
    },
    /// 🧹 Sweep funds from many accounts to one
    Sweep {
        /// Start index of source accounts
        #[arg(long)]
        start_index: usize,
        /// End index of source accounts (inclusive)
        #[arg(long)]
        end_index: usize,
        /// Recipient account index
        #[arg(short, long)]
        to_index: usize,
    },
    /// ⚙️ Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigSubcommands,
    },
    /// ℹ️ Show version information
    Version,
    /// 🔍 View validators information
    Validators,
    /// 🥩 Stake STRK to a validator
    Stake {
        /// Account index to stake from
        #[arg(short, long)]
        index: usize,
        /// Validator Address (Staker Address) - Optional, will prompt/use default if missing
        #[arg(long)]
        validator: Option<String>,
        /// Amount to stake - Optional, will prompt if missing
        #[arg(short, long)]
        amount: Option<f64>,
    },
    /// 📉 Unstake funds (Signal Intent)
    Unstake {
        /// Account index
        #[arg(short, long)]
        index: usize,
        /// Validator Address (Optional)
        #[arg(long)]
        validator: Option<String>,
        /// Amount to unstake
        #[arg(short, long)]
        amount: Option<f64>,
    },
    /// 💸 Withdraw unstaked funds (Action)
    Withdraw {
        /// Account index
        #[arg(short, long)]
        index: usize,
        /// Validator Address (Optional)
        #[arg(long)]
        validator: Option<String>,
    },
    /// 📊 Overview of all accounts
    Overview,
    /// ☁️  Backup keystore to Google Drive
    Backup,
    /// ☁️  Restore keystore from Google Drive
    Restore,
    /// 💱 Swap Tokens (AVNU)
    Swap {
        /// Sell Token Address
        #[arg(short, long)]
        sell: String,
        /// Buy Token Address
        #[arg(short, long)]
        buy: String,
        /// Amount to Sell
        #[arg(short, long)]
        amount: f64,
        /// Max Slippage (default 0.005)
        #[arg(long, default_value = "0.005")]
        slippage: f64,
        /// Account index
        #[arg(long)]
        index: usize,
    },
    /// 🪙 List Supported Tokens (AVNU)
    Tokens,
    /// 🤖 Run MCP Server (AI Agent Mode)
    Mcp,
}

#[derive(Subcommand)]
enum ConfigSubcommands {
    /// 📝 Initialize default .env configuration
    Init,
    /// 🔍 Show current configuration
    Show,
}

// ==================== 主入口 ====================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle Version command
    if let Some(Commands::Version) = &cli.command {
        println!("StarkArk v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // 优先处理 Config 命令 (不需要加载 Config)
    if let Some(Commands::Config { command }) = &cli.command {
        match command {
            ConfigSubcommands::Init => {
                let path = Config::get_default_config_path()?;
                if path.exists() {
                    print!("⚠️  Configuration file already exists at {:?}.\nOverwrite? [y/N]: ", path);
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if input.trim().to_lowercase() != "y" {
                        println!("🚫 Aborted.");
                        return Ok(());
                    }
                }
                Config::write_default_config(&path)?;
                println!("✅ Configuration initialized at: {:?}", path);
                return Ok(());
            },
            ConfigSubcommands::Show => {
                if let Some(path) = Config::find_active_config_path() {
                    println!("📂 Active Configuration File: {:?}", path);
                    match Config::load() {
                        Ok(cfg) => {
                            println!("--------------------------------");
                            println!("RPC URL:      {}", cfg.rpc_url);
                            println!("Keystore:     {}", cfg.keystore_file);
                            println!("STRK Contract:{}", cfg.strk_contract_address);
                            println!("Class Hash:   {}", cfg.oz_class_hash);
                            println!("--------------------------------");
                        }
                        Err(e) => println!("❌ Failed to load configuration: {}", e),
                    }
                } else {
                    println!("❌ No active .env configuration found.\n   Searched in: Current Dir, Executable Dir, User Config Dir");
                }
                return Ok(());
            }
        }
    }

    let mut cfg = Config::load()?;

    // 1. 初始化 UI 模式
    ui::set_json_mode(cli.json);
    
    // Check if we are running in MCP mode
    let is_mcp = matches!(cli.command, Some(Commands::Mcp));
    
    // Only print banner if NOT in MCP mode
    if !is_mcp {
        ui::print_banner();
    }

    if let Some(path) = cli.keystore {
        cfg.keystore_file = path;
    }

    // 如果没有 keystore且不是 Restore 命令，先初始化
    let is_restore = matches!(cli.command, Some(Commands::Restore));
    if !is_restore && !Path::new(&cfg.keystore_file).exists() {
        println!("{}", cfg.messages.wallet_not_found);
        initialize_new_wallet(&cfg.keystore_file, &cfg.messages)?;
    }

    // 根据是否有参数决定运行模式
    match &cli.command {
        Some(cmd) => run_cli_mode(cmd, &cfg).await?,
        None => run_interactive_mode_real(&mut cfg).await?,
    }

    Ok(())
}



async fn show_overview_table(accounts: &[AccountConfig], cfg: &Config) -> Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Idx").add_attribute(Attribute::Bold),
            Cell::new("Address").add_attribute(Attribute::Bold),
            Cell::new("Alias").add_attribute(Attribute::Bold),
            Cell::new("Balance").add_attribute(Attribute::Bold),
            Cell::new("Staked").add_attribute(Attribute::Bold),
            Cell::new("Pending").add_attribute(Attribute::Bold),
            Cell::new("Total").add_attribute(Attribute::Bold),
        ]);

    println!("Fetching data for {} accounts...", accounts.len());

    for (i, acc) in accounts.iter().enumerate() {
        let addr = Keystore::compute_address(acc, &cfg.oz_class_hash)?;
        // Short address format: 0x1234...5678
        let short_addr = if addr.len() > 10 {
            format!("{}...{}", &addr[0..6], &addr[addr.len()-4..])
        } else {
            addr.clone()
        };
        
        let alias = acc.alias.clone().unwrap_or_default();
        
        // Fetch Balance
        let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr).await.unwrap_or(0.0);
        
        // Fetch Staked Info
        let mut staked = 0.0;
        let mut pending = 0.0;
        
        if !cfg.default_staker_address.is_empty() {
             if let Ok(pool_addr) = network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &cfg.default_staker_address).await {
                 if let Ok(info) = network::get_account_pool_info(&cfg.rpc_url, &pool_addr, &addr).await {
                     staked = info.staked_amount;
                     pending = info.unpool_amount;
                 }
             }
        }
        
        let total = balance + staked + pending;
        
        table.add_row(vec![
            Cell::new(i.to_string()),
            Cell::new(short_addr),
            Cell::new(alias),
            Cell::new(format!("{:.4}", balance)),
            Cell::new(format!("{:.4}", staked)).fg(if staked > 0.0 { Color::Green } else { Color::White }),
            Cell::new(format!("{:.4}", pending)).fg(if pending > 0.0 { Color::Yellow } else { Color::White }),
            Cell::new(format!("{:.4}", total)),
        ]);
        
        // Small delay/yield not really needed for sequential but keeps UI responsive-ish if printed incrementally? 
        // No, table prints at end.
    }

    println!("{table}");
    Ok(())
}

// ==================== CLI 模式逻辑 ====================

async fn run_cli_mode(cmd: &Commands, cfg: &Config) -> Result<()> {
    // 0. 处理不需要钱包解锁的命令
    match cmd {
        Commands::Config { .. } | Commands::Version => { return Ok(()); },
        Commands::Mcp => {
             let password = cfg.password.clone()
                .or_else(|| env::var("STARK_ARK_PASSWORD").ok())
                .ok_or_else(|| anyhow::anyhow!("STARK_ARK_PASSWORD environment variable is required for MCP mode."))?;

             let keystore = Keystore::load(&cfg.keystore_file)?;
             let accounts = keystore.decrypt(&password)?;
             
             if accounts.is_empty() {
                return Err(anyhow::anyhow!("No accounts found. Please create one using 'new' or 'import' first via CLI."));
            }
            
            let server = std::sync::Arc::new(stark_ark::mcp::McpServer::new(cfg.clone(), accounts));
            eprintln!("🤖 StarkArk MCP Server Started.");
            eprintln!("📍 Serving Address: {}", server.account_address());
            
            if let Err(e) = server.run().await {
                eprintln!("❌ MCP Server Error: {}", e);
            }
            return Ok(());
        },
        Commands::Tokens => {
            let network = if cfg.rpc_url.contains("sepolia") { AvnuNetwork::Sepolia } else { AvnuNetwork::Mainnet };
            let client = AvnuClient::new(network);
            println!("Fetching tokens from AVNU ({:?})...", network);
            match client.get_tokens().await {
                Ok(tokens) => {
                     let mut table = Table::new();
                    table.load_preset(UTF8_FULL).set_header(vec!["Symbol", "Name", "Address", "Decimals"]);
                    for t in tokens {
                        table.add_row(vec![
                            t.symbol,
                            t.name,
                            t.address,
                            t.decimals.to_string()
                        ]);
                    }
                    println!("{table}");
                },
                Err(e) => println!("Error fetching tokens: {}", e),
            }
            return Ok(());
        },
        Commands::Validators => {
            println!("Please visit https://sepolia.voyager.online/validators to view active validators and their performance.");
            if !cfg.default_staker_address.is_empty() {
                println!("\n✅ Configured Default Staker: {}", cfg.default_staker_address);
                println!("You can use this default staker for the 'stake' command, or choose a different one from the explorer.");
            } else {
                println!("You will need a Validator Address (Staker Address) to delegate your funds.");
            }
            return Ok(());
        },
        Commands::Restore => {
            println!("☁️  Starting Google Drive Restore...");
            let client_id = cfg.google_client_id.as_deref().ok_or_else(|| anyhow::anyhow!("Missing GOOGLE_CLIENT_ID in .env"))?.to_string();
            let client_secret = cfg.google_client_secret.as_deref().ok_or_else(|| anyhow::anyhow!("Missing GOOGLE_CLIENT_SECRET in .env"))?.to_string();

            let backend = GoogleDriveBackend::new(client_id, client_secret).await?;
            println!("🔐 Authenticated. Fetching backups...");

            let backups = backend.list_backups().await?;
            if backups.is_empty() {
                println!("⚠️  No 'keystore' backups found in Google Drive.");
                return Ok(());
            }

            println!("📋 Available Backups:");
            for (i, (_id, name, time)) in backups.iter().enumerate() {
                println!("   [{}] {} (Created: {})", i, name, time);
            }

            print!("👉 Select backup to restore (index): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let index = input.trim().parse::<usize>()?;

            if index >= backups.len() {
                println!("❌ Invalid index.");
                return Ok(());
            }

            let (file_id, name, _) = &backups[index];
            println!("📥 Downloading '{}'...", name);
            
            let target_path = Path::new(&cfg.keystore_file);
            if target_path.exists() {
                 print!("⚠️  Local keystore exists. Overwrite? [y/N]: ");
                 io::stdout().flush()?;
                 let mut confirm = String::new();
                 io::stdin().read_line(&mut confirm)?;
                 if confirm.trim().to_lowercase() != "y" {
                     println!("🚫 Aborted.");
                     return Ok(());
                 }
            }

            backend.download_file(file_id, target_path).await?;
            println!("✅ Restore successful! Saved to: {:?}", target_path);
            return Ok(());
        },
        _ => {}
    }

    // 1. 加载并解密钱包 (仅针对需要操作账户的命令)
    let (keystore, accounts, password) = load_and_decrypt(&cfg.keystore_file, &cfg.messages)?;

    match cmd {
        Commands::List => {
            println!("{}", cfg.messages.account_list);
            for (i, acc) in accounts.iter().enumerate() {
                let addr = Keystore::compute_address(acc, &cfg.oz_class_hash)?;
                let alias_suffix = acc.alias.as_ref().map(|a| format!(" ({})", a)).unwrap_or_default();
                println!("   [{}] {}{}", i, addr, alias_suffix);
            }
        },
        Commands::New => {
            println!("{}", cfg.messages.generating_new_account);
            
            let new_account = AccountConfig {
                private_key: Keystore::generate_new_key(),
                salt: None, // 默认使用公钥
                class_hash: Some(cfg.oz_class_hash.clone()), // 绑定当前环境的 Class Hash
                alias: None,
                address: None, // 可以选择在这里计算并缓存
            };

            let updated = Keystore::add_account(&keystore, &password, new_account)?;
            save_keystore(&cfg.keystore_file, &updated)?;
            println!("{}", cfg.messages.new_account_created);
        },
        Commands::Balance { index } => {
            let (addr, _, _) = get_account_info(index, &accounts, cfg)?;
            
            // AI/Human: Fetching data
            let balance = ui::with_spinner(&format!("Fetching balance for account {}...", index), network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr)).await?;
            
            if ui::is_json_mode() {
                 ui::print_json_obj(&json!({
                    "index": index,
                    "address": addr,
                    "balance": balance,
                    "unit": "STRK"
                 }));
                 return Ok(());
            }

            let msg = cfg.messages.balance_fmt
                .replace("{index}", &index.to_string())
                .replace("{balance}", &format!("{:.4}", balance));
            println!("{}", msg);

            // Check Staked Balance if default staker is configured
            if !cfg.default_staker_address.is_empty() {
                // Silently attempt to resolve pool and get balance
                if let Ok(pool_addr) = network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &cfg.default_staker_address).await {
                     match network::get_account_pool_info(&cfg.rpc_url, &pool_addr, &addr).await {
                         Ok(info) => {
                             if info.staked_amount > 0.0 {
                                 println!("🥩 Staked Balance: {:.4} STRK", info.staked_amount);
                             } else {
                                 println!("🥩 Staked Balance: 0.0000 STRK");
                             }

                             if info.unpool_amount > 0.0 {
                                 let now = Utc::now().timestamp() as u64;
                                 let ready_time = Utc.timestamp_opt(info.unpool_time as i64, 0).unwrap();
                                 println!("⏳ Pending Unstake: {:.4} STRK", info.unpool_amount);
                                 
                                 if info.unpool_time <= now {
                                     println!("   ✅ READY TO WITHDRAW (Use 'withdraw' command)");
                                 } else {
                                     println!("   🕒 Available at: {}", ready_time.format("%Y-%m-%d %H:%M:%S UTC"));
                                 }
                             }
                         },
                         Err(_) => {} 
                     }
                }
            }
        },
        Commands::Deploy { index } => {
            let (addr, priv_felt, pub_felt) = get_account_info(index, &accounts, cfg)?;
            
            if !ui::is_json_mode() {
                 println!("{}{}", cfg.messages.activating_account, addr);
            }
            
            let tx = ui::with_spinner("Deploying Account...", network::deploy_account(&cfg.rpc_url, &cfg.oz_class_hash, priv_felt, pub_felt, &cfg.messages.network_deploying)).await?;
            
            if ui::is_json_mode() {
                ui::print_json_obj(&json!({
                    "status": "success",
                    "operation": "deploy",
                    "address": addr,
                    "tx_hash": tx
                }));
            } else {
                ui::print_success(&format!("{}{}", cfg.messages.tx_sent, tx));
            }
        },
        Commands::Transfer { from_index, to, amount } => {
            validate_target_address(to, &cfg.messages)?;
            let (addr, priv_felt, _) = get_account_info(from_index, &accounts, cfg)?;
            let msg = cfg.messages.sending_transfer_fmt
                .replace("{amount}", &amount.to_string())
                .replace("{to}", to);
            
            if !ui::is_json_mode() {
                println!("{}", msg);
            }
            
            let tx = ui::with_spinner("Sending Transaction...", network::transfer_strk(&cfg.rpc_url, &cfg.strk_contract_address, &addr, priv_felt, to, *amount, (&cfg.messages.network_building_tx, &cfg.messages.network_target_label, &cfg.messages.network_amount_label))).await?;
            if ui::is_json_mode() {
                ui::print_json_obj(&json!({
                     "status": "success",
                     "operation": "transfer",
                     "from": addr,
                     "to": to,
                     "amount": amount,
                     "tx_hash": tx
                }));
            } else {
                ui::print_success(&format!("{}{}", cfg.messages.tx_sent, tx));
            }
        },
        Commands::Overview => {
            show_overview_table(&accounts, cfg).await?;
        },
        Commands::Stake { index, amount, validator } => {
            // 1. Resolve Staker Address
             let staker_addr = if let Some(v) = validator {
                 if !v.is_empty() {
                     v.clone()
                 } else if !cfg.default_staker_address.is_empty() {
                     println!("Using default staker: {}", cfg.default_staker_address);
                     cfg.default_staker_address.clone()
                 } else {
                     println!("❌ No validator address provided. Use --validator or set default in config.");
                     return Ok(());
                 }
             } else if !cfg.default_staker_address.is_empty() {
                 println!("Using default staker: {}", cfg.default_staker_address);
                 cfg.default_staker_address.clone()
             } else {
                 println!("❌ No validator address provided. Use --validator or set default in config.");
                 return Ok(());
             };

             let (addr, priv_felt, _) = get_account_info(index, &accounts, cfg)?;
             
             // Get amount (prompt if not provided)
             let stake_amount = if let Some(amt) = amount {
                 *amt
             } else {
                 print!("Enter amount to stake: ");
                 io::stdout().flush()?;
                 let mut amt_str = String::new();
                 io::stdin().read_line(&mut amt_str)?;
                 amt_str.trim().parse::<f64>().unwrap_or(0.0)
             };
             
             // 2. Resolve Pool Address
             let pool_addr = network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &staker_addr).await?;

             // 3. Delegate Logic (Smart)
             let tx = network::delegate_strk(
                 &cfg.rpc_url,
                 &cfg.strk_contract_address, // Token contract
                 &pool_addr,                 // Pool contract
                 &addr,                      // Sender
                 priv_felt,                  // Private Key
                 stake_amount
             ).await?;
             println!("🎉 Stake Transaction Sent: {}", tx);
        },
        Commands::Export { index } => {
            if *index >= accounts.len() {
                println!("{}", cfg.messages.index_out_of_bounds);
                return Ok(());
            }
            println!("{}", cfg.messages.export_warning);
            let acc = &accounts[*index];
            let export_acc = prepare_export_account(acc, cfg)?;
            // 导出完整的 JSON 配置
            let json = serde_json::to_string_pretty(&export_acc)?;
            println!("{}", cfg.messages.export_result_fmt
                .replace("{json}", &json));
        },
        Commands::Import { key } => {
            let input = match key {
                Some(k) => k.clone(),
                None => {
                    // print!("{}", cfg.messages.import_enter_key);
                    // io::stdout().flush()?;
                    prompt_password(&cfg.messages.import_enter_key)?
                }
            };
            
            let input = input.trim();
            
            // 尝试解析为 JSON 配置，如果失败则视为普通私钥
            let account_config = if input.starts_with('{') {
                 serde_json::from_str::<AccountConfig>(input)
                    .map_err(|_| anyhow::anyhow!("Invalid JSON config"))?
            } else {
                if Felt::from_hex(input).is_err() {
                     println!("{}", cfg.messages.import_invalid_key);
                     return Ok(());
                }
                AccountConfig {
                    private_key: input.to_string(),
                    salt: None,
                    class_hash: Some(cfg.oz_class_hash.clone()),
                    alias: None,
                    address: None,
                }
            };

            match Keystore::add_account(&keystore, &password, account_config) {
                Ok(updated) => {
                    save_keystore(&cfg.keystore_file, &updated)?;
                    println!("{}", cfg.messages.import_success);
                    println!("{}", cfg.messages.import_derivation_warning);
                },
                Err(_) => println!("{}", cfg.messages.import_exists),
            }
        },
        Commands::Distribute { from_index, start_index, end_index, amount } => {
            let (sender_addr, priv_felt, _) = get_account_info(from_index, &accounts, cfg)?;
            
            let mut recipients = Vec::new();
            for i in *start_index..=*end_index {
                // Skip self
                if i == *from_index { continue; }
                let (addr, _, _) = get_account_info(&i, &accounts, cfg)?;
                recipients.push((addr, *amount));
            }

            if recipients.is_empty() {
                println!("⚠️  No recipients found.");
                return Ok(());
            }

            println!("{}", cfg.messages.distribute_start);
            let tx = network::multi_transfer_strk(
                &cfg.rpc_url,
                &cfg.strk_contract_address,
                &sender_addr,
                priv_felt,
                recipients,
                &cfg.messages.network_building_tx
            ).await?;
            println!("{}{}", cfg.messages.distribute_success, tx);
        },
        Commands::Sweep { start_index, end_index, to_index } => {
            let (to_addr, _, _) = get_account_info(to_index, &accounts, cfg)?;
            println!("{}", cfg.messages.sweep_start);

            for i in *start_index..=*end_index {
                if i == *to_index { continue; }
                
                let (from_addr, priv_felt, _) = get_account_info(&i, &accounts, cfg)?;
                println!("{}", cfg.messages.sweep_process_account.replace("{index}", &i.to_string()).replace("{addr}", &from_addr));

                let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &from_addr).await?;
                
                // Estimate fee (dummy amount for estimation)
                let estimated_fee = match network::estimate_transfer_fee(&cfg.rpc_url, &cfg.strk_contract_address, &from_addr, priv_felt, &to_addr, 0.001).await {
                    Ok(f) => f,
                    Err(e) => {
                        println!("   ❌ Fee estimation failed: {}", e);
                        continue;
                    }
                };

                // Calculate max sendable amount (Balance - Fee * 1.2 buffer)
                let amount_to_send = balance - (estimated_fee * 1.2);

                if amount_to_send <= 0.0 {
                    println!("   {}", cfg.messages.sweep_skip_low_balance.replace("{balance}", &format!("{:.4}", balance)));
                    continue;
                }

                let tx = network::transfer_strk(&cfg.rpc_url, &cfg.strk_contract_address, &from_addr, priv_felt, &to_addr, amount_to_send, (&cfg.messages.network_building_tx, &cfg.messages.network_target_label, &cfg.messages.network_amount_label)).await?;
                println!("   {}", cfg.messages.sweep_success.replace("{amount}", &format!("{:.4}", amount_to_send)).replace("{hash}", &tx));
            }
        },
        Commands::Unstake { index, validator, amount } => {
            let (addr, priv_felt, _) = get_account_info(index, &accounts, cfg)?;
            
            // 1. Resolve Staker
            let staker_addr = match validator {
                 Some(v) => v.clone(),
                 None => {
                     if !cfg.default_staker_address.is_empty() {
                         println!("Using default staker: {}", cfg.default_staker_address);
                         cfg.default_staker_address.clone()
                     } else {
                         print!("Enter Validator (Staker) Address: ");
                         io::stdout().flush()?;
                         let mut input = String::new();
                         io::stdin().read_line(&mut input)?;
                         let input = input.trim();
                         if input.is_empty() { println!("❌ Validator address required."); return Ok(()); }
                         input.to_string()
                     }
                 }
            };

            // 2. Resolve Amount
            let unstake_amount = match amount {
                Some(a) => *a,
                None => {
                    print!("Enter Amount to Unstake (STRK): ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                     match input.trim().parse::<f64>() {
                        Ok(v) => v,
                        Err(_) => { println!("❌ Invalid amount."); return Ok(()); }
                    }
                }
            };

            // 3. Resolve Pool
            println!("🔍 Resolving Pool Address for Staker: {}...", staker_addr);
            let pool_addr = match network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &staker_addr).await {
                Ok(p) => { println!("✅ Found Pool Contract: {}", p); p },
                Err(e) => { println!("⚠️  Failed to resolve Pool: {}", e); return Ok(()); }
            };

            // 4. Execute Intent
            let tx = match network::unstake_intent(&cfg.rpc_url, &pool_addr, &addr, priv_felt, unstake_amount).await {
                Ok(hash) => hash,
                Err(e) => { println!("❌ Unstake Intent Failed: {:?}", e); return Ok(()); }
            };
            println!("🎉 Unstake Intent Sent!\nTransaction Hash: {}", tx);
        },
        Commands::Withdraw { index, validator } => {
            let (addr, priv_felt, _) = get_account_info(index, &accounts, cfg)?;
            
            // 1. Resolve Staker
            let staker_addr = match validator {
                 Some(v) => v.clone(),
                 None => {
                     if !cfg.default_staker_address.is_empty() {
                         println!("Using default staker: {}", cfg.default_staker_address);
                         cfg.default_staker_address.clone()
                     } else {
                         print!("Enter Validator (Staker) Address: ");
                         io::stdout().flush()?;
                         let mut input = String::new();
                         io::stdin().read_line(&mut input)?;
                         let input = input.trim();
                         if input.is_empty() { println!("❌ Validator address required."); return Ok(()); }
                         input.to_string()
                     }
                 }
            };

            // 2. Resolve Pool
            println!("🔍 Resolving Pool Address for Staker: {}...", staker_addr);
            let pool_addr = match network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &staker_addr).await {
                Ok(p) => { println!("✅ Found Pool Contract: {}", p); p },
                Err(e) => { println!("⚠️  Failed to resolve Pool: {}", e); return Ok(()); }
            };

            // 3. Execute Action
            let tx = match network::unstake_action(&cfg.rpc_url, &pool_addr, &addr, priv_felt).await {
                Ok(hash) => hash,
                Err(e) => { println!("❌ Withdraw Action Failed: {:?}", e); return Ok(()); }
            };
             println!("🎉 Withdraw Action Sent!\nTransaction Hash: {}", tx);
        },
        Commands::Backup => {
            println!("☁️  Starting Google Drive Backup...");
            let client_id = cfg.google_client_id.as_deref().ok_or_else(|| anyhow::anyhow!("Missing GOOGLE_CLIENT_ID in .env"))?.to_string();
            let client_secret = cfg.google_client_secret.as_deref().ok_or_else(|| anyhow::anyhow!("Missing GOOGLE_CLIENT_SECRET in .env"))?.to_string();

            let backend = GoogleDriveBackend::new(client_id, client_secret).await?;
            println!("🔐 Authenticated.");
            
            let path = Path::new(&cfg.keystore_file);
            if !path.exists() {
                 return Err(anyhow::anyhow!("Keystore file not found: {:?}", path));
            }
            
            let file_id = backend.upload_file(path).await?;
            println!("✅ Backup successful! File ID: {}", file_id);
        },

        Commands::Swap { sell, buy, amount, slippage, index } => {
            let network = if cfg.rpc_url.contains("sepolia") { AvnuNetwork::Sepolia } else { AvnuNetwork::Mainnet };
            let client = AvnuClient::new(network);
            
            // 1. Get Quote
            println!("Fetching quote from AVNU...");
            let tokens = client.get_tokens().await?;
            let sell_token_info = tokens.iter().find(|t| t.address == *sell || t.symbol.eq_ignore_ascii_case(sell)).ok_or(anyhow::anyhow!("Sell token not found (check 'tokens' command)"))?;
            let buy_token_info = tokens.iter().find(|t| t.address == *buy || t.symbol.eq_ignore_ascii_case(buy)).ok_or(anyhow::anyhow!("Buy token not found (check 'tokens' command)"))?;
            
            let amount_wei = (*amount * 10f64.powi(sell_token_info.decimals as i32)).floor();
            let amount_str = format!("{:#x}", amount_wei as u128);
            
            let quote = client.get_quote(&sell_token_info.address, &buy_token_info.address, &amount_str).await?;
            
            let buy_amount_val = u128::from_str_radix(quote.buy_amount.trim_start_matches("0x"), 16)?;
            let buy_amount_float = buy_amount_val as f64 / 10f64.powi(buy_token_info.decimals as i32);
            
            println!("--------------------------------");
            println!("💱 Swap Quote:");
            println!("Sell: {} {}", amount, sell_token_info.symbol);
            println!("Buy:  {:.6} {}", buy_amount_float, buy_token_info.symbol);
            println!("Price: 1 {} ≈ {:.6} {}", sell_token_info.symbol, buy_amount_float/amount, buy_token_info.symbol);
            // println!("Slippage: {:.2}%", slippage * 100.0);
            println!("--------------------------------");
            
            // 2. Build Transaction
            let (addr, priv_felt, _) = get_account_info(index, &accounts, cfg)?;
            let calls = client.build_swap(&quote.quote_id, &addr, *slippage, &sell_token_info.address, &amount_str).await?;
            
            use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient};
            use starknet::accounts::{SingleOwnerAccount, ExecutionEncoding, Account};
            use starknet::signers::LocalWallet;
            use url::Url;
            
            let url = Url::parse(&cfg.rpc_url)?;
            let provider = JsonRpcClient::new(HttpTransport::new(url));
            let chain_id = provider.chain_id().await?;
            let signer = LocalWallet::from(SigningKey::from_secret_scalar(priv_felt));
            let sender_felt = Felt::from_hex(&addr)?;
            
            let account_obj = SingleOwnerAccount::new(
                provider,
                signer,
                sender_felt,
                chain_id,
                ExecutionEncoding::New,
            );
            
            let tx_result = ui::with_spinner("Swapping...", account_obj.execute_v3(calls).send()).await?;
            println!("✅ Swap Transaction Sent: {:#x}", tx_result.transaction_hash);
        },

        _ => {}
    }
    Ok(())
}

// 辅助：从索引获取账户信息
fn get_account_info(index: &usize, accounts: &[AccountConfig], cfg: &Config) -> Result<(String, Felt, Felt)> {
    if *index >= accounts.len() {
        return Err(anyhow::anyhow!("{}", cfg.messages.index_out_of_bounds));
    }
    let acc = &accounts[*index];
    let addr = Keystore::compute_address(acc, &cfg.oz_class_hash)?;
    let priv_felt = Felt::from_hex(&acc.private_key)?;
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

async fn run_interactive_mode_real(cfg: &mut Config) -> Result<()> {
    println!("{}", cfg.messages.interactive_welcome);
    println!("===================================");
    
    // 修复点：正确解包 3 个返回值
    let (current_keystore, accounts, password) = load_and_decrypt(&cfg.keystore_file, &cfg.messages)?;
    println!("{}", cfg.messages.decrypt_success_fmt.replace("{count}", &accounts.len().to_string()));

    let mut current_accounts = accounts;
    let mut keystore_obj = current_keystore;
    let pass = password; 

    loop {
        // Clear screen or just print separator? Let's just print separator for now.
        println!("\n===================================");
        
        // Show account summary briefly? 
        // Or just the menu.
        
        let options = vec![
            "📋 List Accounts",
            "✨ Create New Account",
            "📥 Import Account",
            "🔍 View Validators",
            "📊 Overview (All Accounts)",
            "💱 Swap Tokens",
            "🪙 Check Supported Tokens",
            "❌ Quit",
        ];

        let choice = Select::new(&cfg.messages.menu_choice, options.clone())
            .with_page_size(10)
            .prompt()?;

        match choice {
            "❌ Quit" => break,
            "📋 List Accounts" => {
                 println!("{}", cfg.messages.account_list);
                 for (i, acc) in current_accounts.iter().enumerate() {
                    let addr = Keystore::compute_address(acc, &cfg.oz_class_hash)?;
                    let alias_suffix = acc.alias.as_ref().map(|a| format!(" ({})", a)).unwrap_or_default();
                    println!("   [{}] {}{}", i, addr, alias_suffix);
                 }
                 
                 // Offer to select an account?
                 let mut account_options = current_accounts.iter().enumerate().map(|(i, acc)| {
                     let addr = Keystore::compute_address(acc, &cfg.oz_class_hash).unwrap_or_default();
                     let short = if addr.len() > 10 { format!("{}...", &addr[..10]) } else { addr };
                     format!("[{}] {}", i, short)
                 }).collect::<Vec<_>>();
                 account_options.push("🔙 Back".to_string());

                 if let Ok(acc_choice) = Select::new("Select an account to manage:", account_options).prompt() {
                     if acc_choice != "🔙 Back" {
                         let idx = acc_choice[1..].split(']').next().unwrap().parse::<usize>().unwrap();
                         if let Err(e) = process_single_account_interactive(&current_accounts[idx], idx, &current_accounts, cfg).await {
                             println!("{}{}", cfg.messages.error_prefix, e);
                         }
                     }
                 }
            },
            "✨ Create New Account" => {
                println!("{}", cfg.messages.generating_new_account);
                let new_account = AccountConfig {
                    private_key: Keystore::generate_new_key(),
                    salt: None,
                    class_hash: Some(cfg.oz_class_hash.clone()),
                    alias: None,
                    address: None,
                };
                
                let updated = Keystore::add_account(&keystore_obj, &pass, new_account)?;
                save_keystore(&cfg.keystore_file, &updated)?;
                keystore_obj = updated;
                current_accounts = keystore_obj.decrypt(&pass)?; 
                println!("{}", cfg.messages.new_account_created);
            },
            "📥 Import Account" => {
                let input = prompt_password(&cfg.messages.import_enter_key)?;
                let input = input.trim();
                
                let account_config = if input.starts_with('{') {
                     match serde_json::from_str::<AccountConfig>(input) {
                        Ok(ac) => ac,
                        Err(_) => { println!("❌ Invalid JSON"); continue; }
                     }
                } else {
                    if Felt::from_hex(input).is_err() {
                         println!("{}", cfg.messages.import_invalid_key);
                         continue;
                    }
                    AccountConfig {
                        private_key: input.to_string(),
                        salt: None,
                        class_hash: Some(cfg.oz_class_hash.clone()),
                        alias: None,
                        address: None,
                    }
                };
    
                match Keystore::add_account(&keystore_obj, &pass, account_config) {
                    Ok(updated) => {
                        save_keystore(&cfg.keystore_file, &updated)?;
                        keystore_obj = updated;
                        current_accounts = keystore_obj.decrypt(&pass)?;
                        println!("{}", cfg.messages.import_success);
                    },
                    Err(_) => println!("{}", cfg.messages.import_exists),
                }
            },
            "🔍 View Validators" => {
                println!("Please visit https://sepolia.voyager.online/validators to view active validators.");
            },
            "📊 Overview (All Accounts)" => {
                show_overview_table(&current_accounts, cfg).await?;
            },
            "🪙 Check Supported Tokens" => {
                 let network = if cfg.rpc_url.contains("sepolia") { AvnuNetwork::Sepolia } else { AvnuNetwork::Mainnet };
                let client = AvnuClient::new(network);
                println!("Fetching tokens...");
                match client.get_tokens().await {
                    Ok(tokens) => {
                        let mut show_balance = false;
                        let mut account_addr = String::new();
                        
                        // Ask to show balances
                         if !current_accounts.is_empty() {
                            let choices = vec!["No", "Yes"];
                            if let Ok(choice) = Select::new("Show balances for an account?", choices).prompt() {
                                if choice == "Yes" {
                                     let account_options = current_accounts.iter().enumerate().map(|(i, acc)| {
                                         let addr = Keystore::compute_address(acc, &cfg.oz_class_hash).unwrap_or_default();
                                         let short = if addr.len() > 10 { format!("{}...", &addr[..10]) } else { addr };
                                         format!("[{}] {}", i, short)
                                     }).collect::<Vec<_>>();
                                     
                                     if let Ok(acc_choice) = Select::new("Select Account:", account_options).prompt() {
                                         let acc_idx = acc_choice[1..].split(']').next().unwrap().parse::<usize>().unwrap();
                                         if let Ok((addr, _, _)) = get_account_info(&acc_idx, &current_accounts, cfg) {
                                             account_addr = addr;
                                             show_balance = true;
                                         }
                                     }
                                }
                            }
                        }

                         let mut table = Table::new();
                         if show_balance {
                             table.load_preset(UTF8_FULL).set_header(vec!["Symbol", "Name", "Address", "Balance"]);
                             println!("Fetching balances for {} (this may take a while)...", account_addr);
                             
                             let mut rows = Vec::new();
                             // Fetch balances in parallel or sequential? Sequential is easier but slow.
                             // Let's do sequential for now with a progress indicator or just printing as we go?
                             // Table needs all rows.
                             
                             // We'll use a simple loop. Improving to parallel join_all would be better for 100+ tokens.
                             // But let's stick to simple sequential for stability first, maybe limit to top 20 or user can wait.
                             // Or use buffer/stream.
                             
                             for t in tokens {
                                 print!("\rChecking {}...", t.symbol);
                                 use std::io::Write;
                                 std::io::stdout().flush().unwrap();
                                 
                                 let bal = network::get_token_balance(&cfg.rpc_url, &t.address, &account_addr, t.decimals).await.unwrap_or(0.0);
                                 // Only show non-zero balances? Or all? User might want to see 0.
                                 // Let's show all for now, or maybe filtering option. "Supported Tokens" implies list all.
                                 
                                 rows.push(vec![
                                     t.symbol.clone(),
                                     t.name.clone(),
                                     t.address.clone(),
                                     format!("{:.4}", bal)
                                 ]);
                             }
                             println!("\rDone!          ");
                             
                             for row in rows {
                                 table.add_row(row);
                             }
                             
                         } else {
                            table.load_preset(UTF8_FULL).set_header(vec!["Symbol", "Name", "Address"]);
                            for t in tokens { table.add_row(vec![t.symbol, t.name, t.address]); }
                         }
                        println!("{table}");
                    },
                    Err(e) => println!("Error fetching tokens: {}", e),
                }
            },
            "💱 Swap Tokens" => {
                 // Interactive Swap Wizard
                 let network = if cfg.rpc_url.contains("sepolia") { AvnuNetwork::Sepolia } else { AvnuNetwork::Mainnet };
                 let client = AvnuClient::new(network);
                 
                 // 1. Select Account
                 let account_options = current_accounts.iter().enumerate().map(|(i, acc)| {
                     let addr = Keystore::compute_address(acc, &cfg.oz_class_hash).unwrap_or_default();
                     let short = if addr.len() > 10 { format!("{}...", &addr[..10]) } else { addr };
                     format!("[{}] {}", i, short)
                 }).collect::<Vec<_>>();
                 
                 let acc_choice = Select::new("Select Account:", account_options).prompt();
                 if acc_choice.is_err() { continue; }
                 let acc_choice = acc_choice.unwrap();

                 let acc_idx = acc_choice[1..].split(']').next().unwrap().parse::<usize>().unwrap();
                 let (addr, priv_felt, _) = match get_account_info(&acc_idx, &current_accounts, cfg) {
                     Ok(info) => info,
                     Err(e) => { println!("Error getting account: {}", e); continue; }
                 };
                 
                 // 2. Fetch Tokens
                 println!("Fetching token list...");
                 let tokens = match client.get_tokens().await {
                     Ok(t) => t,
                     Err(e) => { println!("Error fetching tokens: {}", e); continue; }
                 };
                 let token_options: Vec<String> = tokens.iter().map(|t| t.symbol.clone()).collect();
                 
                 // 3. Select Sell Token
                 let sell_symbol = match Select::new("Sell Token:", token_options.clone()).prompt() {
                     Ok(s) => s,
                     Err(_) => continue,
                 };
                 let sell_token = tokens.iter().find(|t| t.symbol == sell_symbol).unwrap();
                 
                 // 4. Select Buy Token
                 let buy_symbol = match Select::new("Buy Token:", token_options).prompt() {
                     Ok(s) => s,
                     Err(_) => continue,
                 };
                 let buy_token = tokens.iter().find(|t| t.symbol == buy_symbol).unwrap();
                 
                 // 5. Amount
                 print!("Amount to Sell ({}): ", sell_symbol);
                 io::stdout().flush()?;
                 let mut input = String::new();
                 io::stdin().read_line(&mut input)?;
                 let amount: f64 = input.trim().parse().unwrap_or(0.0);
                 
                 if amount <= 0.0 { println!("Invalid amount"); continue; }
                 
                 // 6. Get Quote
                 let amount_wei = (amount * 10f64.powi(sell_token.decimals as i32)).floor();
                 let amount_str = format!("{:#x}", amount_wei as u128);
                 
                 match client.get_quote(&sell_token.address, &buy_token.address, &amount_str).await {
                     Ok(quote) => {
                          let buy_amt_val = u128::from_str_radix(quote.buy_amount.trim_start_matches("0x"), 16).unwrap_or(0);
                          let buy_amt = buy_amt_val as f64 / 10f64.powi(buy_token.decimals as i32);
                          println!("\n💱 Quote: {} {} -> {:.6} {}", amount, sell_symbol, buy_amt, buy_symbol);
                          
                          if Select::new("Confirm Swap?", vec!["Yes", "No"]).prompt().unwrap_or("No") == "Yes" {
                              // Execute
                              let calls = match client.build_swap(&quote.quote_id, &addr, 0.01, &sell_token.address, &amount_str).await { // 1% default
                                  Ok(c) => c,
                                  Err(e) => { println!("Error building swap: {}", e); continue; }
                              };
                              
                                // Inline Execution
                                use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient};
                                use starknet::accounts::{SingleOwnerAccount, ExecutionEncoding, Account};
                                use starknet::signers::LocalWallet;
                                use url::Url;
                                
                                let url = Url::parse(&cfg.rpc_url).unwrap();
                                let provider = JsonRpcClient::new(HttpTransport::new(url));
                                let chain_id = provider.chain_id().await.unwrap();
                                let signer = LocalWallet::from(SigningKey::from_secret_scalar(priv_felt));
                                let sender_felt = Felt::from_hex(&addr).unwrap();
                                
                                let account_obj = SingleOwnerAccount::new(
                                    provider,
                                    signer,
                                    sender_felt,
                                    chain_id,
                                    ExecutionEncoding::New,
                                );
                                
                                match ui::with_spinner("Swapping...", account_obj.execute_v3(calls).send()).await {
                                    Ok(tx) => println!("✅ Swap Sent: {:#x}", tx.transaction_hash),
                                    Err(e) => println!("❌ Swap Failed: {}", e),
                                }
                          }
                     },
                     Err(e) => println!("❌ Failed to get quote: {}", e),
                 }
            },
            _ => {}
        }
    }
    Ok(())
}

// 交互模式下的单账户操作
async fn process_single_account_interactive(
    account: &AccountConfig, 
    idx: usize, 
    all_accounts: &[AccountConfig],
    cfg: &mut Config
) -> Result<()> {
    let addr = Keystore::compute_address(account, &cfg.oz_class_hash)?;
    println!("\n{}", cfg.messages.account_details_title.replace("{index}", &idx.to_string()));
    println!("{}{}", cfg.messages.address_label, addr);

    // 显示 QR Code
    if let Ok(code) = QrCode::new(addr.as_bytes()) {
        let image = code.render::<unicode::Dense1x2>()
            .quiet_zone(true)
            .build();
        println!("\n{}", image);
    }
    
    let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr).await?;
    println!("{}{:.4}", cfg.messages.balance_label, balance);

    // Check Dynamic Token Balances (AVNU)
    use futures::stream::StreamExt;
    
    let network = if cfg.rpc_url.contains("sepolia") { AvnuNetwork::Sepolia } else { AvnuNetwork::Mainnet };
    let client = AvnuClient::new(network);
    
    // Fetch tokens
    if let Ok(tokens) = client.get_tokens().await {
        // Only verify top 50 to avoid rate limits if list is huge, strictly 7 on Sepolia currently though.
        let scan_tokens = tokens.into_iter().take(50).collect::<Vec<_>>();
        if !scan_tokens.is_empty() {
             println!("\n💰 Token Balances (Scanning {} tokens via AVNU)...", scan_tokens.len());
             
             // Define async task
             let rpc_url = cfg.rpc_url.clone();
             let user_addr = addr.clone();
             
             let fetch_balance = |token: Token| {
                 let rpc = rpc_url.clone();
                 let u_addr = user_addr.clone();
                 async move {
                     let bal = network::get_token_balance(&rpc, &token.address, &u_addr, token.decimals)
                         .await.unwrap_or(0.0);
                     (token, bal)
                 }
             };
             
             let mut stream = futures::stream::iter(scan_tokens)
                 .map(|t| fetch_balance(t))
                 .buffer_unordered(10); // 10 concurrent
                 
             let mut active_tokens = Vec::new();
             while let Some((token, bal)) = stream.next().await {
                 if bal > 0.0 {
                     active_tokens.push((token.symbol, bal));
                 }
             }
             
             // Sort by symbol
             active_tokens.sort_by(|a, b| a.0.cmp(&b.0));
             
             if !active_tokens.is_empty() {
                 let mut table = Table::new();
                 table.load_preset(UTF8_FULL).set_header(vec!["Token", "Balance"]);
                 for (sym, bal) in active_tokens {
                     table.add_row(vec![sym, format!("{:.4}", bal)]);
                 }
                 println!("{table}");
             }
        }
    }

    // Check Staked Balance if default staker is configured
    if !cfg.default_staker_address.is_empty() {
        if let Ok(pool_addr) = network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &cfg.default_staker_address).await {
             if let Ok(info) = network::get_account_pool_info(&cfg.rpc_url, &pool_addr, &addr).await {
                 if info.staked_amount > 0.0 {
                     println!("🥩 Staked Balance: {:.4} STRK", info.staked_amount);
                 } else {
                     println!("🥩 Staked Balance: 0.0000 STRK");
                 }

                 if info.unpool_amount > 0.0 {
                     let now = Utc::now().timestamp() as u64;
                     let ready_time = Utc.timestamp_opt(info.unpool_time as i64, 0).unwrap();
                     println!("⏳ Pending Unstake: {:.4} STRK", info.unpool_amount);
                     
                     if info.unpool_time <= now {
                         println!("   ✅ READY TO WITHDRAW (Use 'withdraw' command or press [X])");
                     } else {
                         println!("   🕒 Available at: {}", ready_time.format("%Y-%m-%d %H:%M:%S UTC"));
                     }
                 }
             }
        }
    }
    
    let deployed = network::is_account_deployed(&cfg.rpc_url, &addr).await?;
    
    // 动态修改操作提示，增加 [E]Export [S]Stake [D]Distribute [W]Sweep [U]Unstake [X]Withdraw
    println!("{} [E]Export [S]Stake [D]Distribute [W]Sweep [U]Unstake [X]Withdraw", cfg.messages.operations_label.replace(" [B]Back", ""));
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
                if target_idx < all_accounts.len() {
                    let target_acc = &all_accounts[target_idx];
                    let addr = Keystore::compute_address(target_acc, &cfg.oz_class_hash)?;
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
            
            let pk_felt = Felt::from_hex(&account.private_key)?;
            let tx = network::transfer_strk(&cfg.rpc_url, &cfg.strk_contract_address, &addr, pk_felt, &to_addr, amt, (&cfg.messages.network_building_tx, &cfg.messages.network_target_label, &cfg.messages.network_amount_label)).await?;
            println!("{}{}", cfg.messages.tx_sent, tx);
        },
        "A" => {
            if deployed { println!("{}", cfg.messages.already_activated); return Ok(()); }
            let pk_felt = Felt::from_hex(&account.private_key)?;
            let signer = SigningKey::from_secret_scalar(pk_felt);
            let pub_felt = signer.verifying_key().scalar();
            let tx = network::deploy_account(&cfg.rpc_url, &cfg.oz_class_hash, pk_felt, pub_felt, &cfg.messages.network_deploying).await?;
            println!("{}{}", cfg.messages.tx_sent, tx);
        },
        "E" => {
            println!("{}", cfg.messages.export_warning);
            let export_acc = prepare_export_account(account, cfg)?;
            let json = serde_json::to_string_pretty(&export_acc)?;
            println!("{}", cfg.messages.export_result_fmt
                .replace("{json}", &json));
        },

        "S" => {
            // 1. Resolve Staker Address
            let staker_addr = if !cfg.default_staker_address.is_empty() {
                println!("Using default staker: {}", cfg.default_staker_address);
                cfg.default_staker_address.clone()
            } else {
                print!("Enter Validator (Staker) Address: ");
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let input = input.trim();
                if input.is_empty() {
                    println!("❌ Validator address required.");
                    return Ok(());
                }
                input.to_string()
            };

            // 2. Resolve Amount
            print!("Enter Amount to Stake (STRK): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let stake_amount = match input.trim().parse::<f64>() {
                Ok(v) => v,
                Err(_) => {
                    println!("❌ Invalid amount.");
                    return Ok(());
                }
            };

            // 3. Resolve Pool Address
            println!("🔍 Resolving Pool Address for Staker: {}...", staker_addr);
            let pool_addr = match network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &staker_addr).await {
                Ok(p) => {
                    println!("✅ Found Pool Contract: {}", p);
                    p
                },
                Err(e) => {
                    println!("⚠️  Failed to resolve Pool Address automatically: {}", e);
                    print!("Please enter Pool Contract Address manually (or press Enter to abort): ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    let input = input.trim();
                    if input.is_empty() {
                        println!("🚫 Aborted.");
                        return Ok(());
                    }
                    input.to_string()
                }
            };

            // 4. Create Signer
            let pk_felt = Felt::from_hex(&account.private_key)?;
            
            // 5. Execute Delegation
            let tx = match network::delegate_strk(
                &cfg.rpc_url,
                &cfg.strk_contract_address,
                &pool_addr,
                &addr,
                pk_felt,
                stake_amount
            ).await {
                Ok(hash) => hash,
                Err(e) => {
                    println!("❌ Transaction Failed!");
                    println!("Error Details: {:?}", e);
                    return Ok(());
                }
            };
            
            println!("🎉 Staking Success!");
            println!("Transaction Hash: {}", tx);

            if cfg.default_staker_address.is_empty() {
                cfg.default_staker_address = staker_addr.clone();
                println!("\n✅ Configured '{}' as temporary default staker for this session.", staker_addr);
                println!("   (To make this permanent, add DEFAULT_STAKER_ADDRESS={} to your .env file)", staker_addr);
            }
        },
        "D" => {
            print!("Start Index of recipients: ");
            io::stdout().flush()?;
            let mut s = String::new();
            io::stdin().read_line(&mut s)?;
            let start: usize = match s.trim().parse() { Ok(i) => i, Err(_) => { println!("Invalid number"); return Ok(()); } };

            print!("End Index of recipients: ");
            io::stdout().flush()?;
            let mut e = String::new();
            io::stdin().read_line(&mut e)?;
            let end: usize = match e.trim().parse() { Ok(i) => i, Err(_) => { println!("Invalid number"); return Ok(()); } };

            print!("Amount per recipient (STRK): ");
            io::stdout().flush()?;
            let mut a = String::new();
            io::stdin().read_line(&mut a)?;
            let amt: f64 = match a.trim().parse() { Ok(f) => f, Err(_) => { println!("Invalid amount"); return Ok(()); } };

            let (sender_addr, priv_felt, _) = get_account_info(&idx, all_accounts, cfg)?;
            
            let mut recipients = Vec::new();
            for i in start..=end {
                if i == idx { continue; }
                if i >= all_accounts.len() { continue; }
                let (addr, _, _) = get_account_info(&i, all_accounts, cfg)?;
                recipients.push((addr, amt));
            }

            if recipients.is_empty() {
                println!("⚠️  No valid recipients found (checked index {} to {}).", start, end);
            } else {
                println!("{}", cfg.messages.distribute_start);
                match network::multi_transfer_strk(
                    &cfg.rpc_url,
                    &cfg.strk_contract_address,
                    &sender_addr,
                    priv_felt,
                    recipients,
                    &cfg.messages.network_building_tx
                ).await {
                    Ok(tx) => println!("{}{}", cfg.messages.distribute_success, tx),
                    Err(e) => println!("❌ Distribution Failed: {}", e),
                }
            }
        },
        "W" => {
            print!("Start Index of source accounts: ");
            io::stdout().flush()?;
            let mut s = String::new();
            io::stdin().read_line(&mut s)?;
            let start: usize = match s.trim().parse() { Ok(i) => i, Err(_) => { println!("Invalid number"); return Ok(()); } };

            print!("End Index of source accounts: ");
            io::stdout().flush()?;
            let mut e = String::new();
            io::stdin().read_line(&mut e)?;
            let end: usize = match e.trim().parse() { Ok(i) => i, Err(_) => { println!("Invalid number"); return Ok(()); } };

            let (to_addr, _, _) = get_account_info(&idx, all_accounts, cfg)?;
            println!("{}", cfg.messages.sweep_start);

            for i in start..=end {
                if i == idx { continue; }
                if i >= all_accounts.len() { continue; }
                
                let (from_addr, priv_felt, _) = get_account_info(&i, all_accounts, cfg)?;
                println!("{}", cfg.messages.sweep_process_account.replace("{index}", &i.to_string()).replace("{addr}", &from_addr));

                let balance = match network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &from_addr).await {
                    Ok(b) => b,
                    Err(_) => { println!("   ❌ Failed to get balance"); continue; }
                };

                // Estimate fee (dummy amount for estimation)
                let estimated_fee = match network::estimate_transfer_fee(&cfg.rpc_url, &cfg.strk_contract_address, &from_addr, priv_felt, &to_addr, 0.001).await {
                    Ok(f) => f,
                    Err(e) => {
                        println!("   ❌ Fee estimation failed: {}", e);
                        continue;
                    }
                };

                let amount_to_send = balance - (estimated_fee * 1.2);

                if amount_to_send <= 0.0 {
                    println!("   {}", cfg.messages.sweep_skip_low_balance.replace("{balance}", &format!("{:.4}", balance)));
                    continue;
                }

                match network::transfer_strk(&cfg.rpc_url, &cfg.strk_contract_address, &from_addr, priv_felt, &to_addr, amount_to_send, (&cfg.messages.network_building_tx, &cfg.messages.network_target_label, &cfg.messages.network_amount_label)).await {
                    Ok(tx) => println!("   {}", cfg.messages.sweep_success.replace("{amount}", &format!("{:.4}", amount_to_send)).replace("{hash}", &tx)),
                    Err(e) => println!("   ❌ User Sweep Failed: {}", e),
                }
            }
        },
        "U" => {
            // 1. Resolve Staker
            let staker_addr = if !cfg.default_staker_address.is_empty() {
                println!("Using default staker: {}", cfg.default_staker_address);
                cfg.default_staker_address.clone()
            } else {
                print!("Enter Validator (Staker) Address: ");
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let input = input.trim();
                if input.is_empty() { println!("❌ Validator address required."); return Ok(()); }
                input.to_string()
            };

            // 2. Resolve Amount
            print!("Enter Amount to Unstake (STRK): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let unstake_amount = match input.trim().parse::<f64>() {
                Ok(v) => v,
                Err(_) => { println!("❌ Invalid amount."); return Ok(()); }
            };

            // 3. Resolve Pool
            println!("🔍 Resolving Pool Address for Staker: {}...", staker_addr);
            let pool_addr = match network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &staker_addr).await {
                Ok(p) => { println!("✅ Found Pool Contract: {}", p); p },
                Err(e) => { println!("⚠️  Failed to resolve Pool: {}", e); return Ok(()); }
            };

            // 4. Intent
            let pk_felt = Felt::from_hex(&account.private_key)?;
            let tx = match network::unstake_intent(&cfg.rpc_url, &pool_addr, &addr, pk_felt, unstake_amount).await {
                Ok(hash) => hash,
                Err(e) => { println!("❌ Unstake Intent Failed: {:?}", e); return Ok(()); }
            };
            println!("🎉 Unstake Intent Sent!\nTransaction Hash: {}", tx);
        },
        "X" => {
            // 1. Resolve Staker
            let staker_addr = if !cfg.default_staker_address.is_empty() {
                println!("Using default staker: {}", cfg.default_staker_address);
                cfg.default_staker_address.clone()
            } else {
                print!("Enter Validator (Staker) Address: ");
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let input = input.trim();
                if input.is_empty() { println!("❌ Validator address required."); return Ok(()); }
                input.to_string()
            };

            // 2. Resolve Pool
            println!("🔍 Resolving Pool Address for Staker: {}...", staker_addr);
            let pool_addr = match network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &staker_addr).await {
                Ok(p) => { println!("✅ Found Pool Contract: {}", p); p },
                Err(e) => { println!("⚠️  Failed to resolve Pool: {}", e); return Ok(()); }
            };

            // 3. Action
            let pk_felt = Felt::from_hex(&account.private_key)?;
            let tx = match network::unstake_action(&cfg.rpc_url, &pool_addr, &addr, pk_felt).await {
                Ok(hash) => hash,
                Err(e) => { println!("❌ Withdraw Action Failed: {:?}", e); return Ok(()); }
            };
            println!("🎉 Withdraw Action Sent!\nTransaction Hash: {}", tx);
        },
        _ => {}
    }
    Ok(())
}

// ==================== 通用辅助函数 ====================

/// 加载并解密，返回 (Keystore对象, 私钥列表, 密码字符串)
/// 加载并解密，返回 (Keystore对象, 私钥列表, 密码字符串)
fn load_and_decrypt(filepath: &str, msgs: &i18n::Messages) -> Result<(Keystore, Vec<AccountConfig>, String)> {
    // 智能获取密码 (Env Var -> Prompt)
    let password = prompt_password(&msgs.enter_password)?;

    let content = std::fs::read_to_string(filepath)?;
    let keystore: Keystore = serde_json::from_str(&content)?;
    
    let keys = keystore.decrypt(&password)
        .map_err(|_| anyhow::anyhow!("{}", msgs.password_error))?;
    
    Ok((keystore, keys, password))
}

fn prompt_password(prompt: &str) -> Result<String> {
    // 1. Check Environment Variable (Secure & AI Friendly)
    if let Ok(p) = env::var("STARK_ARK_PASSWORD") {
        if !p.trim().is_empty() {
             return Ok(p.trim().to_string());
        }
    }

    // 2. Check Non-Interactive Mode
    if ui::is_json_mode() {
        return Err(anyhow::anyhow!("Password required! Set STARK_ARK_PASSWORD env var for non-interactive mode."));
    }

    // 3. Interactive Prompt
    Ok(Password::new(prompt)
        .without_confirmation()
        .prompt()?)
}

fn prepare_export_account(acc: &AccountConfig, cfg: &Config) -> Result<AccountConfig> {
    let mut export_acc = acc.clone();

    // 1. 补全 Address
    if export_acc.address.is_none() {
        let addr = Keystore::compute_address(acc, &cfg.oz_class_hash)?;
        export_acc.address = Some(addr);
    }

    // 2. 补全 Class Hash
    if export_acc.class_hash.is_none() {
        export_acc.class_hash = Some(cfg.oz_class_hash.clone());
    }

    // 3. 补全 Salt
    if export_acc.salt.is_none() {
        let priv_felt = Felt::from_hex(&export_acc.private_key)?;
        let signer = SigningKey::from_secret_scalar(priv_felt);
        let public_key = signer.verifying_key().scalar();
        export_acc.salt = Some(format!("{:#x}", public_key));
    }

    Ok(export_acc)
}

fn save_keystore(filepath: &str, keystore: &Keystore) -> Result<()> {
    let json = serde_json::to_string_pretty(keystore)?;
    std::fs::write(filepath, json)?;
    Ok(())
}

fn initialize_new_wallet(filename: &str, msgs: &i18n::Messages) -> Result<()> {
    println!("{}", msgs.init_new_wallet);
    // print!("{}", msgs.set_password);
    // io::stdout().flush()?;
    let password = prompt_password(&msgs.set_password)?;
    
    // 初始化时创建一个默认账户，不指定 Class Hash (使用运行时默认)
    let first_account = AccountConfig {
        private_key: Keystore::generate_new_key(),
        salt: None,
        class_hash: None, 
        alias: Some("Main".to_string()),
        address: None,
    };
    
    let keystore = Keystore::encrypt(&password, &[first_account])?;
    save_keystore(filename, &keystore)?;
    println!("{}", msgs.wallet_init_complete);
    Ok(())
}