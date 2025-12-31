use clap::{Parser, Subcommand};
use stark_ark::keystore::{Keystore, AccountConfig};
use stark_ark::config::Config;
use stark_ark::network;
use stark_ark::i18n;
use anyhow::Result;
use std::path::Path;
use std::io::{self, Write};
use starknet::core::types::Felt;
use starknet::signers::SigningKey;
use qrcode::QrCode;
use qrcode::render::unicode;

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
    // 0. 处理不需要钱包解锁的命令
    match cmd {
        Commands::Config { .. } | Commands::Version => { return Ok(()); },
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
            let balance = network::get_balance(&cfg.rpc_url, &cfg.strk_contract_address, &addr).await?;
            let msg = cfg.messages.balance_fmt
                .replace("{index}", &index.to_string())
                .replace("{balance}", &format!("{:.4}", balance));
            println!("{}", msg);

            // Check Staked Balance if default staker is configured
            if !cfg.default_staker_address.is_empty() {
                // Silently attempt to resolve pool and get balance
                if let Ok(pool_addr) = network::get_pool_address(&cfg.rpc_url, &cfg.staking_contract_address, &cfg.default_staker_address).await {
                     match network::get_staked_balance(&cfg.rpc_url, &pool_addr, &addr).await {
                         Ok(staked) => {
                             if staked > 0.0 {
                                 println!("🥩 Staked Balance: {:.4} STRK", staked);
                             } else {
                                 println!("🥩 Staked Balance: 0.0000 STRK");
                             }
                         },
                         Err(_) => {} 
                     }
                }
            }
        },
        Commands::Deploy { index } => {
            let (addr, priv_felt, pub_felt) = get_account_info(index, &accounts, cfg)?;
            println!("{}{}", cfg.messages.activating_account, addr);
            let tx = network::deploy_account(&cfg.rpc_url, &cfg.oz_class_hash, priv_felt, pub_felt, &cfg.messages.network_deploying).await?;
            println!("{}{}", cfg.messages.tx_sent, tx);
        },
        Commands::Transfer { from_index, to, amount } => {
            validate_target_address(to, &cfg.messages)?;
            let (addr, priv_felt, _) = get_account_info(from_index, &accounts, cfg)?;
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
                    print!("{}", cfg.messages.import_enter_key);
                    io::stdout().flush()?;
                    prompt_password()?
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
        Commands::Stake { index, validator, amount } => {
            let (addr, priv_felt, _) = get_account_info(index, &accounts, cfg)?;
            
            // 1. Resolve Staker Address
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
                        if input.is_empty() {
                            println!("❌ Validator address required.");
                            return Ok(());
                        }
                        input.to_string()
                    }
                }
            };

            // 2. Resolve Amount
            let stake_amount = match amount {
                Some(a) => *a,
                None => {
                    print!("Enter Amount to Stake (STRK): ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    match input.trim().parse::<f64>() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("❌ Invalid amount.");
                            return Ok(());
                        }
                    }
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

            // 4. Execute Delegation (Multicall)
            let tx = match network::delegate_strk(
                &cfg.rpc_url,
                &cfg.strk_contract_address,
                &pool_addr,
                &addr,
                priv_felt,
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

async fn run_interactive_mode_real(cfg: &Config) -> Result<()> {
    println!("{}", cfg.messages.interactive_welcome);
    println!("===================================");
    
    // 修复点：正确解包 3 个返回值
    let (current_keystore, accounts, password) = load_and_decrypt(&cfg.keystore_file, &cfg.messages)?;
    println!("{}", cfg.messages.decrypt_success_fmt.replace("{count}", &accounts.len().to_string()));

    let mut current_accounts = accounts;
    let mut keystore_obj = current_keystore;
    let pass = password; 

    loop {
        println!("\n{}", cfg.messages.account_list);
        for (i, acc) in current_accounts.iter().enumerate() {
            let addr = Keystore::compute_address(acc, &cfg.oz_class_hash)?;
            let alias_suffix = acc.alias.as_ref().map(|a| format!(" ({})", a)).unwrap_or_default();
            println!("   [{}] {}{}", i, addr, alias_suffix);
        }
        println!("   {}", cfg.messages.menu_create_account);
        println!("   {}", cfg.messages.menu_import_account);
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
            let new_account = AccountConfig {
                private_key: Keystore::generate_new_key(),
                salt: None,
                class_hash: Some(cfg.oz_class_hash.clone()),
                alias: None,
                address: None,
            };
            
            let updated = Keystore::add_account(&keystore_obj, &pass, new_account)?;
            save_keystore(&cfg.keystore_file, &updated)?;
            // 更新内存状态
            keystore_obj = updated;
            current_accounts = keystore_obj.decrypt(&pass)?; 
            println!("{}", cfg.messages.new_account_created);
        } else if choice == "I" {
            print!("{}", cfg.messages.import_enter_key);
            io::stdout().flush()?;
            let input = prompt_password()?;
            let input = input.trim();
            
            let account_config = if input.starts_with('{') {
                 match serde_json::from_str::<AccountConfig>(input) {
                    Ok(ac) => ac,
                    Err(_) => {
                        println!("❌ Invalid JSON");
                        continue;
                    }
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
                    println!("{}", cfg.messages.import_derivation_warning);
                },
                Err(_) => println!("{}", cfg.messages.import_exists),
            }
        } else if let Ok(index) = choice.parse::<usize>() {
            if index < current_accounts.len() {
                // 进入单账户操作
                if let Err(e) = process_single_account_interactive(&current_accounts[index], index, &current_accounts, cfg).await {
                    println!("{}{}", cfg.messages.error_prefix, e);
                }
            }
        }
    }
    Ok(())
}

// 交互模式下的单账户操作
async fn process_single_account_interactive(
    account: &AccountConfig, 
    idx: usize, 
    all_accounts: &[AccountConfig],
    cfg: &Config
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
        _ => {}
    }
    Ok(())
}

// ==================== 通用辅助函数 ====================

/// 加载并解密，返回 (Keystore对象, 私钥列表, 密码字符串)
fn load_and_decrypt(filepath: &str, msgs: &i18n::Messages) -> Result<(Keystore, Vec<AccountConfig>, String)> {
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
    print!("{}", msgs.set_password);
    io::stdout().flush()?;
    let password = prompt_password()?;
    
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