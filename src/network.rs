use starknet::core::types::{BlockId, BlockTag, Call, FunctionCall, Felt};
use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider};
use starknet::accounts::{Account, SingleOwnerAccount, ExecutionEncoding};
use starknet::signers::{LocalWallet, SigningKey};
use starknet::core::utils::get_selector_from_name;
use starknet::accounts::{AccountFactory, OpenZeppelinAccountFactory};
use url::Url;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct AccountPoolInfo {
    pub staked_amount: f64,
    pub unpool_amount: f64,
    pub unpool_time: u64,
}

// ==================== 查余额 ====================
pub async fn get_balance(rpc_url: &str, strk_contract: &str, user_address_str: &str) -> Result<f64> {
    get_token_balance(rpc_url, strk_contract, user_address_str, 18).await
}

pub async fn get_token_balance(rpc_url: &str, token_address_str: &str, user_address_str: &str, decimals: u32) -> Result<f64> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));

    let contract_address = Felt::from_hex(token_address_str)?;
    let user_address = Felt::from_hex(user_address_str)?;
    let selector = get_selector_from_name("balanceOf")?;

    let call_request = FunctionCall {
        contract_address,
        entry_point_selector: selector,
        calldata: vec![user_address],
    };

    match provider.call(call_request, BlockId::Tag(BlockTag::Latest)).await {
        Ok(res) => {
            if res.len() >= 2 {
                let low = res[0]; // Assuming U256 returns [low, high]
                // For simplicity assuming balance fits in u128 (low part). 
                // To be robust we should handle high part but f64 precision is limited anyway.
                let balance_u128: u128 = match low.try_into() { Ok(val) => val, Err(_) => 0 };
                let divisor = 10f64.powi(decimals as i32);
                Ok(balance_u128 as f64 / divisor)
            } else {
                Ok(0.0)
            }
        },
        Err(_) => Ok(0.0)
    }
}

// ==================== 检查状态 ====================
pub async fn is_account_deployed(rpc_url: &str, address_str: &str) -> Result<bool> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    let address = Felt::from_hex(address_str)?;
    
    match provider.get_class_hash_at(BlockId::Tag(BlockTag::Latest), address).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ==================== 部署/激活 ====================
pub async fn deploy_account(
    rpc_url: &str, 
    class_hash_hex: &str,
    private_key: Felt, 
    public_key: Felt,
    log_msg: &str
) -> Result<String> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    
    // ✅ 自动获取当前网络的 Chain ID，防止配置错误导致签名无效
    let chain_id = provider.chain_id().await?;

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let class_hash = Felt::from_hex(class_hash_hex)?;
    
    let factory = OpenZeppelinAccountFactory::new(
        class_hash,
        chain_id,
        signer,
        provider,
    ).await?;

    let deployment = factory.deploy_v3(public_key);
    println!("{}", log_msg);
    let result = deployment.send().await?;

    Ok(format!("{:#x}", result.transaction_hash))
}

// ==================== 转账功能 ====================
pub async fn transfer_strk(
    rpc_url: &str,
    strk_contract: &str,
    sender_address: &str,
    private_key: Felt,
    recipient_address: &str,
    amount: f64,
    log_msgs: (&str, &str, &str) // (building_msg, target_label, amount_label)
) -> Result<String> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    // ✅ 自动获取 Chain ID
    let chain_id = provider.chain_id().await?;
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let sender_felt = Felt::from_hex(sender_address)?;

    // 1. 初始化账户
    let account = SingleOwnerAccount::new(
    provider,
    signer,
    sender_felt,
    chain_id,
    ExecutionEncoding::New,
    );

    // 2. 准备金额 (u256: low, high)
    let amount_wei = (amount * 1_000_000_000_000_000_000.0) as u128;
    let amount_low = Felt::from(amount_wei);
    let amount_high = Felt::ZERO;

    // 3. 构建调用 (Call)
    let recipient_felt = Felt::from_hex(recipient_address)?;
    let contract_address = Felt::from_hex(strk_contract)?;
    
    let transfer_call = Call {
        to: contract_address,
        selector: get_selector_from_name("transfer")?,
        calldata: vec![
            recipient_felt,
            amount_low,
            amount_high
        ],
    };

    println!("{}", log_msgs.0);
    println!("{}{}", log_msgs.1, recipient_address);
    println!("{}{}", log_msgs.2, amount);

    // 4. 发送交易 (V3)
    let result = account
        .execute_v3(vec![transfer_call])
        .send()
        .await?;

    Ok(format!("{:#x}", result.transaction_hash))
}

// ==================== 批量转账 (Multicall) ====================
pub async fn multi_transfer_strk(
    rpc_url: &str,
    strk_contract: &str,
    sender_address: &str,
    private_key: Felt,
    recipients: Vec<(String, f64)>, // (Address, Amount)
    log_msg: &str
) -> Result<String> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    let chain_id = provider.chain_id().await?;
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let sender_felt = Felt::from_hex(sender_address)?;

    let account = SingleOwnerAccount::new(
        provider,
        signer,
        sender_felt,
        chain_id,
        ExecutionEncoding::New,
    );

    let contract_address = Felt::from_hex(strk_contract)?;
    let selector = get_selector_from_name("transfer")?;

    let mut calls = Vec::new();
    for (recipient_addr, amount) in recipients {
        let recipient_felt = Felt::from_hex(&recipient_addr)?;
        let amount_wei = (amount * 1_000_000_000_000_000_000.0) as u128;
        let amount_low = Felt::from(amount_wei);
        let amount_high = Felt::ZERO;

        calls.push(Call {
            to: contract_address,
            selector,
            calldata: vec![recipient_felt, amount_low, amount_high],
        });
    }

    println!("{}", log_msg);

    let result = account
        .execute_v3(calls)
        .send()
        .await?;

    Ok(format!("{:#x}", result.transaction_hash))
}

// ==================== 估算转账费用 ====================
pub async fn estimate_transfer_fee(
    rpc_url: &str,
    strk_contract: &str,
    sender_address: &str,
    private_key: Felt,
    recipient_address: &str,
    amount: f64
) -> Result<f64> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    let chain_id = provider.chain_id().await?;
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let sender_felt = Felt::from_hex(sender_address)?;

    let account = SingleOwnerAccount::new(provider, signer, sender_felt, chain_id, ExecutionEncoding::New);

    let amount_wei = (amount * 1_000_000_000_000_000_000.0) as u128;
    let recipient_felt = Felt::from_hex(recipient_address)?;
    let contract_address = Felt::from_hex(strk_contract)?;

    let call = Call {
        to: contract_address,
        selector: get_selector_from_name("transfer")?,
        calldata: vec![recipient_felt, Felt::from(amount_wei), Felt::ZERO],
    };

    let estimate = account.execute_v3(vec![call]).estimate_fee().await?;
    
    let overall_fee_u128: u128 = estimate.overall_fee.try_into().unwrap_or(0);
    Ok(overall_fee_u128 as f64 / 1_000_000_000_000_000_000.0)
}

// ==================== 获取质押池地址 ====================
pub async fn get_pool_address(
    rpc_url: &str,
    staking_contract: &str,
    staker_address: &str
) -> Result<String> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    
    let contract_address = Felt::from_hex(staking_contract)?;
    let staker_felt = Felt::from_hex(staker_address)?;
    let selector = get_selector_from_name("staker_pool_info")?;

    let call_request = FunctionCall {
        contract_address,
        entry_point_selector: selector,
        calldata: vec![staker_felt],
    };

    let res = provider.call(call_request, BlockId::Tag(BlockTag::Latest)).await?;
    
    if res.len() <= 3 {
        return Err(anyhow::anyhow!("Invalid response length from staker_pool_info"));
    }

    // Based on debug observation, the pool contract address is at index 3.
    let pool_addr = res[3];
    if pool_addr == Felt::ZERO {
        return Err(anyhow::anyhow!("Staker has no active Delegation Pool (address at index 3 is 0x0). Please choose another validator."));
    }

    Ok(format!("{:#x}", pool_addr))
}


// ==================== 质押 (Delegate) ====================
pub async fn delegate_strk(
    rpc_url: &str,
    strk_contract: &str,
    pool_contract: &str,
    sender_address: &str,
    private_key: Felt,
    amount: f64
) -> Result<String> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    let chain_id = provider.chain_id().await?;
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let sender_felt = Felt::from_hex(sender_address)?;

    // 1. Initialize Account
    let account = SingleOwnerAccount::new(
        provider,
        signer,
        sender_felt,
        chain_id,
        ExecutionEncoding::New,
    );

    // 2. Prepare Amount (u256)
    let amount_wei = (amount * 1_000_000_000_000_000_000.0) as u128;
    let amount_low = Felt::from(amount_wei);
    let amount_high = Felt::ZERO;

    let pool_address_felt = Felt::from_hex(pool_contract)?;
    let strk_address_felt = Felt::from_hex(strk_contract)?;

    // 3. Construct Calls for Multicall
    let mut calls = Vec::new();

    // Call 1: Approve STRK to Pool Contract
    // approve(spender, amount)
    calls.push(Call {
        to: strk_address_felt,
        selector: get_selector_from_name("approve")?,
        calldata: vec![pool_address_felt, amount_low, amount_high],
    });

    // Call 2: Delegate (Enter or Add)
    // Check if user already has a stake
    let current_stake = get_staked_balance(rpc_url, pool_contract, sender_address).await.unwrap_or(0.0);
    
    if current_stake > 0.0 {
        // Existing staker: Use add_to_delegation_pool
        // Signature: add_to_delegation_pool(pool_member, amount)
        println!("   -> Detecting existing stake of {} STRK. Adding to pool...", current_stake);
        calls.push(Call {
            to: pool_address_felt,
            selector: get_selector_from_name("add_to_delegation_pool")?,
            calldata: vec![sender_felt, amount_low],
        });
        println!("   2. Add {} STRK to Delegation Pool", amount);
    } else {
        // New staker: Use enter_delegation_pool
        // enter_delegation_pool(reward_address, amount)
        println!("   -> New staker. Entering pool...");
        calls.push(Call {
            to: pool_address_felt,
            selector: get_selector_from_name("enter_delegation_pool")?,
            calldata: vec![sender_felt, amount_low],
        });
        println!("   2. Enter Delegation Pool with {} STRK", amount);
    }

    // 4. Send Transaction
    let result = account
        .execute_v3(calls)
        .send()
        .await?;

    Ok(format!("{:#x}", result.transaction_hash))
}

// ==================== 查询账户质押信息 (Get Account Pool Info) ====================
pub async fn get_account_pool_info(
    rpc_url: &str,
    pool_contract: &str,
    user_address: &str
) -> Result<AccountPoolInfo> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));

    let contract_address = Felt::from_hex(pool_contract)?;
    let user_felt = Felt::from_hex(user_address)?;
    
    let selector = get_selector_from_name("get_pool_member_info_v1")?;

    let call_request = FunctionCall {
        contract_address,
        entry_point_selector: selector,
        calldata: vec![user_felt],
    };

    match provider.call(call_request, BlockId::Tag(BlockTag::Latest)).await {
        Ok(res) => {
            
            // Relaxed parsing:
            // Staked Amount (Indices 2, 3) is always present if len >= 4
            // Unpooled info might be missing or optional?
            
            let mut staked_amount = 0.0;
            let mut unpool_amount = 0.0;
            let mut unpool_time = 0;

            if res.len() >= 4 {
                let amount_low: u128 = res[2].try_into().unwrap_or(0);
                staked_amount = amount_low as f64 / 1_000_000_000_000_000_000.0;
            }

            if res.len() >= 8 {
                let unpool_low: u128 = res[5].try_into().unwrap_or(0);
                unpool_amount = unpool_low as f64 / 1_000_000_000_000_000_000.0;
                unpool_time = res[7].try_into().unwrap_or(0);
            }

            // Remove debug print for clean output
            
            Ok(AccountPoolInfo {
                staked_amount,
                unpool_amount,
                unpool_time,
            })
        },
        Err(_) => {
            // Pool might not exist or user not in it
            Ok(AccountPoolInfo { staked_amount: 0.0, unpool_amount: 0.0, unpool_time: 0 })
        }
    }
}

// Keep legacy-like signature for compatibility/convenience if needed, but better to upgrade callers.
// Helper to just get staked (legacy uses)
pub async fn get_staked_balance(
    rpc_url: &str,
    pool_contract: &str,
    user_address: &str
) -> Result<f64> {
     let info = get_account_pool_info(rpc_url, pool_contract, user_address).await?;
     Ok(info.staked_amount)
}

// ==================== 解除质押意图 (Unstake Intent) ====================
pub async fn unstake_intent(
    rpc_url: &str,
    pool_contract: &str,
    sender_address: &str,
    private_key: Felt,
    amount: f64
) -> Result<String> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    let chain_id = provider.chain_id().await?;
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let sender_felt = Felt::from_hex(sender_address)?;

    let account = SingleOwnerAccount::new(
        provider,
        signer,
        sender_felt,
        chain_id,
        ExecutionEncoding::New,
    );

    let amount_wei = (amount * 1_000_000_000_000_000_000.0) as u128;
    let amount_low = Felt::from(amount_wei);

    let pool_address_felt = Felt::from_hex(pool_contract)?;

    // Call: exit_delegation_pool_intent(amount)
    let call = Call {
        to: pool_address_felt,
        selector: get_selector_from_name("exit_delegation_pool_intent")?,
        calldata: vec![amount_low], 
    };

    let result = account
        .execute_v3(vec![call])
        .send()
        .await?;

    Ok(format!("{:#x}", result.transaction_hash))
}

// ==================== 解除质押动作 (Unstake Action / Withdraw) ====================
pub async fn unstake_action(
    rpc_url: &str,
    pool_contract: &str,
    sender_address: &str,
    private_key: Felt
) -> Result<String> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));
    let chain_id = provider.chain_id().await?;
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    let sender_felt = Felt::from_hex(sender_address)?;

    let account = SingleOwnerAccount::new(
        provider,
        signer,
        sender_felt,
        chain_id,
        ExecutionEncoding::New,
    );

    let pool_address_felt = Felt::from_hex(pool_contract)?;

    // Check for pending unstake
    let info = get_account_pool_info(rpc_url, pool_contract, sender_address).await?;
    
    if info.unpool_amount <= 0.0 {
        return Err(anyhow::anyhow!("No pending unstake funds found. You must 'unstake' (start intent) first."));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if info.unpool_time > now {
         let wait = info.unpool_time - now;
         return Err(anyhow::anyhow!("Unstake funds not ready yet. Please wait {} seconds.", wait));
    }

    // Call: exit_delegation_pool_action(pool_member)
    let call = Call {
        to: pool_address_felt,
        selector: get_selector_from_name("exit_delegation_pool_action")?,
        calldata: vec![sender_felt],
    };

    let result = account
        .execute_v3(vec![call])
        .send()
        .await?;

    Ok(format!("{:#x}", result.transaction_hash))
}