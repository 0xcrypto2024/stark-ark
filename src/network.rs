use starknet::{
    // ❌ 删除这里的 Call
    accounts::{AccountFactory, OpenZeppelinAccountFactory, Account, SingleOwnerAccount, ExecutionEncoding},
    core::{
        // ✅ Call 移到了这里 (core::types)
        types::{BlockId, BlockTag, Felt, FunctionCall, Call}, 
        utils::get_selector_from_name,
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use url::Url;
use anyhow::Result;

// ==================== 查余额 ====================
pub async fn get_balance(rpc_url: &str, strk_contract: &str, user_address_str: &str) -> Result<f64> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));

    let contract_address = Felt::from_hex(strk_contract)?;
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
                let low = res[0];
                let balance_u128: u128 = match low.try_into() { Ok(val) => val, Err(_) => 0 };
                Ok(balance_u128 as f64 / 1_000_000_000_000_000_000.0)
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

    // Call 2: Enter Delegation Pool on Pool Contract
    // enter_delegation_pool(reward_address, amount)
    // Reward address defaults to sender
    // NOTE: Order is important! 
    // DEBUG: StakerPoolInfo suggests Amount is u128 (1 felt)
    calls.push(Call {
        to: pool_address_felt,
        selector: get_selector_from_name("enter_delegation_pool")?,
        calldata: vec![sender_felt, amount_low],
    });

    println!("Building Atomic Transaction...");
    println!("   1. Approve {} STRK to Pool {}", amount, pool_contract);
    println!("   2. Delegate {} STRK", amount);

    // 4. Send Transaction
    let result = account
        .execute_v3(calls)
        .send()
        .await?;

    Ok(format!("{:#x}", result.transaction_hash))
}

// ==================== 查询质押余额 ====================
pub async fn get_staked_balance(
    rpc_url: &str,
    pool_contract: &str,
    user_address: &str
) -> Result<f64> {
    let url = Url::parse(rpc_url)?;
    let provider = JsonRpcClient::new(HttpTransport::new(url));

    let contract_address = Felt::from_hex(pool_contract)?;
    let user_felt = Felt::from_hex(user_address)?;
    
    // Correct selector for Delegation Pool (v1)
    let selector = get_selector_from_name("get_pool_member_info_v1")?;

    let call_request = FunctionCall {
        contract_address,
        entry_point_selector: selector,
        calldata: vec![user_felt],
    };

    match provider.call(call_request, BlockId::Tag(BlockTag::Latest)).await {
        Ok(res) => {
            // PoolMemberInfo struct typical layout:
            // {
            //   amount: Amount (u128),     <- Index 0
            //   reward_address: Address,   <- Index 1
            //   ...
            // }
            // Debugging to be sure
            // Debug logging to be sure
            // println!("🔍 Debug: get_pool_member_info raw response: {:?}", res);
            
            // Debug confirms:
            // Index 0: 0x0
            // Index 1: Reward Address (User)
            // Index 2: Amount (1.0 STRK) => 0xde0b6b3a7640000
            
            if res.len() > 2 {
                let amount_felt = res[2];
                let balance_u128: u128 = match amount_felt.try_into() { Ok(val) => val, Err(_) => 0 };
                Ok(balance_u128 as f64 / 1_000_000_000_000_000_000.0)
            } else {
                Ok(0.0)
            }
        },
        Err(e) => {
            println!("Debug: Failed to get staked balance: {:?}", e);
            Ok(0.0)
        }
    }
}