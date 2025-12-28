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