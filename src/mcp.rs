use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use crate::config::Config;
use crate::keystore::{AccountConfig, Keystore};
use crate::network;
use crate::avnu::{AvnuClient, AvnuNetwork};

use starknet::core::types::Felt;


// Simplified JSON-RPC Request/Response structures
#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Serialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<Value>,
}

#[derive(Serialize, Debug)]
struct JsonRpcError {
    code: i32,
    message: String,
    data: Option<Value>,
}

pub struct McpServer {
    config: Config,
    accounts: Vec<AccountConfig>,
    avnu_client: AvnuClient,
}

impl McpServer {
    pub fn new(config: Config, mut accounts: Vec<AccountConfig>) -> Self {
        let network = if config.rpc_url.contains("sepolia") { AvnuNetwork::Sepolia } else { AvnuNetwork::Mainnet };
        
        // Ensure addresses are present for all accounts
        for account in &mut accounts {
            if account.address.is_none() {
                 if let Ok(computed) = Keystore::compute_address(account, &config.oz_class_hash) {
                     account.address = Some(computed);
                 }
            }
        }

        Self {
            config,
            accounts,
            avnu_client: AvnuClient::new(network),
        }
    }

    pub fn account_address(&self) -> &str {
        self.accounts.first().and_then(|a| a.address.as_deref()).unwrap_or("Unknown")
    }
    
    fn get_account(&self, address: Option<&str>) -> Result<&AccountConfig> {
        if self.accounts.is_empty() {
             return Err(anyhow::anyhow!("No accounts loaded"));
        }
        
        match address {
            Some(addr) => {
                self.accounts.iter().find(|a| {
                    a.address.as_deref().map(|s| s.eq_ignore_ascii_case(addr)).unwrap_or(false)
                }).ok_or_else(|| anyhow::anyhow!("Account not found: {}", addr))
            },
            None => Ok(&self.accounts[0])
        }
    }

    pub async fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() { continue; }

            // Log raw input for debug (optional, can be removed)
            // eprintln!("DEBUG MCP Input: {}", line);

            let req: Result<JsonRpcRequest, _> = serde_json::from_str(&line);
            match req {
                Ok(req) => {
                    let is_notification = req.id.is_none();
                    let resp = self.handle_request(req).await;
                    
                    if !is_notification {
                        let resp_str = serde_json::to_string(&resp)?;
                        writeln!(stdout, "{}", resp_str)?;
                        stdout.flush()?;
                    }
                }
                Err(e) => {
                    // Only respond with error if it wasn't a notification (but hard to know if parse failed)
                    // Usually we respond with Parse Error for invalid JSON
                    let err_resp = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32700,
                            message: format!("Parse error: {}", e),
                            data: None,
                        }),
                        id: None,
                    };
                    writeln!(stdout, "{}", serde_json::to_string(&err_resp)?)?;
                    stdout.flush()?;
                }
            }
        }
        Ok(())
    }

    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        match req.method.as_str() {
            "initialize" => {
                // MCP Handshake
                // Returns capabilities
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "stark-ark-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": {}
                    }
                });
                self.ok_response(req.id, result)
            },
            "tools/list" => {
                let tools = vec![
                    json!({
                        "name": "list_accounts",
                        "description": "List all available wallet accounts with their addresses.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    }),
                    json!({
                        "name": "get_balance",
                        "description": "Get token balance for a specific account.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "token_symbol": { "type": "string", "description": "Token Symbol (e.g. ETH, STRK). Default: ETH" },
                                "account_address": { "type": "string", "description": "Account address to check. Defaults to primary account." }
                            }
                        }
                    }),
                    json!({
                        "name": "get_tokens",
                        "description": "List all supported tokens on AVNU.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    }),
                    json!({
                        "name": "swap",
                        "description": "Swap tokens using AVNU aggregator.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "sell_token": { "type": "string", "description": "Token to sell (Symbol or Address)" },
                                "buy_token": { "type": "string", "description": "Token to buy (Symbol or Address)" },
                                "amount": { "type": "number", "description": "Amount to sell" },
                                "slippage": { "type": "number", "description": "Max slippage (default 0.005)" },
                                "account_address": { "type": "string", "description": "Account address to execute swap. Defaults to primary account." }
                            },
                            "required": ["sell_token", "buy_token", "amount"]
                        }
                    }),
                    json!({
                        "name": "transfer",
                        "description": "Transfer funds to another address.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "to": { "type": "string", "description": "Recipient address" },
                                "amount": { "type": "number", "description": "Amount to transfer" },
                                "token_symbol": { "type": "string", "description": "Token Symbol (e.g. STRK, ETH). Default: STRK" },
                                "account_address": { "type": "string", "description": "Account address to send from. Defaults to primary account." }
                            },
                            "required": ["to", "amount"]
                        }
                    }),
                    json!({
                        "name": "stake",
                        "description": "Stake (Delegate) STRK to a validator pool.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "amount": { "type": "number", "description": "Amount of STRK to stake" },
                                "validator_address": { "type": "string", "description": "Validator Pool Address" },
                                "account_address": { "type": "string", "description": "Account address to stake from. Defaults to primary." }
                            },
                            "required": ["amount", "validator_address"]
                        }
                    }),
                    json!({
                        "name": "unstake",
                        "description": "Signal intent to unstake (unbind) STRK funds. Takes 14 days to become withdrawable.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "amount": { "type": "number", "description": "Amount of STRK to unstake" },
                                "validator_address": { "type": "string", "description": "Validator Address (Staker Address)" },
                                "account_address": { "type": "string", "description": "Account address to unstake from. Defaults to primary." }
                            },
                            "required": ["amount", "validator_address"]
                        }
                    }),
                    json!({
                        "name": "withdraw_unstaked",
                        "description": "Withdraw unstaked STRK funds after the unbonding period.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "validator_address": { "type": "string", "description": "Validator Address (Staker Address)" },
                                "account_address": { "type": "string", "description": "Account address to withdraw to. Defaults to primary." }
                            },
                            "required": ["validator_address"]
                        }
                    })
                ];
                self.ok_response(req.id, json!({ "tools": tools }))
            },
            "tools/call" => {
                if let Some(params) = req.params {
                    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let args = params.get("arguments").cloned().unwrap_or(json!({}));
                    
                    match name {
                        "list_accounts" => self.handle_list_accounts().await.wrap_response(req.id),
                        "get_balance" => self.handle_get_balance(args).await.wrap_response(req.id),
                        "get_tokens" => self.handle_get_tokens().await.wrap_response(req.id),
                        "swap" => self.handle_swap(args).await.wrap_response(req.id),
                        "transfer" => self.handle_transfer(args).await.wrap_response(req.id),
                        "stake" => self.handle_stake(args).await.wrap_response(req.id),
                        "unstake" => self.handle_unstake(args).await.wrap_response(req.id),
                        "withdraw_unstaked" => self.handle_withdraw_unstaked(args).await.wrap_response(req.id),
                        _ => self.error_response(req.id, -32601, format!("Method not found: {}", name))
                    }
                } else {
                     self.error_response(req.id, -32602, "Missing params".to_string())
                }
            },
            // Handle other standard JSON-RPC if needed or just ignore/error
            _ => self.error_response(req.id, -32601, "Method not found".to_string())
        }
    }

    fn ok_response(&self, id: Option<Value>, result: Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    fn error_response(&self, id: Option<Value>, code: i32, message: String) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError { code, message, data: None }),
            id,
        }
    }

    // --- Tool Handlers ---

    async fn handle_list_accounts(&self) -> Result<Value> {
         let content = self.accounts.iter().enumerate().map(|(i, a)| {
             let alias = a.alias.as_deref().unwrap_or("Unnamed");
             let addr = a.address.as_deref().unwrap_or("Unknown");
             format!("{}. {} ({})", i, alias, addr)
         }).collect::<Vec<_>>().join("\n");
         
         Ok(json!({
             "content": [{
                 "type": "text",
                 "text": format!("Available Accounts:\n{}", content)
             }]
         }))
    }

    async fn handle_get_balance(&self, args: Value) -> Result<Value> {
        let _symbol = args["token_symbol"].as_str().unwrap_or("ETH");
        let account_addr = args["account_address"].as_str();

        let eth = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
        let strk = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
        
        // Helper to check one account
        async fn check_one(rpc: &str, eth: &str, strk: &str, addr: &str, alias: &str, pool_contract: Option<&str>) -> Result<String> {
             let bal_eth = network::get_balance(rpc, eth, addr).await.unwrap_or(0.0);
             let bal_strk = network::get_balance(rpc, strk, addr).await.unwrap_or(0.0);
             let mut extra = String::new();
             
             // If Staking contract is known (from config), check staked balance
             if let Some(pool) = pool_contract {
                 let staked = network::get_staked_balance(rpc, pool, addr).await.unwrap_or(0.0);
                 if staked > 0.0 {
                     extra = format!(", Staked: {:.4} STRK", staked);
                 }
             }

             Ok(format!("- {} ({}): {:.4} ETH, {:.4} STRK{}", alias, addr, bal_eth, bal_strk, extra))
        }

        let mut lines = Vec::new();

        if let Some(req_addr) = account_addr {
            // Specific Account
            let account = self.get_account(Some(req_addr))?;
            let addr = account.address.as_deref().ok_or(anyhow::anyhow!("Account has no address"))?;
            let alias = account.alias.as_deref().unwrap_or("Unnamed");
            // Note: we might not know which pool they staked in unless we scan or have default. 
            // Using config.default_staker_address as a best guess for checking stake? 
            // Or we just skip stake check if unknown. 
            // For now, let's use config.staking_contract_address if set, or skip.
            let pool_contract = if !self.config.staking_contract_address.is_empty() { Some(self.config.staking_contract_address.as_str()) } else { None };
            
            lines.push(check_one(&self.config.rpc_url, eth, strk, addr, alias, pool_contract).await?);
        } else {
            // All Accounts
            let pool_contract = if !self.config.staking_contract_address.is_empty() { Some(self.config.staking_contract_address.as_str()) } else { None };
            
            for account in &self.accounts {
                if let Some(addr) = account.address.as_deref() {
                     let alias = account.alias.as_deref().unwrap_or("Unnamed");
                     lines.push(check_one(&self.config.rpc_url, eth, strk, addr, alias, pool_contract).await?);
                }
            }
        }
        
        Ok(json!({
            "content": [{
                "type": "text",
                "text": if lines.is_empty() { "No accounts found.".to_string() } else { lines.join("\n") }
            }]
        }))
    }

    async fn handle_get_tokens(&self) -> Result<Value> {
        let tokens = self.avnu_client.get_tokens().await?;
        let text = tokens.iter().take(20).map(|t| format!("- {} ({})", t.symbol, t.address)).collect::<Vec<_>>().join("\n");
        let extra = if tokens.len() > 20 { format!("\n... and {} more", tokens.len() - 20) } else { "".to_string() };
        
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("Supported Tokens:\n{}{}", text, extra)
            }]
        }))
    }

    async fn handle_swap(&self, args: Value) -> Result<Value> {
        let sell = args["sell_token"].as_str().ok_or(anyhow::anyhow!("Missing sell_token"))?;
        let buy = args["buy_token"].as_str().ok_or(anyhow::anyhow!("Missing buy_token"))?;
        let amount = args["amount"].as_f64().ok_or(anyhow::anyhow!("Missing amount"))?;
        let slippage = args["slippage"].as_f64().unwrap_or(0.005);
        let account_addr = args["account_address"].as_str();
        
        let account = self.get_account(account_addr)?;
        let addr = account.address.as_deref().ok_or(anyhow::anyhow!("Account has no address"))?;
        let priv_key = Felt::from_hex(&account.private_key)?;

        // Resolve tokens
        let tokens = self.avnu_client.get_tokens().await?;
        let sell_token = tokens.iter().find(|t| t.address == sell || t.symbol.eq_ignore_ascii_case(sell)).ok_or(anyhow::anyhow!("Sell token not found"))?;
        let buy_token = tokens.iter().find(|t| t.address == buy || t.symbol.eq_ignore_ascii_case(buy)).ok_or(anyhow::anyhow!("Buy token not found"))?;

        // Get Quote
        let amount_wei = (amount * 10f64.powi(sell_token.decimals as i32)).floor();
        let amount_str = format!("{:#x}", amount_wei as u128);
        
        let quote = self.avnu_client.get_quote(&sell_token.address, &buy_token.address, &amount_str).await?;
        
        // Build Tx
        let calls = self.avnu_client.build_swap(&quote.quote_id, &addr, slippage, &sell_token.address, &amount_str).await?;
        
        // Execute
        use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider};
        use starknet::accounts::{SingleOwnerAccount, ExecutionEncoding, Account};
        use starknet::signers::LocalWallet;
        use url::Url;
        use starknet::signers::SigningKey;
        
        let url = Url::parse(&self.config.rpc_url)?;
        let provider = JsonRpcClient::new(HttpTransport::new(url));
        let chain_id = provider.chain_id().await?;
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(priv_key));
        let sender_felt = Felt::from_hex(&addr)?;
        
        let account_obj = SingleOwnerAccount::new(
            provider,
            signer,
            sender_felt,
            chain_id,
            ExecutionEncoding::New,
        );

        let exec = account_obj.execute_v3(calls);
        let result = exec.send().await.context("Transaction execution failed")?;
        
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("Swap Sent! Hash: {:#x}", result.transaction_hash)
            }]
        }))
    }
    
    async fn handle_transfer(&self, args: Value) -> Result<Value> {
        let to = args["to"].as_str().ok_or(anyhow::anyhow!("Missing to address"))?;
        let amount = args["amount"].as_f64().ok_or(anyhow::anyhow!("Missing amount"))?;
        let symbol = args["token_symbol"].as_str().unwrap_or("STRK");
        let account_addr = args["account_address"].as_str();

        let account = self.get_account(account_addr)?;
        let addr = account.address.as_deref().ok_or(anyhow::anyhow!("Account has no address"))?;
        let priv_key = Felt::from_hex(&account.private_key)?;

        // Basic transfer logic similar to main.rs
        // Only supporting STRK for now in simple transfer tool for safety/simplicity
        if symbol.to_uppercase() != "STRK" {
             return Err(anyhow::anyhow!("Only STRK transfers supported in this version."));
        }

        let tx_hash = network::transfer_strk(
            &self.config.rpc_url, 
            &self.config.strk_contract_address, 
            &addr, 
            priv_key, 
            to, 
            amount,
            ("Transferring STRK", "Recipient", "Amount")
        ).await?;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("Transfer Sent! Hash: {}", tx_hash)
            }]
        }))
    }
    async fn handle_stake(&self, args: Value) -> Result<Value> {
        let amount = args["amount"].as_f64().ok_or(anyhow::anyhow!("Missing amount"))?;
        let validator_addr = args["validator_address"].as_str().ok_or(anyhow::anyhow!("Missing validator_address"))?;
        let account_addr = args["account_address"].as_str();

        let account = self.get_account(account_addr)?;
        let addr = account.address.as_deref().ok_or(anyhow::anyhow!("Account has no address"))?;
        let priv_key = Felt::from_hex(&account.private_key)?;
        
        // Resolve Pool Address
        let pool_addr = network::get_pool_address(&self.config.rpc_url, &self.config.staking_contract_address, validator_addr).await?;

        let tx_hash = network::delegate_strk(
            &self.config.rpc_url,
            &self.config.strk_contract_address,
            &pool_addr,
            addr,
            priv_key,
            amount
        ).await?;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("Staked {} STRK to {} using pool {}! Hash: {}", amount, validator_addr, pool_addr, tx_hash)
            }]
        }))
    }

    async fn handle_unstake(&self, args: Value) -> Result<Value> {
        let amount = args["amount"].as_f64().ok_or(anyhow::anyhow!("Missing amount"))?;
        let validator_addr = args["validator_address"].as_str().ok_or(anyhow::anyhow!("Missing validator_address"))?;
        let account_addr = args["account_address"].as_str();

        let account = self.get_account(account_addr)?;
        let addr = account.address.as_deref().ok_or(anyhow::anyhow!("Account has no address"))?;
        let priv_key = Felt::from_hex(&account.private_key)?;

        // Resolve Pool Address
        let pool_addr = network::get_pool_address(&self.config.rpc_url, &self.config.staking_contract_address, validator_addr).await?;

        let tx_hash = network::unstake_intent(
            &self.config.rpc_url,
            &pool_addr,
            addr,
            priv_key,
            amount
        ).await?;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("Unstake Intent ({} STRK) dispatched for validator {}! Hash: {}", amount, validator_addr, tx_hash)
            }]
        }))
    }

    async fn handle_withdraw_unstaked(&self, args: Value) -> Result<Value> {
        let validator_addr = args["validator_address"].as_str().ok_or(anyhow::anyhow!("Missing validator_address"))?;
        let account_addr = args["account_address"].as_str();

        let account = self.get_account(account_addr)?;
        let addr = account.address.as_deref().ok_or(anyhow::anyhow!("Account has no address"))?;
        let priv_key = Felt::from_hex(&account.private_key)?;

        // Resolve Pool Address
        let pool_addr = network::get_pool_address(&self.config.rpc_url, &self.config.staking_contract_address, validator_addr).await?;

        let tx_hash = network::unstake_action(
            &self.config.rpc_url,
            &pool_addr,
            addr,
            priv_key
        ).await?;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("Withdrawal of unstaked funds executed! Hash: {}", tx_hash)
            }]
        }))
    }
}

trait ResponseWrapper {
    fn wrap_response(self, id: Option<Value>) -> JsonRpcResponse;
}

impl ResponseWrapper for Result<Value> {
    fn wrap_response(self, id: Option<Value>) -> JsonRpcResponse {
        match self {
            Ok(v) => JsonRpcResponse { jsonrpc: "2.0".to_string(), result: Some(v), error: None, id },
            Err(e) => JsonRpcResponse { 
                jsonrpc: "2.0".to_string(), 
                result: None, 
                error: Some(JsonRpcError { code: -32000, message: e.to_string(), data: None }), 
                id 
            }
        }
    }
}
