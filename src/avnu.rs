use serde::{Deserialize, Serialize};
use reqwest::Client;
use anyhow::Result;
use starknet::core::types::{Call, Felt};
use starknet::core::utils::get_selector_from_name;

#[derive(Debug, Clone, Copy)]
pub enum AvnuNetwork {
    Mainnet,
    Sepolia,
}

impl AvnuNetwork {
    pub fn base_url(&self) -> &str {
        match self {
            AvnuNetwork::Mainnet => "https://starknet.api.avnu.fi",
            AvnuNetwork::Sepolia => "https://sepolia.api.avnu.fi",
        }
    }
}

pub struct AvnuClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Token {
    pub name: String,
    pub symbol: String,
    pub address: String,
    pub decimals: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct QuoteResponse {
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "sellAmount")]
    pub sell_amount: String,
    #[serde(rename = "buyAmount")]
    pub buy_amount: String,
    #[serde(rename = "buyAmountWithoutFees")]
    pub buy_amount_without_fees: String,
}

#[derive(Debug, Serialize)]
struct BuildSwapRequest {
    #[serde(rename = "quoteId")]
    quote_id: String,
    #[serde(rename = "takerAddress")]
    taker_address: String,
    slippage: f64,
    #[serde(rename = "includeApprove")]
    include_approve: bool,
}

#[derive(Debug, Deserialize)]
struct BuildSwapResponse {
    #[serde(rename = "contractAddress")]
    contract_address: String,
    entrypoint: String,
    calldata: Vec<String>,
}

#[derive(Deserialize)]
struct Page<T> {
    content: Vec<T>,
}

impl AvnuClient {
    pub fn new(network: AvnuNetwork) -> Self {
        Self {
            client: Client::new(),
            base_url: network.base_url().to_string(),
        }
    }

    pub async fn get_tokens(&self) -> Result<Vec<Token>> {
        let url = format!("{}/swap/v1/tokens?size=100", self.base_url);
        let resp: Page<Token> = self.client.get(&url).send().await?.json().await?;
        Ok(resp.content)
    }

    pub async fn get_quote(&self, sell_token: &str, buy_token: &str, sell_amount_wei: &str) -> Result<QuoteResponse> {
        let url = format!("{}/swap/v1/quotes", self.base_url);
        println!("DEBUG: Requesting quote: {} -> {} (Amount: {})", sell_token, buy_token, sell_amount_wei); // Log params
        let resp: Vec<QuoteResponse> = self.client
            .get(&url)
            .query(&[
                ("sellTokenAddress", sell_token),
                ("buyTokenAddress", buy_token),
                ("sellAmount", sell_amount_wei),
            ])
            .send().await?
            .json().await?;
        
        // Return best quote (first one usually)
        resp.into_iter().next().ok_or_else(|| anyhow::anyhow!("No quotes found"))
    }

    pub async fn build_swap(&self, quote_id: &str, taker_address: &str, slippage: f64, sell_token_address: &str, sell_amount_wei: &str) -> Result<Vec<Call>> {
        let url = format!("{}/swap/v1/build", self.base_url);
        let req = BuildSwapRequest {
            quote_id: quote_id.to_string(),
            taker_address: taker_address.to_string(),
            slippage,
            include_approve: false, // We handle it manually now
        };

        // The API returns the Call directly as the JSON body
        let resp: BuildSwapResponse = self.client.post(&url).json(&req).send().await?.json().await?;

        let mut calls = Vec::new();

        // 1. Manually create Approve Call
        // Router Address is the contract that needs approval (resp.contractAddress)
        let router_address = Felt::from_hex(&resp.contract_address)?;
        let token_address = Felt::from_hex(sell_token_address)?;
        let approve_selector = get_selector_from_name("approve")?;
        
        // Amount is U256 (low, high). Parsing from hex string.
        // sell_amount_wei should be a hex string like "0x123..."

        // Wait, U256 conversion might be tricky manually. Let's use Felt for now if it fits or u128.
        // Actually, amount in hex string might be small or large.
        // Let's use BigUint or similar? Or just simple u128 if we assume < 2^128 for now (user input was u128).
        // The main.rs converts amount to u128 for hex string.
        // So we can parse u128 from hex.
        let amount_u128 = u128::from_str_radix(sell_amount_wei.trim_start_matches("0x"), 16)?;
        let amount_low = Felt::from(amount_u128);
        let amount_high = Felt::ZERO; // Assuming < 2^128

        calls.push(Call {
             to: token_address,
             selector: approve_selector,
             calldata: vec![router_address, amount_low, amount_high],
        });

        // 2. Add Swap Call
        let contract_address = Felt::from_hex(&resp.contract_address)?; // Router
        let selector = get_selector_from_name(&resp.entrypoint)?;
        let calldata: Result<Vec<Felt>, _> = resp.calldata.iter().map(|s| Felt::from_hex(s)).collect();
        
        calls.push(Call {
            to: contract_address,
            selector,
            calldata: calldata?,
        });

        Ok(calls)
    }
}
