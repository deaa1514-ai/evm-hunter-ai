//! Radar — يجلب العقود الجديدة من GeckoTerminal آخر 24 ساعة
use anyhow::{Result, Context};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct RadarToken {
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub chain: String,
    pub pool_address: String,
    pub created_at: String,
    pub liquidity_usd: f64,
    pub volume_24h: f64,
}

pub struct Radar {
    client: Client,
    min_liquidity_usd: f64,
    min_volume_usd: f64,
}

impl Radar {
    pub fn new(min_liquidity_usd: f64, min_volume_usd: f64) -> Self {
        Self {
            client: Client::builder()
                .user_agent("evm-bounty-hunter/0.2")
                .build()
                .unwrap_or_default(),
            min_liquidity_usd,
            min_volume_usd,
        }
    }

    /// جلب أحدث العقود من GeckoTerminal على شبكة معينة
    pub async fn fetch_new_tokens(&self, network: &str, pages: u32) -> Result<Vec<RadarToken>> {
        let mut tokens = Vec::new();
        let mut seen = HashSet::new();

        for page in 1..=pages {
            let url = format!(
                "https://api.geckoterminal.com/api/v2/networks/{}/new_pools?page={}",
                network, page
            );

            let resp = self.client.get(&url)
                .send().await
                .context("Failed to connect to GeckoTerminal")?;

            if !resp.status().is_success() {
                warn!("GeckoTerminal page {} returned {}", page, resp.status());
                break;
            }

            let json: Value = resp.json().await
                .context("Failed to parse GeckoTerminal response")?;

            let pools = match json["data"].as_array() {
                Some(p) => p,
                None => break,
            };

            if pools.is_empty() {
                break;
            }

            for pool in pools {
                let attrs = &pool["attributes"];

                // استخرج عنوان التوكن الأساسي
                let token_addr = pool["relationships"]["base_token"]["data"]["id"]
                    .as_str()
                    .unwrap_or("")
                    .split('_')
                    .last()
                    .unwrap_or("")
                    .to_lowercase();

                if token_addr.is_empty() || seen.contains(&token_addr) {
                    continue;
                }

                let liquidity = attrs["reserve_in_usd"]
                    .as_str()
                    .unwrap_or("0")
                    .parse::<f64>()
                    .unwrap_or(0.0);

                let volume = attrs["volume_usd"]["h24"]
                    .as_str()
                    .unwrap_or("0")
                    .parse::<f64>()
                    .unwrap_or(0.0);

                // فلتر: سيولة كافية فقط
                if liquidity < self.min_liquidity_usd || volume < self.min_volume_usd {
                    continue;
                }

                let pool_address = attrs["address"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase();

                let name = attrs["name"].as_str().unwrap_or("Unknown").to_string();
                let created_at = attrs["pool_created_at"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                // استخرج اسم ورمز التوكن من الاسم (مثل "PEPE / ETH")
                let (token_name, token_symbol) = parse_token_name(&name);

                seen.insert(token_addr.clone());
                tokens.push(RadarToken {
                    address: token_addr,
                    name: token_name,
                    symbol: token_symbol,
                    chain: network.to_string(),
                    pool_address,
                    created_at,
                    liquidity_usd: liquidity,
                    volume_24h: volume,
                });
            }

            // GeckoTerminal rate limit
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        }

        info!("Radar found {} new tokens on {}", tokens.len(), network);
        Ok(tokens)
    }

    /// جلب من شبكات متعددة
    pub async fn fetch_all_networks(&self, networks: &[&str], pages: u32) -> Vec<RadarToken> {
        let mut all = Vec::new();
        for network in networks {
            match self.fetch_new_tokens(network, pages).await {
                Ok(mut tokens) => all.append(&mut tokens),
                Err(e) => warn!("Failed to fetch from {}: {}", network, e),
            }
        }
        all
    }
}

fn parse_token_name(pool_name: &str) -> (String, String) {
    // "PEPE / ETH 0.3%" → name="PEPE", symbol="PEPE"
    let parts: Vec<&str> = pool_name.splitn(2, '/').collect();
    let raw = parts[0].trim();
    // أحياناً يكون "TokenName SYMBOL"
    let words: Vec<&str> = raw.split_whitespace().collect();
    match words.len() {
        0 => ("Unknown".to_string(), "?".to_string()),
        1 => (words[0].to_string(), words[0].to_string()),
        _ => (words[0].to_string(), words[words.len() - 1].to_string()),
    }
}
