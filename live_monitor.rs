// Auto-imported
use crate::auto_hunter::AutoHunter;
// Live Transaction Monitor — يراقب transactions على الشبكة
// يكتشف أنماط مشبوهة في real-time

use anyhow::Result;
use tracing::{info, warn};
use colored::*;

// ─── Known Safe Contracts (تجاهل) ───────────────────

const KNOWN_SAFE: &[&str] = &[
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH
    "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", // WBTC
    "0x6c3ea9036406852006290770bedfcaba0e23a0e8", // PYUSD
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
    "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 Router
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", // UNI
    "0x514910771af9ca656af840dff83e8264ecf986ca", // LINK
    "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9", // AAVE
    "0xc00e94cb662c3520282e6f5717214004a7f26888", // COMP
];

// ─── Suspicious Patterns ────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PatternSeverity {
    Critical,
    High,
    Medium,
}

// Function selectors + their risk level
// فقط الأنماط الخطيرة حقاً
const SUSPICIOUS_SELECTORS: &[(&str, &str, PatternSeverity, bool)] = &[
    // (selector, name, severity, requires_large_value)
    ("0x40c10f19", "mint(address,uint256)", PatternSeverity::Critical, false),
    ("0x1249c58b", "mint()", PatternSeverity::Critical, false),
    ("0x3659cfe6", "upgradeTo(address)", PatternSeverity::Critical, false),
    ("0x4f1ef286", "upgradeToAndCall(address,bytes)", PatternSeverity::Critical, false),
    ("0xf2fde38b", "transferOwnership(address)", PatternSeverity::High, false),
    ("0x5cffe9de", "flashLoan", PatternSeverity::Critical, false),
    ("0x2f2ff15d", "grantRole(bytes32,address)", PatternSeverity::High, false),
    ("0xd547741f", "revokeRole(bytes32,address)", PatternSeverity::High, false),
    ("0x9dc29fac", "burn(address,uint256)", PatternSeverity::High, false),
    ("0x42966c68", "burn(uint256)", PatternSeverity::High, false),
    ("0x8456cb59", "pause()", PatternSeverity::High, false),
    ("0x5c975abb", "paused()", PatternSeverity::Medium, false),
    // withdraw فقط لو مبلغ كبير (>1 ETH)
    ("0x2e1a7d4d", "withdraw(uint256)", PatternSeverity::High, true),
    ("0x3ccfd60b", "withdraw()", PatternSeverity::High, true),
    ("0xd9caed12", "withdraw(address,address,uint256)", PatternSeverity::High, true),
];

// ─── Transaction Event ───────────────────────────────

#[derive(Debug, Clone)]
pub struct TxEvent {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub input: String,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct SuspiciousTx {
    pub tx: TxEvent,
    pub pattern: String,
    pub severity: PatternSeverity,
    pub description: String,
    pub network: String,
}

// ─── Live Monitor ────────────────────────────────────

pub struct LiveMonitor {
    rpc_url: String,
    network_name: String,
    watched_contracts: Vec<String>,
    seen_contracts: std::collections::HashMap<String, std::time::Instant>,
}

impl LiveMonitor {
    pub fn new(rpc_url: String, network_name: String) -> Self {
        Self {
            rpc_url,
            network_name,
            watched_contracts: Vec::new(),
            seen_contracts: std::collections::HashMap::new(),
        }
    }

    pub fn watch_contract(&mut self, address: String) {
        self.watched_contracts.push(address.to_lowercase());
    }

    pub async fn poll_new_blocks(
        &mut self,
        callback: impl Fn(SuspiciousTx) + Send + Sync + 'static,
    ) -> Result<()> {
        info!("👁️  [{}] Starting live monitor...", self.network_name);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let mut last_block = self.get_latest_block(&client).await?;
        // Retry up to 5 times if block is 0
        let mut retries = 0;
        while last_block == 0 && retries < 5 {
            warn!("[{}] Failed to get latest block — retrying ({}/5)...", self.network_name, retries + 1);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            last_block = self.get_latest_block(&client).await.unwrap_or(0);
            retries += 1;
        }
        if last_block == 0 {
            warn!("[{}] Could not get latest block after 5 retries — skipping", self.network_name);
            return Ok(());
        }
        // Retry up to 5 times if block is 0
        let mut retries = 0;
        while last_block == 0 && retries < 5 {
            warn!("[{}] Failed to get latest block — retrying ({}/5)...", self.network_name, retries + 1);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            last_block = self.get_latest_block(&client).await.unwrap_or(0);
            retries += 1;
        }
        if last_block == 0 {
            warn!("[{}] Could not get latest block after 5 retries — skipping", self.network_name);
            return Ok(());
        }
        info!("📦 [{}] Starting from block: {}", self.network_name, last_block);

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(12)).await;

            let current_block = match self.get_latest_block(&client).await {
                Ok(b) => b,
                Err(e) => { warn!("[{}] Block fetch error: {}", self.network_name, e); continue; }
            };

            if current_block <= last_block { continue; }

            for block_num in (last_block + 1)..=current_block {
                match self.scan_block(&client, block_num).await {
                    Ok(suspicious) => {
                        for s in suspicious {
                            let severity_str = match s.severity {
                                PatternSeverity::Critical => "🔴 CRITICAL".red().bold().to_string(),
                                PatternSeverity::High     => "🟠 HIGH".yellow().bold().to_string(),
                                PatternSeverity::Medium   => "🟡 MEDIUM".yellow().to_string(),
                            };
                            println!("\n   {} [{}] Block #{}", severity_str, s.network.cyan(), block_num);
                            println!("   Pattern  : {}", s.pattern.red().bold());
                            println!("   Contract : {}", s.tx.to.yellow());
                            println!("   From     : {}", s.tx.from.cyan());
                            let explorer = match s.network.as_str() {
        "bsc"      => "https://bscscan.com/tx/",
        "base"     => "https://basescan.org/tx/",
        "arbitrum" => "https://arbiscan.io/tx/",
        "polygon"  => "https://polygonscan.com/tx/",
        "optimism" => "https://optimistic.etherscan.io/tx/",
        "avalanche"=> "https://snowtrace.io/tx/",
        _          => "https://etherscan.io/tx/",
    };
    println!("   TxHash   : {}{}", explorer, s.tx.hash);
                            callback(s);
                        }
                    }
                    Err(e) => warn!("[{}] Block scan error {}: {}", self.network_name, block_num, e),
                }
            }

            last_block = current_block;
        }
    }

    async fn get_latest_block(&self, client: &reqwest::Client) -> Result<u64> {
        let resp = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1
            }))
            .send().await?;

        let data: serde_json::Value = resp.json().await?;
        let hex = data["result"].as_str().unwrap_or("0x0");
        Ok(u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0))
    }

    async fn scan_block(&mut self, client: &reqwest::Client, block_num: u64) -> Result<Vec<SuspiciousTx>> {
        let block_hex = format!("0x{:x}", block_num);

        let resp = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [block_hex, true],
                "id": 1
            }))
            .send().await?;

        let data: serde_json::Value = resp.json().await?;
        let txs = data["result"]["transactions"].as_array().cloned().unwrap_or_default();

        let mut suspicious = Vec::new();

        for tx in &txs {
            let to = tx["to"].as_str().unwrap_or("").to_lowercase();
            let input = tx["input"].as_str().unwrap_or("0x");
            let from = tx["from"].as_str().unwrap_or("");
            let hash = tx["hash"].as_str().unwrap_or("");
            let value = tx["value"].as_str().unwrap_or("0x0");

            // تجاهل العقود المعروفة
            if KNOWN_SAFE.contains(&to.as_str()) { continue; }

            // تجاهل لو مش في قائمة المراقبة
            if !self.watched_contracts.is_empty()
               && !self.watched_contracts.contains(&to) { continue; }

            if let Some(s) = self.detect_pattern(hash, from, &to, value, input) {
                // Dedup — نفس العقد مرة كل ساعة فقط
                let key = format!("{}:{}", to, s.pattern);
                let now = std::time::Instant::now();
                let cooldown = std::time::Duration::from_secs(3600);
                if self.seen_contracts.get(&key).map(|t| t.elapsed() > cooldown).unwrap_or(true) {
                    self.seen_contracts.insert(key, now);
                    suspicious.push(s);
                }
            }
        }

        Ok(suspicious)
    }

    fn detect_pattern(&self, hash: &str, from: &str, to: &str, value: &str, input: &str) -> Option<SuspiciousTx> {
        if input.len() < 10 { return None; }
        let selector = &input[..10];

        for (sel, name, severity, requires_large) in SUSPICIOUS_SELECTORS {
            if selector != *sel { continue; }

            // لو يحتاج مبلغ كبير، تحقق
            if *requires_large {
                let val_num = u128::from_str_radix(value.trim_start_matches("0x"), 16).unwrap_or(0);
                let one_eth = 1_000_000_000_000_000_000u128; // 1 ETH in wei
                if val_num < one_eth { continue; } // تجاهل المبالغ الصغيرة
            }

            return Some(SuspiciousTx {
                tx: TxEvent {
                    hash: hash.to_string(),
                    from: from.to_string(),
                    to: to.to_string(),
                    value: value.to_string(),
                    input: input[..input.len().min(100)].to_string(),
                    block_number: 0,
                },
                pattern: name.to_string(),
                severity: severity.clone(),
                description: format!("{} called on {} by {}", name, &to[..to.len().min(10)], &from[..from.len().min(10)]),
                network: self.network_name.clone(),
            });
        }
        None
    }
}

// ─── Multi-chain Monitor Command ────────────────────

pub async fn run_monitor(
    rpc_url: String,
    contracts: Vec<String>,
    telegram_enabled: bool,
    networks: Vec<String>,
) -> Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║   👁️  LIVE MONITOR  ACTIVE  🔴        ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());

    // Build RPC list
    let mut rpc_list: Vec<(String, String)> = Vec::new();

    let nets = if networks.is_empty() { vec!["eth".to_string()] } else { networks.clone() };

    for net in &nets {
        let rpc = match net.as_str() {
            "eth"       => std::env::var("RPC_URL").unwrap_or_else(|_| rpc_url.clone()),
            "base"      => std::env::var("BASE_RPC_URL").unwrap_or_else(|_| "https://base.drpc.org".to_string()),
            "arbitrum"  => std::env::var("ARBITRUM_RPC_URL").unwrap_or_else(|_| "https://arbitrum.drpc.org".to_string()),
            "polygon"   => std::env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon.drpc.org".to_string()),
            "optimism"  => std::env::var("OPTIMISM_RPC_URL").unwrap_or_else(|_| "https://optimism.drpc.org".to_string()),
            "bsc"       => std::env::var("BSC_RPC_URL").unwrap_or_else(|_| "https://bsc.drpc.org".to_string()),
            "bnb"       => std::env::var("BSC_RPC_URL").unwrap_or_else(|_| "https://bsc.drpc.org".to_string()),
            "avalanche" | "avax" => std::env::var("AVAX_RPC_URL").unwrap_or_else(|_| "https://avalanche.drpc.org".to_string()),
            "fantom"    | "ftm"  => std::env::var("FTM_RPC_URL").unwrap_or_else(|_| "https://fantom.drpc.org".to_string()),
            "zksync"    => std::env::var("ZKSYNC_RPC_URL").unwrap_or_else(|_| "https://zksync.drpc.org".to_string()),
            "linea"     => std::env::var("LINEA_RPC_URL").unwrap_or_else(|_| "https://linea.drpc.org".to_string()),
            "blast"     => std::env::var("BLAST_RPC_URL").unwrap_or_else(|_| "https://blast.drpc.org".to_string()),
            "scroll"    => std::env::var("SCROLL_RPC_URL").unwrap_or_else(|_| "https://scroll.drpc.org".to_string()),
            "mantle"    => std::env::var("MANTLE_RPC_URL").unwrap_or_else(|_| "https://mantle.drpc.org".to_string()),
            _           => continue,
        };
        rpc_list.push((net.clone(), rpc));
    }

    println!("   Networks : {}", rpc_list.iter().map(|(n,_)| n.as_str()).collect::<Vec<_>>().join(", ").cyan());
    println!("   Watching : {}", if contracts.is_empty() { "ALL new contracts".to_string() } else { format!("{} contracts", contracts.len()) });
    println!("   Filters  : {}", "Known safe contracts excluded".green());
    println!("   Triggers : {}", "mint, upgrade, transferOwnership, flashLoan, grantRole...".yellow());
    println!();

    let mut handles = Vec::new();

    for (net_name, net_rpc) in rpc_list {
        let contracts_clone = contracts.clone();
        let net_name_clone = net_name.clone();

        let handle = tokio::spawn(async move {
            let mut monitor = LiveMonitor::new(net_rpc.clone(), net_name_clone.clone());
            for c in &contracts_clone {
                monitor.watch_contract(c.clone());
            }

            let rpc_for_hunt = net_rpc.clone();
            let etherscan_key = std::env::var("ETHERSCAN_API_KEY").unwrap_or_default();
            let (tx_sender, mut tx_receiver) = tokio::sync::mpsc::unbounded_channel::<SuspiciousTx>();

            // Hunter task
            let hunt_rpc = rpc_for_hunt.clone();
            let hunt_key = etherscan_key.clone();
            tokio::spawn(async move {
                while let Some(suspicious) = tx_receiver.recv().await {
                    let hunter = crate::auto_hunter::AutoHunter::new(
                        hunt_key.clone(),
                        hunt_rpc.clone(),
                        5u32,
                    );
                    if let Err(e) = hunter.hunt(&suspicious).await {
                        warn!("Auto-hunt failed: {}", e);
                    }
                }
            });

            if let Err(e) = monitor.poll_new_blocks(move |s| {
                info!("[{}] {} on {}", net_name_clone, s.pattern, s.tx.to);
                if s.severity == PatternSeverity::Critical {
                    let _ = tx_sender.send(s);
                }
            }).await {
                warn!("Monitor error: {}", e);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
