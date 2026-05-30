#![allow(unused_imports)]
use clap::{Parser, Subcommand};
use anyhow::Result;
use tracing::{info, warn, error};
use colored::*;
use std::env;

mod scanner;
mod cfg;
mod storage_tracker;
mod exploitability;
mod contract_context;
mod auto_hunter;
mod abi_fuzzer;
mod smart_scorer;
mod bytecode_analyzer;
mod live_monitor;
use storage_tracker::StorageTracker;
use exploitability::ExploitabilityEngine;
use contract_context::ContextAnalyzer;
use live_monitor::run_monitor;
use cfg::CfgBuilder;
mod ast_analyzer;
mod reporter;
mod foundry_integration;
mod config;
mod utils;
mod radar;
mod fuzzer;
mod pattern_analyzer;
mod logger;
mod ai_scorer;
mod smart_ast;
mod telegram;

use scanner::{Chain, ContractScanner, ContractSource};
use ast_analyzer::AstAnalyzer;
use reporter::{Finding, ReportGenerator, Severity};
use foundry_integration::FoundryPocGenerator;
use radar::Radar;
use fuzzer::{LocalFuzzer, FuzzResult};
use pattern_analyzer::PatternAnalyzer;
use logger::ExploitLogger;
use ai_scorer::AiScorer;
use smart_ast::SmartAstEngine;

#[derive(Parser)]
#[command(name = "evm-bounty-hunter")]
#[command(about = "Advanced EVM vulnerability scanner & live radar for bug bounty hunting")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// فحص عقد أو أكثر يدوياً
    Scan {
        #[arg(required = true)]
        addresses: Vec<String>,

        #[arg(short, long, default_value = "ethereum")]
        chain: String,

        #[arg(short, long)]
        poc: bool,

        #[arg(short, long, default_value = "report.json")]
        output: String,

        #[arg(short, long, default_value = "low")]
        min_severity: String,

        /// تشغيل fuzzing محلي على الثغرات المكتشفة
        #[arg(long)]
        fuzz: bool,

        /// عدد جولات الـ fuzzing
        #[arg(long, default_value = "50")]
        fuzz_runs: u32,
    },

    /// تحليل ملف Solidity محلي
    Analyze {
        #[arg(required = true)]
        path: String,

        #[arg(short, long)]
        poc: bool,
    },

    /// توليد مشروع Foundry PoC
    Forge {
        #[arg(required = true)]
        address: String,

        #[arg(required = true)]
        vuln_type: String,

        #[arg(short, long)]
        rpc: Option<String>,
    },

    /// 👁️ مراقبة live transactions
    Monitor {
        #[arg(long, default_value = "eth")]
        networks: String,
        #[arg(long, default_value = "")]
        contracts: String,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        telegram: bool,
    },

    /// 🔴 الرادار — يراقب العقود الجديدة ويفحصها تلقائياً
    Radar {
        /// الشبكات للمراقبة (مفصولة بفاصلة)
        #[arg(short, long, default_value = "eth,base,bsc")]
        networks: String,

        /// الحد الأدنى للسيولة بالدولار
        #[arg(long, default_value = "10000")]
        min_liquidity: f64,

        /// الحد الأدنى للحجم اليومي بالدولار
        #[arg(long, default_value = "5000")]
        min_volume: f64,

        /// عدد الصفحات لكل شبكة (كل صفحة ~20 توكن)
        #[arg(long, default_value = "3")]
        pages: u32,

        /// RPC URL للـ fork
        #[arg(long)]
        rpc: Option<String>,

        /// عدد جولات الـ fuzzing لكل عقد
        #[arg(long, default_value = "50")]
        fuzz_runs: u32,

        /// ملف تسجيل النتائج
        #[arg(long, default_value = "radar_exploits.log")]
        log_file: String,

        /// تخطي الـ fuzzing (فحص سريع بدون forge)
        #[arg(long)]
        no_fuzz: bool,

        /// تفعيل الإشعارات عبر Telegram
        #[arg(long)]
        telegram: bool,

        /// تشغيل الـ specialized fuzzing
        #[arg(long)]
        deep_fuzz: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // تحميل .env
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { addresses, chain, poc, output, min_severity, fuzz, fuzz_runs } => {
            cmd_scan(addresses, chain, poc, output, min_severity, fuzz, fuzz_runs).await?;
        }

        Commands::Analyze { path, poc } => {
            cmd_analyze(path, poc).await?;
        }

        Commands::Forge { address, vuln_type, rpc } => {
            cmd_forge(address, vuln_type, rpc).await?;
        }

        Commands::Monitor { networks, contracts, rpc, telegram } => {
            let rpc_url = rpc.unwrap_or_else(get_rpc_url);
            let contract_list: Vec<String> = if contracts.is_empty() {
                Vec::new()
            } else {
                contracts.split(',').map(|s| s.trim().to_lowercase()).collect()
            };
            let network_list: Vec<String> = networks.split(',')
                .map(|s| s.trim().to_lowercase())
                .collect();
            run_monitor(rpc_url, contract_list, telegram, network_list).await?;
        },

        Commands::Radar { networks, min_liquidity, min_volume, pages, rpc, fuzz_runs, log_file, no_fuzz, telegram, deep_fuzz } => {
            cmd_radar(networks, min_liquidity, min_volume, pages, rpc, fuzz_runs, log_file, no_fuzz, telegram, deep_fuzz).await?;
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────
// SCAN
// ─────────────────────────────────────────────
async fn cmd_scan(
    addresses: Vec<String>,
    chain: String,
    poc: bool,
    output: String,
    min_severity: String,
    fuzz: bool,
    fuzz_runs: u32,
) -> Result<()> {
    let chain_enum = parse_chain(&chain);
    info!("Starting scan on {} for {} contract(s)", chain, addresses.len());

    let api_key = env::var("ETHERSCAN_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        warn!("ETHERSCAN_API_KEY not set — API calls may fail");
    }

    let scanner      = ContractScanner::new(chain_enum, api_key);
    let analyzer     = AstAnalyzer::new();
    let pattern_a    = PatternAnalyzer::new();
        let smart_ast_engine = SmartAstEngine::new();
        let storage_tracker = StorageTracker::new();
        let exploit_engine  = ExploitabilityEngine::new();
        let storage_tracker = StorageTracker::new();
        let exploit_engine  = ExploitabilityEngine::new();
        let cfg_builder     = CfgBuilder::new();
    let mut report_gen = ReportGenerator::new();
    report_gen.set_chain(&chain);

    let rpc_url = get_rpc_url();

    for addr in &addresses {
        println!("\n{}", format!("🔍 Scanning: {}", addr).bold().cyan());

        match scanner.fetch_contract(addr).await {
            Ok(contract) => {
                println!("   📄 Name    : {}", contract.name.green());
                println!("   🔗 Compiler: {} v{}", contract.compiler, contract.compiler_version);
                println!("   📁 Files   : {}", contract.sources.len());
                if contract.is_proxy {
                    println!("   🔄 Proxy{}",
                        contract.implementation.as_deref()
                            .map(|i| format!(" → {}", i))
                            .unwrap_or_default()
                    );
                }

                // جمع كل الثغرات
                let mut all_findings = Vec::new();
                all_findings.extend(analyzer.analyze_contract(&contract));
                all_findings.extend(scanner.pattern_scan(&contract));
                all_findings.extend(pattern_a.analyze(&contract.sources));
                all_findings.extend(smart_ast_engine.analyze(&contract.sources));
        all_findings.extend(storage_tracker.analyze(&contract.sources));
                all_findings.extend(storage_tracker.analyze(&contract.sources));

                let min_sev = Severity::from_str(&min_severity);
                let mut filtered: Vec<_> = all_findings
                    .into_iter()
                    .filter(|f| f.severity >= min_sev)
                    .collect();
                filtered.sort_by(|a, b| b.severity.cmp(&a.severity));
                filtered.dedup_by_key(|f| (f.id.clone(), f.line));

                print_findings(&filtered);
                report_gen.add_contract(addr, &contract, filtered.clone());

                // PoC
                if poc && !filtered.is_empty() {
                    let poc_gen = FoundryPocGenerator::new();
                    for finding in filtered.iter().filter(|f| f.severity >= Severity::High) {
                        let safe_id = finding.id.to_lowercase().replace('_', "-");
                        let poc_path = format!("poc_{:.8}_{}.sol", addr, safe_id);
                        match poc_gen.generate_poc(&contract, finding, &poc_path) {
                            Ok(_) => println!("   📝 PoC: {}", poc_path.green()),
                            Err(e) => warn!("PoC failed: {}", e),
                        }
                    }
                }

                // Fuzzing
                if fuzz && !filtered.is_empty() {
                    println!("\n   {}", "🌋 Starting local fuzzing...".yellow().bold());
                    let fuzzer = LocalFuzzer::new(rpc_url.clone(), fuzz_runs);
                    match fuzzer.fuzz_contract(addr, "", &filtered).await {
                        Ok(results) => {
                            let exploitable: Vec<_> = results.iter().filter(|r| r.exploitable).collect();
                            if exploitable.is_empty() {
                                println!("   {} All fuzz tests passed", "🟢".green());
                            } else {
                                println!("   {} {} exploit(s) confirmed!", "🔴".red(), exploitable.len());
                            }
                        }
                        Err(e) => warn!("Fuzzing error: {}", e),
                    }
                }
            }
            Err(e) => {
                error!("Failed to scan {}: {}", addr, e);
                println!("   ❌ {}", e.to_string().red());
            }
        }
    }

    report_gen.save(&output)?;
    println!("\n📊 Report saved: {}", output.green().bold());
    Ok(())
}

// ─────────────────────────────────────────────
// ANALYZE
// ─────────────────────────────────────────────
async fn cmd_analyze(path: String, poc: bool) -> Result<()> {
    println!("{}", format!("📁 Analyzing: {}", path).bold().cyan());

    let content = std::fs::read_to_string(&path)?;
    let analyzer  = AstAnalyzer::new();
    let pattern_a = PatternAnalyzer::new();

    let mut findings = analyzer.analyze_source(&path, &content);

    // pattern analyzer يحتاج ContractSource
    let source = ContractSource {
        name: path.clone(),
        content: content.clone(),
    };
    findings.extend(pattern_a.analyze(&[source]));
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings.dedup_by_key(|f| (f.id.clone(), f.line));

    print_findings(&findings);

    if poc && !findings.is_empty() {
        println!("\n📝 forge: evm-bounty-hunter forge <address> <vuln_type>");
    }
    Ok(())
}

// ─────────────────────────────────────────────
// FORGE
// ─────────────────────────────────────────────
async fn cmd_forge(address: String, vuln_type: String, rpc: Option<String>) -> Result<()> {
    println!("{}", "🔨 Generating Foundry PoC...".bold().cyan());

    let rpc_url = rpc.unwrap_or_else(get_rpc_url);
    let poc_gen = FoundryPocGenerator::new();

    match poc_gen.generate_foundry_project(&address, &vuln_type, &rpc_url) {
        Ok(path) => {
            println!("   ✅ Project: {}", path.green());
            println!("   cd {} && forge test --fork-url {}", path, rpc_url);
        }
        Err(e) => error!("Forge failed: {}", e),
    }
    Ok(())
}

// ─────────────────────────────────────────────
// RADAR
// ─────────────────────────────────────────────
async fn cmd_radar(
    networks_str: String,
    min_liquidity: f64,
    min_volume: f64,
    pages: u32,
    rpc: Option<String>,
    fuzz_runs: u32,
    log_file: String,
    no_fuzz: bool,
    telegram: bool,
    deep_fuzz: bool,
) -> Result<()> {
    println!("{}", "
╔══════════════════════════════════════╗
║   🔴  EVM BOUNTY RADAR  ACTIVE  🔴   ║
╚══════════════════════════════════════╝".red().bold());

    let api_key = env::var("ETHERSCAN_API_KEY").unwrap_or_default();
    let rpc_url = rpc.unwrap_or_else(get_rpc_url);

    // شبكات GeckoTerminal
    let networks: Vec<&str> = networks_str.split(',')
        .map(|s| s.trim())
        .collect();

    println!("   Networks  : {}", networks.join(", ").cyan());
    println!("   Liquidity : ≥ ${:.0}", min_liquidity);
    println!("   Volume 24h: ≥ ${:.0}", min_volume);
    println!("   Pages     : {} (~{} tokens/network)", pages, pages * 20);
    println!("   Fuzz runs : {}", if no_fuzz { "disabled".to_string() } else { fuzz_runs.to_string() });
    println!("   Log file  : {}", log_file.yellow());

    // ─── المرحلة الأولى: الرادار ───
    println!("\n{}", "📡 Phase 1: Scanning for new tokens...".bold());
    let radar_engine = Radar::new(min_liquidity, min_volume);
    let tokens = radar_engine.fetch_all_networks(&networks, pages).await;

    if tokens.is_empty() {
        println!("   ⚠️  No tokens found matching criteria");
        return Ok(());
    }

    println!("   ✅ Found {} tokens to analyze", tokens.len().to_string().green());

    let exploit_logger = ExploitLogger::new(&log_file);
    let analyzer     = AstAnalyzer::new();
    let pattern_a    = PatternAnalyzer::new();
        let smart_ast_engine = SmartAstEngine::new();
        let storage_tracker  = StorageTracker::new();
        let exploit_engine   = ExploitabilityEngine::new();
        let ctx_analyzer     = ContextAnalyzer::new(rpc_url.clone());
    let fuzzer       = LocalFuzzer::new(rpc_url.clone(), fuzz_runs);

    let mut total     = 0usize;
    let mut exploitable_count = 0usize;
    let mut safe_count        = 0usize;

    // ─── المرحلة الثانية-الخامسة: فحص كل توكن ───
    for (idx, token) in tokens.iter().enumerate() {
        println!("\n{}", format!(
            "━━━ [{}/{}] {} ({}) ━━━",
            idx + 1, tokens.len(), token.name, token.symbol
        ).bold());
        println!("   Address  : {}", token.address.cyan());
        println!("   Chain    : {}  💧 ${:.0}  📈 ${:.0}/24h",
            token.chain, token.liquidity_usd, token.volume_24h);

        total += 1;

        // تحديد الـ chain enum
        let chain_enum = gecko_network_to_chain(&token.chain);
        let scanner_inst = ContractScanner::new(chain_enum, api_key.clone());

        // ─── جلب الكود ───
        let contract = match scanner_inst.fetch_contract(&token.address).await {
            Ok(c) => c,
            Err(e) => {
                println!("   ⚠️  Source not verified: {}", e.to_string().yellow());
                continue;
            }
        };

        println!("   📄 {} — {} files", contract.name.green(), contract.sources.len());

        // ─── المرحلة الثانية: جمع الثغرات ───
        let mut findings = Vec::new();
        findings.extend(analyzer.analyze_contract(&contract));
        findings.extend(scanner_inst.pattern_scan(&contract));
        findings.extend(pattern_a.analyze(&contract.sources));
        findings.extend(smart_ast_engine.analyze(&contract.sources));
        findings.extend(storage_tracker.analyze(&contract.sources));
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings.dedup_by_key(|f| (f.id.clone(), f.line));

        let critical_high: Vec<_> = findings.iter()
            .filter(|f| f.severity >= Severity::High)
            .collect();

        if critical_high.is_empty() {
            println!("   {} No high/critical findings", "🟢".green());
            safe_count += 1;
            continue;
        }

        println!("   ⚠️  {} finding(s) — Critical/High", critical_high.len().to_string().red());
        for f in &critical_high {
            let sev = match f.severity {
                Severity::Critical => "CRIT".red().bold(),
                Severity::High     => "HIGH".red(),
                _                  => "MED ".yellow(),
            };
            println!("      [{}] {} (line {})", sev, f.id.cyan(), f.line);
        }

        if no_fuzz {
            // بدون fuzzing — نسجل كمشتبه به
            exploitable_count += 1;
            for f in &critical_high {
                let _ = exploit_logger.log_exploit(&token, &FuzzResult {
                    address: token.address.clone(),
                    exploitable: true,
                    vulnerability: f.id.clone(),
                    details: f.description.clone(),
                    counterexample: None,
                });
            }
            continue;
        }

        // ─── المرحلة الثالثة والرابعة: Fuzzing ───
        println!("   {}", "🌋 Fuzzing...".yellow());

        let source_code = contract.sources.first()
            .map(|s| s.content.as_str())
            .unwrap_or("");

        // Context analysis — skip known safe contracts
        let ctx = ctx_analyzer.analyze(&token.address, &token.name, source_code).await;
        if ctx.should_skip() {
            println!("   ✅ Skipped: {}", ctx.skip_reason.as_deref().unwrap_or("known safe"));
            continue;
        }
        if !ctx.context_notes.is_empty() {
            for note in &ctx.context_notes {
                println!("   {}", note);
            }
        }

        // Filter findings by context
        let findings = ctx_analyzer.filter_findings_by_context(&findings, &ctx, source_code);

        let token_fuzzer = LocalFuzzer::new(get_chain_rpc_url(&token.chain), fuzz_runs);
        match token_fuzzer.fuzz_contract(&token.address, source_code, &findings).await {
            Ok(results) => {
                let exploits: Vec<_> = results.iter().filter(|r| r.exploitable).collect();

                if exploits.is_empty() {
                    println!("   {} Passed all fuzz tests", "🟢 SAFE".green());
                    safe_count += 1;
                    let _ = exploit_logger.log_safe(token, "all");
                } else {
                    // ─── المرحلة الرابعة: EXPLOIT مؤكد ───
                    exploitable_count += 1;
                    
                    // أخذ أفضل exploit فقط (الأول المؤكد)
                    let confirmed: Vec<_> = exploits.iter()
                        .filter(|e| e.exploitable)
                        .collect();
                    
                    if confirmed.is_empty() { continue; }
                    
                    println!("\n   {}", "🚨 EXPLOIT CONFIRMED! 🚨".red().bold());

                    // AI Scoring
                    let ai = AiScorer::new();
                    let source_snippet = contract.sources.first()
                        .map(|s| s.content.as_str())
                        .unwrap_or("");

                    // طبع الـ exploit الأول فقط
                    let exploit = confirmed[0];
                    {
                        // Exploitability score
                        let source_str = contract.sources.first().map(|s| s.content.as_str()).unwrap_or("");
                        let exp_score = exploit_engine.score(
                            &findings.iter().find(|f| f.id == exploit.vulnerability).cloned()
                                .unwrap_or_else(|| findings[0].clone()),
                            Some(exploit),
                            source_str,
                            token.liquidity_usd,
                        );

                        println!("   ┌─ Vuln    : {}", exploit.vulnerability.red().bold());
                        println!("   ├─ Score   : {}", exploit_engine.format_score(&exp_score).yellow());
                        println!("   ├─ Details : {}", &exploit.details[..exploit.details.len().min(200)].yellow());
                        if let Some(ref ce) = exploit.counterexample {
                            println!("   └─ PoC    : {}", &ce[..ce.len().min(150)].cyan());
                        }

                        // AI Score
                        match ai.score_exploit(&contract, exploit, source_snippet).await {
                            Ok(score) => {
                                println!("   ┌─ 🤖 AI Score    : {:.1}/10.0 (confidence: {:.0}%)",
                                    score.risk_score, score.confidence * 100.0);
                                println!("   ├─ Bug Bounty     : {}", score.bug_bounty_potential.red().bold());
                                println!("   ├─ Affects Funds  : {}", if score.affects_funds { "YES 💰".red() } else { "No".white() });
                                println!("   ├─ Summary        : {}", score.summary.yellow());
                                println!("   └─ Fix            : {}", score.recommendation.green());
                                if !score.attack_path.is_empty() {
                                    println!("   Attack Path:");
                                    for (i, step) in score.attack_path.iter().enumerate() {
                                        println!("      {}. {}", i+1, step.cyan());
                                    }
                                }
                            }
                            Err(e) => warn!("AI scoring failed: {}", e),
                        }

                        let _ = exploit_logger.log_exploit(token, exploit);
                    }
                    // نوقف فحص هذا العقد بعد أول exploit مؤكد
                    break;
                }
            }
            Err(e) => {
                warn!("Fuzzing failed: {}", e);
                println!("   ⚠️  Fuzz error — manual review needed");
            }
        }

        // GeckoTerminal rate limit
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // ─── ملخص نهائي ───
    let _ = exploit_logger.log_summary(total, exploitable_count, safe_count);

    println!("\n{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bold());
    println!("{}", "📊 RADAR SCAN COMPLETE".bold().cyan());
    println!("   Total scanned : {}", total);
    println!("   Exploitable   : {}", exploitable_count.to_string().red().bold());
    println!("   Safe          : {}", safe_count.to_string().green());
    println!("   Log saved     : {}", log_file.yellow());

    Ok(())
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
fn print_findings(findings: &[reporter::Finding]) {
    if findings.is_empty() {
        println!("   {} No vulnerabilities found", "✅".green());
        return;
    }
    println!("   ⚠️  {} finding(s):", findings.len().to_string().yellow());
    for f in findings {
        let sev = match f.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High     => "HIGH    ".red(),
            Severity::Medium   => "MEDIUM  ".yellow(),
            Severity::Low      => "LOW     ".blue(),
            Severity::Info     => "INFO    ".white(),
        };
        println!("      [{}] {} (line {})", sev, f.id.cyan(), f.line);
        println!("               └─ {}", f.description);
        if let Some(ref lt) = f.line_text {
            println!("               └─ {}", lt.dimmed());
        }
    }
}

fn get_rpc_url() -> String {
    env::var("RPC_URL")
        .unwrap_or_else(|_| "https://eth.drpc.org".to_string())
}

fn get_chain_rpc_url(chain: &str) -> String {
    match chain {
        "base"      => env::var("BASE_RPC_URL").unwrap_or_else(|_| "https://base.drpc.org".to_string()),
        "arbitrum"  | "arbitrum_one" => env::var("ARBITRUM_RPC_URL").unwrap_or_else(|_| "https://arbitrum.drpc.org".to_string()),
        "optimism"  | "optimistic-ethereum" => env::var("OPTIMISM_RPC_URL").unwrap_or_else(|_| "https://optimism.drpc.org".to_string()),
        "polygon"   | "polygon_pos" => env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon.drpc.org".to_string()),
        "bsc"       | "binance-smart-chain" => env::var("BSC_RPC_URL").unwrap_or_else(|_| "https://bsc.drpc.org".to_string()),
        "avalanche" | "avax" => env::var("AVAX_RPC_URL").unwrap_or_else(|_| "https://avalanche.drpc.org".to_string()),
        "fantom"    | "ftm"  => env::var("FTM_RPC_URL").unwrap_or_else(|_| "https://fantom.drpc.org".to_string()),
        "zksync"    => env::var("ZKSYNC_RPC_URL").unwrap_or_else(|_| "https://zksync.drpc.org".to_string()),
        "linea"     => env::var("LINEA_RPC_URL").unwrap_or_else(|_| "https://linea.drpc.org".to_string()),
        "blast"     => env::var("BLAST_RPC_URL").unwrap_or_else(|_| "https://blast.drpc.org".to_string()),
        _           => get_rpc_url(), // ethereum default
    }
}

fn gecko_network_to_chain(network: &str) -> Chain {
    match network {
        "eth"  | "ethereum"        => Chain::Ethereum,
        "base"                     => Chain::Base,
        "arbitrum" | "arbitrum_one"=> Chain::Arbitrum,
        "optimism" | "optimistic-ethereum" => Chain::Optimism,
        "polygon_pos" | "polygon"  => Chain::Polygon,
        _ => Chain::Ethereum,
    }
}

fn parse_chain(s: &str) -> Chain {
    match s {
        "ethereum" | "eth" | "mainnet" => Chain::Ethereum,
        "base"                         => Chain::Base,
        "arbitrum" | "arb"             => Chain::Arbitrum,
        "optimism" | "op"              => Chain::Optimism,
        "polygon" | "matic"            => Chain::Polygon,
        other => {
            eprintln!("⚠️  Unknown chain '{}', defaulting to Ethereum", other);
            Chain::Ethereum
        }
    }
}
