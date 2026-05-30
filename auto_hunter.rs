//! Auto Hunter — يربط Monitor + Scanner + Fuzzer
//! لما يكتشف transaction مشبوهة يفحص العقد فوراً

use anyhow::Result;
use tracing::{info, warn};
use colored::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::time::{Instant, Duration};

use crate::scanner::{ContractScanner, Chain, ContractInfo};
use crate::ast_analyzer::AstAnalyzer;
use crate::pattern_analyzer::PatternAnalyzer;
use crate::smart_ast::SmartAstEngine;
use crate::storage_tracker::StorageTracker;
use crate::fuzzer::LocalFuzzer;
use crate::contract_context::ContextAnalyzer;
use crate::reporter::Severity;
use crate::live_monitor::SuspiciousTx;
use crate::telegram::TelegramNotifier;
use crate::smart_scorer::SmartScorer;
use crate::bytecode_analyzer::BytecodeAnalyzer;
use crate::abi_fuzzer::AbiFuzzer;

pub struct AutoHunter {
    etherscan_key: String,
    rpc_url: String,
    fuzz_runs: u32,
    telegram: TelegramNotifier,
    // Cache — تجنب فحص نفس العقد مرتين
    scanned: Arc<Mutex<HashMap<String, Instant>>>,
}

impl AutoHunter {
    pub fn new(etherscan_key: String, rpc_url: String, fuzz_runs: u32) -> Self {
        Self {
            etherscan_key,
            rpc_url,
            fuzz_runs,
            telegram: TelegramNotifier::new(),
            scanned: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// نقطة الدخول الرئيسية — استدعيها لكل suspicious tx
    pub async fn hunt(&self, suspicious: &SuspiciousTx) -> Result<()> {
        let address = &suspicious.tx.to;

        // تجاهل لو فحصنا هذا العقد مؤخراً
        {
            let mut cache = self.scanned.lock().await;
            if let Some(t) = cache.get(address) {
                if t.elapsed() < Duration::from_secs(3600) {
                    return Ok(());
                }
            }
            cache.insert(address.clone(), Instant::now());
        }

        println!("\n   {} Auto-hunting: {} [{}]",
            "🔬".cyan(),
            &address[..address.len().min(12)],
            suspicious.network.yellow()
        );

        // ─── Phase 1: Fetch Contract ───────────────────
        let chain = match suspicious.network.as_str() {
            "bsc"      => Chain::Ethereum, // BSC uses same API structure
            "base"     => Chain::Base,
            "arbitrum" => Chain::Arbitrum,
            "polygon"  => Chain::Polygon,
            _          => Chain::Ethereum,
        };

        let api_key = self.etherscan_key.clone();
        let scanner = ContractScanner::new(chain.clone(), api_key);

        let contract = match scanner.fetch_contract(address).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to fetch {}: {}", address, e);
                return Ok(());
            }
        };

        if contract.sources.is_empty() {
            println!("   🔍 No source — analyzing bytecode...");
            // استخدام RPC الصحيح حسب الشبكة
        let network_rpc = match suspicious.network.as_str() {
            "bsc"      => std::env::var("BSC_RPC_URL").unwrap_or_else(|_| "https://bsc.drpc.org".to_string()),
            "base"     => std::env::var("BASE_RPC_URL").unwrap_or_else(|_| "https://base.drpc.org".to_string()),
            "arbitrum" => std::env::var("ARBITRUM_RPC_URL").unwrap_or_else(|_| "https://arbitrum.drpc.org".to_string()),
            "polygon"  => std::env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon.drpc.org".to_string()),
            _          => self.rpc_url.clone(),
        };
        let bytecode_analyzer = BytecodeAnalyzer::new(network_rpc.clone());
            if let Ok(analysis) = bytecode_analyzer.analyze(address).await {
                print!("{}", BytecodeAnalyzer::format_analysis(&analysis));
                if analysis.risk_score >= 5.0 {
                    println!("   🚨 Unverified + High Bytecode Risk: {:.1}/10", analysis.risk_score);

                    // ABI Fuzzing — نختبر الـ dangerous functions مباشرة
                    let abi_fuzzer = AbiFuzzer::new(network_rpc.clone());
                    let fuzz_results = abi_fuzzer.fuzz_unverified(address, &analysis).await;
                    
                    let confirmed_vulns: Vec<_> = fuzz_results.iter()
                        .filter(|r| r.is_vulnerable)
                        .collect();
                    
                    if !confirmed_vulns.is_empty() {
                        println!("   💥 {} CONFIRMED VULNERABILITIES!", confirmed_vulns.len());
                        for v in &confirmed_vulns {
                            println!("      🔴 {}: {}", v.function_name, v.details);
                            if let Some(ref poc) = v.poc_calldata {
                                println!("      PoC: {}", poc);
                            }
                        }
                    }

                    let fake_token = crate::radar::RadarToken {
                        address: address.to_string(),
                        name: format!("Unverified [{}]", &suspicious.network),
                        symbol: "?".to_string(),
                        chain: suspicious.network.clone(),
                        liquidity_usd: 0.0,
                        volume_24h: 0.0,
                        pool_address: String::new(),
                        created_at: String::new(),
                    };
                    let fake_exploit = crate::fuzzer::FuzzResult {
                        address: address.to_string(),
                        exploitable: true,
                        vulnerability: format!("UNVERIFIED_{}", suspicious.pattern
                            .to_uppercase().replace("(","_").replace(")","").replace(",","")),
                        details: format!("Unverified — bytecode risk {:.1}/10 | delegatecall:{} selfdestruct:{}",
                            analysis.risk_score, analysis.has_delegatecall, analysis.has_selfdestruct),
                        counterexample: Some(analysis.risk_indicators.join(" | ")),
                    };
                    let _ = self.telegram.notify_exploit(&fake_token, &fake_exploit).await;
                } else {
                    println!("   ℹ️  Unverified — low risk ({:.1}/10) — skipping", analysis.risk_score);
                }
            }
            return Ok(());
        }

        println!("   📄 {} — {} files",
            contract.name.cyan(),
            contract.sources.len()
        );

        // ─── Phase 2: Static Analysis ─────────────────
        let source_code = contract.sources.first()
            .map(|s| s.content.as_str())
            .unwrap_or("");

        // Context check
        let ctx_analyzer = ContextAnalyzer::new(self.rpc_url.clone());
        let ctx = ctx_analyzer.analyze(address, &contract.name, source_code).await;

        if ctx.is_known_safe {
            info!("Known safe contract: {}", address);
            return Ok(());
        }

        // Run all analyzers
        let analyzer    = AstAnalyzer::new();
        let pattern_a   = PatternAnalyzer::new();
        let smart_ast   = SmartAstEngine::new();
        let storage     = StorageTracker::new();

        let mut findings = Vec::new();
        findings.extend(analyzer.analyze_contract(&contract));
        findings.extend(scanner.pattern_scan(&contract));
        findings.extend(pattern_a.analyze(&contract.sources));
        findings.extend(smart_ast.analyze(&contract.sources));
        findings.extend(storage.analyze(&contract.sources));

        // Filter by context
        let findings = ctx_analyzer.filter_findings_by_context(&findings, &ctx, source_code);

        // Filter Critical/High only + Dedup by ID
        let mut seen_ids = std::collections::HashSet::new();
        let critical: Vec<_> = findings.iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .filter(|f| f.id != "UNPROTECTED_FUNCTION")
            .filter(|f| seen_ids.insert(f.id.clone())) // dedup by ID
            .cloned()
            .collect();

        if critical.is_empty() {
            println!("   🟢 No critical findings");
            return Ok(());
        }

        println!("   ⚠️  {} critical finding(s):", critical.len());
        for f in critical.iter().take(3) {
            println!("      [{:?}] {}", f.severity, f.id.red());
        }

        // ─── Phase 3: Fuzzing ──────────────────────────
        // ─── Smart Scorer ────────────────────────────────
        let scorer = SmartScorer::new();
        let risk = scorer.score_contract(
            address,
            source_code,
            &suspicious.pattern,
            0.0, // liquidity from future integration
            &self.rpc_url,
        ).await;

        println!("   📊 Risk Score: {:.1}/10 | Confidence: {:.0}% | {}",
            risk.score,
            risk.confidence * 100.0,
            risk.summary
        );

        for factor in &risk.factors {
            let sign = if factor.points > 0.0 { "+" } else { "" };
            println!("      {}{:.1} — {}", sign, factor.points, factor.reason);
        }

        // تجاهل العقود اللي score منخفض
        if !risk.is_critical {
            println!("   🟢 Risk score {:.1} < 6.0 — skipping fuzz", risk.score);
            return Ok(());
        }

        // ─── Exploitability Pre-filter ───────────────────
        let exploit_engine = crate::exploitability::ExploitabilityEngine::new();
        let scored: Vec<_> = critical.iter()
            .map(|f| {
                let score = exploit_engine.score(f, None, source_code, 0.0);
                (f, score)
            })
            .filter(|(_, s)| {
                // تجاهل الـ findings اللي probability false positive عالية
                s.false_positive_probability < 0.6 && s.score >= 3.0
            })
            .collect();

        if scored.is_empty() {
            println!("   ⚠️  All findings filtered by Exploitability Engine (high FP risk)");
            return Ok(());
        }

        let filtered_critical: Vec<crate::reporter::Finding> = scored.iter()
            .map(|(f, _)| (*f).clone())
            .collect();

        println!("   🌋 Fuzzing {} findings ({} filtered out) — {} runs...",
            filtered_critical.len(),
            critical.len() - filtered_critical.len(),
            self.fuzz_runs
        );

        // Log exploitability scores
        for (f, score) in &scored {
            println!("      [{:.1}/10] {} (FP:{:.0}%)",
                score.score, f.id, score.false_positive_probability * 100.0);
        }

        let fuzzer = LocalFuzzer::new(self.rpc_url.clone(), self.fuzz_runs);

        match fuzzer.fuzz_contract(address, source_code, &filtered_critical).await {
            Ok(results) => {
                let exploits: Vec<_> = results.iter()
                    .filter(|r| r.exploitable)
                    .collect();

                if exploits.is_empty() {
                    println!("   🟢 All fuzz tests passed — no exploit found");
                } else {
                    // ─── EXPLOIT CONFIRMED! ───────────────
                    println!("\n   {} AUTO-HUNT EXPLOIT CONFIRMED!",
                        "🚨".red().bold()
                    );
                    println!("   Contract  : {}", address.yellow());
                    println!("   Network   : {}", suspicious.network.cyan());
                    println!("   Trigger   : {}", suspicious.pattern.red());

                    for exploit in &exploits {
                        println!("   Vuln      : {}", exploit.vulnerability.red().bold());
                        if let Some(ref ce) = exploit.counterexample {
                            println!("   PoC       : {}", &ce[..ce.len().min(150)].cyan());
                        }
                    }

                    // Telegram notification
                    if let Some(exploit) = exploits.first() {
                        // Build a fake token for telegram
                        let fake_token = crate::radar::RadarToken {
                            address: address.clone(),
                            name: contract.name.clone(),
                            symbol: "?".to_string(),
                            chain: suspicious.network.clone(),
                            liquidity_usd: 0.0,
                            volume_24h: 0.0,
                            pool_address: String::new(),
                            created_at: String::new(),
                        };

                        if let Err(e) = self.telegram.notify_exploit(&fake_token, exploit).await {
                            warn!("Telegram failed: {}", e);
                        }

                        // Save report
                        let report_path = format!("hunt_{}.txt", &address[..address.len().min(10)]);
                        let report = format!(
                            "AUTO-HUNT REPORT\n\
                             ================\n\
                             Address  : {}\n\
                             Network  : {}\n\
                             Trigger  : {}\n\
                             Vuln     : {}\n\
                             PoC      : {}\n\
                             Time     : {}\n",
                            address,
                            suspicious.network,
                            suspicious.pattern,
                            exploit.vulnerability,
                            exploit.counterexample.as_deref().unwrap_or("N/A"),
                            chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
                        );
                        let _ = std::fs::write(&report_path, report);
                        println!("   📄 Report : {}", report_path.green());
                    }
                }
            }
            Err(e) => warn!("Fuzzing failed: {}", e),
        }

        Ok(())
    }
}
