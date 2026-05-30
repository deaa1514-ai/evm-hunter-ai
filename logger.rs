//! Logger — يسجل الثغرات في radar_exploits.log
use anyhow::Result;
use std::fs::{OpenOptions};
use std::io::Write;
use chrono::Utc;
use crate::fuzzer::FuzzResult;
use crate::radar::RadarToken;

pub struct ExploitLogger {
    log_path: String,
}

impl ExploitLogger {
    pub fn new(log_path: &str) -> Self {
        Self { log_path: log_path.to_string() }
    }

    pub fn log_exploit(&self, token: &RadarToken, result: &FuzzResult) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let entry = format!(
            "[{}] 🔴 EXPLOITABLE\n\
             Address  : {}\n\
             Name     : {} ({})\n\
             Chain    : {}\n\
             Pool     : {}\n\
             Liquidity: ${:.2}\n\
             Volume24h: ${:.2}\n\
             Vuln     : {}\n\
             Details  : {}\n\
             {}---\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            result.address,
            token.name, token.symbol,
            token.chain,
            token.pool_address,
            token.liquidity_usd,
            token.volume_24h,
            result.vulnerability,
            result.details,
            result.counterexample.as_deref()
                .map(|ce| format!("PoC      : {}\n", ce))
                .unwrap_or_default(),
        );

        file.write_all(entry.as_bytes())?;
        Ok(())
    }

    pub fn log_safe(&self, token: &RadarToken, vuln: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let entry = format!(
            "[{}] 🟢 SAFE — {} ({}) — {}\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            token.address,
            token.symbol,
            vuln,
        );

        file.write_all(entry.as_bytes())?;
        Ok(())
    }

    pub fn log_summary(&self, total: usize, exploitable: usize, safe: usize) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let entry = format!(
            "\n[{}] === SCAN SUMMARY ===\n\
             Total Scanned : {}\n\
             Exploitable   : {} 🔴\n\
             Safe          : {} 🟢\n\
             ==================\n\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            total, exploitable, safe,
        );

        file.write_all(entry.as_bytes())?;
        Ok(())
    }
}
