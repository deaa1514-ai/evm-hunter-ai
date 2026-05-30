//! Telegram Bot — إشعارات فورية عند اكتشاف exploit
use anyhow::Result;
use crate::fuzzer::FuzzResult;
use crate::radar::RadarToken;

pub struct TelegramNotifier {
    bot_token: String,
    chat_id: String,
    enabled: bool,
}

impl TelegramNotifier {
    pub fn new() -> Self {
        let bot_token = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
        let chat_id = std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default();
        let enabled = !bot_token.is_empty() && !chat_id.is_empty();
        if enabled {
            tracing::info!("📱 Telegram notifications enabled");
        }
        Self { bot_token, chat_id, enabled }
    }

    pub fn is_enabled(&self) -> bool { self.enabled }

    pub async fn notify_exploit(
        &self,
        token: &RadarToken,
        exploit: &FuzzResult,
    ) -> Result<()> {
        if !self.enabled { return Ok(()); }

        let message = format!(
            "🚨 *EXPLOIT CONFIRMED* 🚨\n\n\
             📋 *Contract:* `{}`\n\
             🏷️ *Name:* {} ({})\n\
             ⛓️ *Chain:* {}\n\
             💧 *Liquidity:* ${:.0}\n\
             📈 *Volume 24h:* ${:.0}\n\
             🔴 *Vulnerability:* `{}`\n\
             📝 *Details:* {}\n\
             {}
             🔗 https://etherscan.io/address/{}",
            exploit.address,
            token.name, token.symbol,
            token.chain,
            token.liquidity_usd,
            token.volume_24h,
            exploit.vulnerability,
            &exploit.details[..exploit.details.len().min(200)],
            exploit.counterexample.as_deref()
                .map(|ce| format!("⚡ *PoC:* `{}`\n", &ce[..ce.len().min(150)]))
                .unwrap_or_default(),
            exploit.address,
        );

        self.send(&message).await
    }

    pub async fn notify_scan_complete(
        &self,
        total: usize,
        exploitable: usize,
    ) -> Result<()> {
        if !self.enabled || exploitable == 0 { return Ok(()); }

        let message = format!(
            "📊 *Radar Scan Complete*\n\n\
             🔍 Scanned: {} contracts\n\
             🔴 Exploitable: *{}*\n\
             🟢 Safe: {}",
            total,
            exploitable,
            total - exploitable,
        );

        self.send(&message).await
    }

    async fn send(&self, message: &str) -> Result<()> {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": false
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            tracing::warn!("Telegram send failed: {}", err);
        }

        Ok(())
    }
}

fn escape_telegram(text: &str) -> String {
    text.chars().map(|c| match c {
        '_' | '*' | '[' | ']' | '(' | ')' | '~' | '`' | '>' | '#' | '+' | '-' | '=' | '|' | '{' | '}' | '.' | '!' => {
            format!("\\{}", c)
        }
        _ => c.to_string(),
    }).collect()
}
