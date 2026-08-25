use alloy_primitives::Address;
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path};

fn default_endpoint() -> String {
    "http://localhost:8545".into()
}
fn default_engine_api() -> String {
    "http://localhost:8551".into()
}
fn default_jwt() -> String {
    "./jwt.hex".into()
}
fn default_comet_endpoint() -> String {
    "http://localhost:26657".into()
}
fn default_comet_home() -> String {
    "./cometbft_home".into()
}
fn default_listen() -> String {
    "0.0.0.0:8080".into()
}
fn default_health() -> String {
    "0.0.0.0:8081".into()
}
fn default_state() -> String {
    "ethbft_state.json".into()
}
fn default_version() -> String {
    crate::VERSION.into()
}
fn default_level() -> String {
    "info".into()
}
fn default_timeout() -> u64 {
    10
}
fn default_true() -> bool {
    true
}
fn default_max_lag() -> i64 {
    5
}
fn default_stall() -> u64 {
    30
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthereumConfig {
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(
        default = "default_engine_api",
        rename = "engineAPI",
        alias = "engineApi"
    )]
    pub engine_api: String,
    #[serde(default = "default_jwt")]
    pub jwt_secret: String,
}

impl Default for EthereumConfig {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            engine_api: default_engine_api(),
            jwt_secret: default_jwt(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CometConfig {
    #[serde(default = "default_comet_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_comet_home")]
    pub home_dir: String,
}

impl Default for CometConfig {
    fn default() -> Self {
        Self {
            endpoint: default_comet_endpoint(),
            home_dir: default_comet_home(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeConfig {
    #[serde(default = "default_listen")]
    pub listen_addr: String,
    #[serde(default = "default_health")]
    pub health_addr: String,
    #[serde(default = "default_state")]
    pub state_file: String,
    #[serde(default = "default_version")]
    pub app_version: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_level")]
    pub log_level: String,
    #[serde(default = "default_true")]
    pub enable_bridging: bool,
    #[serde(default)]
    pub fee_recipient: String,
    #[serde(default)]
    pub finality_depth: u64,
    #[serde(default)]
    pub safe_depth: u64,
    #[serde(default)]
    pub finalized_depth: u64,
    #[serde(default = "default_max_lag")]
    pub max_bridge_lag: i64,
    #[serde(default = "default_stall")]
    pub stall_timeout: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
            health_addr: default_health(),
            state_file: default_state(),
            app_version: default_version(),
            timeout: default_timeout(),
            log_level: default_level(),
            enable_bridging: true,
            fee_recipient: String::new(),
            finality_depth: 0,
            safe_depth: 0,
            finalized_depth: 0,
            max_bridge_lag: default_max_lag(),
            stall_timeout: default_stall(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub ethereum: EthereumConfig,
    #[serde(default)]
    pub cometbft: CometConfig,
    #[serde(default)]
    pub bridge: BridgeConfig,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = env::var("ETHBFT_CONFIG").unwrap_or_else(|_| "config.yaml".into());
        let mut config = if Path::new(&path).exists() {
            serde_yaml::from_str(
                &fs::read_to_string(&path).with_context(|| format!("read {path}"))?,
            )
            .with_context(|| format!("decode {path}"))?
        } else {
            Self::default()
        };
        if let Ok(host) = env::var("ETHEREUM_HOST") {
            config.ethereum.endpoint = replace_host(&config.ethereum.endpoint, &host)?;
            config.ethereum.engine_api = replace_host(&config.ethereum.engine_api, &host)?;
        }
        if let Ok(host) = env::var("COMETBFT_HOST") {
            config.cometbft.endpoint = replace_host(&config.cometbft.endpoint, &host)?;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.ethereum.endpoint.trim().is_empty() || self.ethereum.engine_api.trim().is_empty() {
            bail!("ethereum endpoint and engineAPI are required");
        }
        if self.cometbft.endpoint.trim().is_empty() {
            bail!("cometbft endpoint is required");
        }
        if !self.bridge.enable_bridging {
            bail!("protocol v1 requires enableBridging=true");
        }
        if self.bridge.timeout == 0 {
            bail!("bridge timeout must be positive");
        }
        if self.bridge.finality_depth != 0
            || self.bridge.safe_depth != 0
            || self.bridge.finalized_depth != 0
        {
            bail!("protocol v1 finalizes decided blocks immediately; finality depths must be zero");
        }
        if !self.bridge.fee_recipient.trim().is_empty() {
            self.bridge
                .fee_recipient
                .parse::<Address>()
                .context("invalid bridge feeRecipient")?;
        }
        match self.bridge.log_level.to_ascii_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => bail!("invalid bridge logLevel {}", self.bridge.log_level),
        }
        Ok(())
    }
}

fn replace_host(raw: &str, host: &str) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse(raw).with_context(|| format!("invalid URL {raw}"))?;
    url.set_host(Some(host))
        .map_err(|_| anyhow::anyhow!("invalid replacement host {host}"))?;
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn consensus_depths_fail_closed() {
        let mut config = Config::default();
        config.bridge.safe_depth = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn legacy_engine_api_key_is_preserved() {
        let config: Config = serde_yaml::from_str(
            "ethereum:\n  engineAPI: http://execution:8551\nbridge:\n  enableBridging: true\n",
        )
        .unwrap();
        assert_eq!(config.ethereum.engine_api, "http://execution:8551");
    }
}
