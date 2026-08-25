use crate::protocol::EngineApiVersion;
use alloy_primitives::Address;
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path};

fn default_engine_endpoint() -> String {
    "http://localhost:8551".into()
}
fn default_jwt() -> String {
    "./jwt.hex".into()
}
fn default_comet_endpoint() -> String {
    "http://localhost:26657".into()
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
fn default_max_lag() -> i64 {
    5
}
fn default_stall() -> u64 {
    30
}
fn default_max_payload_bytes() -> usize {
    16 * 1024 * 1024
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionConfig {
    #[serde(
        default = "default_engine_endpoint",
        alias = "engineAPI",
        alias = "engineApi"
    )]
    pub endpoint: String,
    #[serde(default = "default_jwt")]
    pub jwt_secret: String,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            endpoint: default_engine_endpoint(),
            jwt_secret: default_jwt(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CometConfig {
    #[serde(default = "default_comet_endpoint")]
    pub endpoint: String,
}

impl Default for CometConfig {
    fn default() -> Self {
        Self {
            endpoint: default_comet_endpoint(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolConfig {
    #[serde(default)]
    pub shanghai_time: u64,
    #[serde(default)]
    pub cancun_time: Option<u64>,
    #[serde(default)]
    pub prague_time: Option<u64>,
    #[serde(default)]
    pub fee_recipient: String,
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            shanghai_time: 0,
            cancun_time: None,
            prague_time: None,
            fee_recipient: String::new(),
            max_payload_bytes: default_max_payload_bytes(),
        }
    }
}

impl ProtocolConfig {
    pub fn engine_version(&self, timestamp: u64) -> anyhow::Result<EngineApiVersion> {
        if timestamp < self.shanghai_time {
            bail!("pre-Shanghai execution payloads are not supported");
        }
        if self
            .prague_time
            .is_some_and(|activation| timestamp >= activation)
        {
            return Ok(EngineApiVersion::V4);
        }
        if self
            .cancun_time
            .is_some_and(|activation| timestamp >= activation)
        {
            return Ok(EngineApiVersion::V3);
        }
        Ok(EngineApiVersion::V2)
    }

    pub fn configured_versions(&self) -> Vec<EngineApiVersion> {
        let mut versions = vec![EngineApiVersion::V2];
        if self.cancun_time.is_some() {
            versions.push(EngineApiVersion::V3);
        }
        if self.prague_time.is_some() {
            versions.push(EngineApiVersion::V4);
        }
        versions
    }

    pub fn fee_recipient(&self) -> anyhow::Result<Address> {
        if self.fee_recipient.trim().is_empty() {
            Ok(Address::ZERO)
        } else {
            self.fee_recipient
                .parse()
                .context("parse protocol fee recipient")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeConfig {
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
    #[serde(default = "default_max_lag")]
    pub max_consensus_lag: i64,
    #[serde(default = "default_stall")]
    pub stall_timeout: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
            health_addr: default_health(),
            state_file: default_state(),
            app_version: default_version(),
            timeout: default_timeout(),
            log_level: default_level(),
            max_consensus_lag: default_max_lag(),
            stall_timeout: default_stall(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default, alias = "ethereum")]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub cometbft: CometConfig,
    #[serde(default)]
    pub protocol: ProtocolConfig,
    #[serde(default, alias = "bridge")]
    pub node: NodeConfig,
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
        if let Ok(host) = env::var("EXECUTION_HOST").or_else(|_| env::var("ETHEREUM_HOST")) {
            config.execution.endpoint = replace_host(&config.execution.endpoint, &host)?;
        }
        if let Ok(host) = env::var("COMETBFT_HOST") {
            config.cometbft.endpoint = replace_host(&config.cometbft.endpoint, &host)?;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.execution.endpoint.trim().is_empty() {
            bail!("execution endpoint is required");
        }
        if self.cometbft.endpoint.trim().is_empty() {
            bail!("cometbft endpoint is required");
        }
        if self.node.timeout == 0 {
            bail!("node timeout must be positive");
        }
        if self.protocol.max_payload_bytes == 0
            || self.protocol.max_payload_bytes > crate::protocol::MAX_ENVELOPE_LEN
        {
            bail!(
                "protocol maxPayloadBytes must be between 1 and {}",
                crate::protocol::MAX_ENVELOPE_LEN
            );
        }
        if let Some(cancun) = self.protocol.cancun_time {
            if cancun < self.protocol.shanghai_time {
                bail!("Cancun activation must not precede Shanghai");
            }
        }
        if let Some(prague) = self.protocol.prague_time {
            let cancun = self
                .protocol
                .cancun_time
                .context("Prague configuration requires Cancun activation")?;
            if prague < cancun {
                bail!("Prague activation must not precede Cancun");
            }
        }
        self.protocol.fee_recipient()?;
        match self.node.log_level.to_ascii_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => bail!("invalid node logLevel {}", self.node.log_level),
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
    fn engine_version_follows_fork_schedule() {
        let protocol = ProtocolConfig {
            cancun_time: Some(10),
            prague_time: Some(20),
            ..Default::default()
        };
        assert_eq!(protocol.engine_version(1).unwrap(), EngineApiVersion::V2);
        assert_eq!(protocol.engine_version(10).unwrap(), EngineApiVersion::V3);
        assert_eq!(protocol.engine_version(20).unwrap(), EngineApiVersion::V4);
    }

    #[test]
    fn legacy_engine_api_key_maps_to_single_endpoint() {
        let config: Config = serde_yaml::from_str(
            "ethereum:\n  engineAPI: http://execution:8551\nbridge:\n  timeout: 10\n",
        )
        .unwrap();
        assert_eq!(config.execution.endpoint, "http://execution:8551");
    }
}
