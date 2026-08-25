use crate::protocol::{payload_versioned_hashes, EngineApiVersion, ExecutionEnvelope};
use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::{
    ExecutionPayload, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV2,
    ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadStatus,
};
use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    fs,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ADVERTISED_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedV2",
    "engine_forkchoiceUpdatedV3",
    "engine_getPayloadV2",
    "engine_getPayloadV3",
    "engine_getPayloadV4",
    "engine_newPayloadV2",
    "engine_newPayloadV3",
    "engine_newPayloadV4",
    "engine_getClientVersionV1",
];

#[derive(Clone)]
pub struct EngineClient {
    endpoint: String,
    jwt_key: Arc<Vec<u8>>,
    http: Client,
    next_id: Arc<AtomicU64>,
}

#[derive(Clone, Debug)]
pub struct EngineCapabilities {
    methods: BTreeSet<String>,
}

impl EngineCapabilities {
    pub fn require(&self, version: EngineApiVersion) -> anyhow::Result<()> {
        let missing = version
            .required_capabilities()
            .into_iter()
            .filter(|method| !self.methods.contains(*method))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!(
                "execution client does not support Engine API {}: missing {}",
                version.number(),
                missing.join(", ")
            );
        }
        Ok(())
    }

    pub fn methods(&self) -> impl Iterator<Item = &str> {
        self.methods.iter().map(String::as_str)
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockSummary {
    pub hash: B256,
    pub number: String,
    pub timestamp: String,
}

#[derive(Clone, Debug)]
pub struct BuiltPayload {
    pub payload: ExecutionPayload,
    pub parent_beacon_block_root: Option<B256>,
    pub versioned_hashes: Vec<B256>,
    pub execution_requests: Vec<alloy_primitives::Bytes>,
}

// Alloy's untagged V2 response enum tests the V1 shape first, and V1 accepts
// the additional `withdrawals` field. EthBFT never supports pre-Shanghai
// payloads, so decode the required post-Shanghai shape without ambiguity.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShanghaiPayloadEnvelope {
    execution_payload: ExecutionPayloadV2,
    #[allow(dead_code)]
    block_value: U256,
}

impl EngineClient {
    pub fn new(endpoint: String, jwt_path: &str, timeout: Duration) -> anyhow::Result<Self> {
        let secret =
            fs::read_to_string(jwt_path).with_context(|| format!("read JWT secret {jwt_path}"))?;
        let key = hex::decode(secret.trim().trim_start_matches("0x"))
            .context("JWT secret is not valid hex")?;
        if key.len() < 32 {
            bail!("JWT secret must contain at least 32 bytes");
        }
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            endpoint,
            jwt_key: Arc::new(key),
            http,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> anyhow::Result<T> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(self.jwt()?)
            .json(&json!({
                "jsonrpc": "2.0", "id": id, "method": method, "params": params,
            }))
            .send()
            .await
            .with_context(|| format!("call {method}"))?;
        let status = response.status();
        let body = response.bytes().await.context("read JSON-RPC response")?;
        if !status.is_success() {
            bail!(
                "{method} returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let response: RpcResponse<T> = serde_json::from_slice(&body).with_context(|| {
            format!(
                "decode {method} response: {}",
                String::from_utf8_lossy(&body)
            )
        })?;
        if let Some(error) = response.error {
            bail!("{method} JSON-RPC error {}: {}", error.code, error.message);
        }
        response
            .result
            .with_context(|| format!("{method} response has no result"))
    }

    fn jwt(&self) -> anyhow::Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"iat":{now},"exp":{}}}"#, now + 60));
        let input = format!("{header}.{claims}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.jwt_key).context("create JWT signer")?;
        mac.update(input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{input}.{signature}"))
    }

    pub async fn exchange_capabilities(&self) -> anyhow::Result<EngineCapabilities> {
        let methods: Vec<String> = self
            .call(
                "engine_exchangeCapabilities",
                json!([ADVERTISED_CAPABILITIES]),
            )
            .await?;
        Ok(EngineCapabilities {
            methods: methods.into_iter().collect(),
        })
    }

    pub async fn client_version(&self) -> anyhow::Result<Option<Value>> {
        match self
            .call::<Vec<Value>>(
                "engine_getClientVersionV1",
                json!([{"code":"EBFT","name":"ethbft","version":crate::VERSION,"commit":""}]),
            )
            .await
        {
            Ok(mut versions) => Ok(versions.pop()),
            Err(error) if error.to_string().contains("-32601") => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn chain_id(&self) -> anyhow::Result<U256> {
        let value: String = self.call("eth_chainId", json!([])).await?;
        U256::from_str_radix(value.trim_start_matches("0x"), 16).context("decode eth_chainId")
    }

    pub async fn block_by_number(&self, number: &str) -> anyhow::Result<BlockSummary> {
        self.call("eth_getBlockByNumber", json!([number, false]))
            .await
    }

    pub async fn block_by_hash(&self, hash: B256) -> anyhow::Result<Option<BlockSummary>> {
        self.call("eth_getBlockByHash", json!([hash, false])).await
    }

    pub async fn block_number(&self) -> anyhow::Result<u64> {
        let value: String = self.call("eth_blockNumber", json!([])).await?;
        u64::from_str_radix(value.trim_start_matches("0x"), 16).context("decode eth_blockNumber")
    }

    pub async fn syncing(&self) -> anyhow::Result<Value> {
        self.call("eth_syncing", json!([])).await
    }

    pub async fn start_payload(
        &self,
        version: EngineApiVersion,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> anyhow::Result<ForkchoiceUpdated> {
        let method = match version {
            EngineApiVersion::V2 => "engine_forkchoiceUpdatedV2",
            EngineApiVersion::V3 | EngineApiVersion::V4 => "engine_forkchoiceUpdatedV3",
        };
        self.call(method, json!([state, attrs])).await
    }

    pub async fn get_payload(
        &self,
        version: EngineApiVersion,
        id: impl Serialize,
        parent_beacon_block_root: Option<B256>,
    ) -> anyhow::Result<BuiltPayload> {
        match version {
            EngineApiVersion::V2 => {
                let result: ShanghaiPayloadEnvelope =
                    self.call("engine_getPayloadV2", json!([id])).await?;
                let payload = ExecutionPayload::V2(result.execution_payload);
                Ok(BuiltPayload {
                    payload,
                    parent_beacon_block_root: None,
                    versioned_hashes: vec![],
                    execution_requests: vec![],
                })
            }
            EngineApiVersion::V3 => {
                let result: ExecutionPayloadEnvelopeV3 =
                    self.call("engine_getPayloadV3", json!([id])).await?;
                let payload = ExecutionPayload::V3(result.execution_payload);
                let versioned_hashes = payload_versioned_hashes(payload.transactions())?;
                Ok(BuiltPayload {
                    payload,
                    parent_beacon_block_root,
                    versioned_hashes,
                    execution_requests: vec![],
                })
            }
            EngineApiVersion::V4 => {
                let result: ExecutionPayloadEnvelopeV4 =
                    self.call("engine_getPayloadV4", json!([id])).await?;
                let payload = ExecutionPayload::V3(result.envelope_inner.execution_payload);
                let versioned_hashes = payload_versioned_hashes(payload.transactions())?;
                Ok(BuiltPayload {
                    payload,
                    parent_beacon_block_root,
                    versioned_hashes,
                    execution_requests: result.execution_requests.take(),
                })
            }
        }
    }

    pub async fn new_payload(&self, envelope: &ExecutionEnvelope) -> anyhow::Result<PayloadStatus> {
        match (&envelope.engine_api, &envelope.payload) {
            (EngineApiVersion::V2, ExecutionPayload::V2(payload)) => {
                self.call("engine_newPayloadV2", json!([payload])).await
            }
            (EngineApiVersion::V3, ExecutionPayload::V3(payload)) => {
                self.call(
                    "engine_newPayloadV3",
                    json!([
                        payload,
                        envelope.versioned_hashes,
                        envelope.parent_beacon_block_root
                    ]),
                )
                .await
            }
            (EngineApiVersion::V4, ExecutionPayload::V3(payload)) => {
                self.call(
                    "engine_newPayloadV4",
                    json!([
                        payload,
                        envelope.versioned_hashes,
                        envelope.parent_beacon_block_root,
                        envelope.execution_requests
                    ]),
                )
                .await
            }
            _ => bail!("payload shape does not match Engine API version"),
        }
    }

    pub async fn update_forkchoice(
        &self,
        version: EngineApiVersion,
        hash: B256,
    ) -> anyhow::Result<ForkchoiceUpdated> {
        let method = match version {
            EngineApiVersion::V2 => "engine_forkchoiceUpdatedV2",
            EngineApiVersion::V3 | EngineApiVersion::V4 => "engine_forkchoiceUpdatedV3",
        };
        self.call(
            method,
            json!([ForkchoiceState::same_hash(hash), Value::Null]),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn jwt_has_three_segments() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "{}", "11".repeat(32)).unwrap();
        let client = EngineClient::new(
            "http://localhost".into(),
            file.path().to_str().unwrap(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(client.jwt().unwrap().split('.').count(), 3);
    }

    #[test]
    fn capabilities_fail_closed() {
        let capabilities = EngineCapabilities {
            methods: ["engine_newPayloadV2".to_string()].into_iter().collect(),
        };
        assert!(capabilities.require(EngineApiVersion::V2).is_err());
    }
}
