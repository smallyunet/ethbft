use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::{
    ExecutionPayloadV2, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadStatus,
};
use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    fs,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct EngineClient {
    execution_endpoint: String,
    engine_endpoint: String,
    jwt_key: Arc<Vec<u8>>,
    http: Client,
    next_id: Arc<AtomicU64>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPayloadV2Result {
    pub execution_payload: ExecutionPayloadV2,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockSummary {
    pub hash: B256,
    pub number: String,
    pub timestamp: String,
}

impl EngineClient {
    pub fn new(
        execution_endpoint: String,
        engine_endpoint: String,
        jwt_path: &str,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
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
            execution_endpoint,
            engine_endpoint,
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
        let engine = method.starts_with("engine_");
        let endpoint = if engine {
            &self.engine_endpoint
        } else {
            &self.execution_endpoint
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = self.http.post(endpoint).json(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params,
        }));
        if engine {
            request = request.bearer_auth(self.jwt()?);
        }
        let response = request
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

    pub async fn submit_raw_transaction(&self, raw: &[u8]) -> anyhow::Result<B256> {
        self.call(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(raw))]),
        )
        .await
    }

    pub async fn start_payload(
        &self,
        state: ForkchoiceState,
        attrs: PayloadAttributes,
    ) -> anyhow::Result<ForkchoiceUpdated> {
        self.call("engine_forkchoiceUpdatedV2", json!([state, attrs]))
            .await
    }

    pub async fn get_payload_v2(&self, id: impl Serialize) -> anyhow::Result<GetPayloadV2Result> {
        self.call("engine_getPayloadV2", json!([id])).await
    }

    pub async fn new_payload_v2(
        &self,
        payload: &ExecutionPayloadV2,
    ) -> anyhow::Result<PayloadStatus> {
        self.call("engine_newPayloadV2", json!([payload])).await
    }

    pub async fn update_forkchoice(&self, hash: B256) -> anyhow::Result<ForkchoiceUpdated> {
        self.call(
            "engine_forkchoiceUpdatedV2",
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
            "http://localhost".into(),
            file.path().to_str().unwrap(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(client.jwt().unwrap().split('.').count(), 3);
    }
}
