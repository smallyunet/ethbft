use crate::{
    config::Config,
    engine::EngineClient,
    protocol::{
        decode_envelope, encode_envelope, proposal_beacon_root, proposal_randao, EngineApiVersion,
        ExecutionEnvelope,
    },
    state::{CommitIntent, PersistedState, StateStore},
};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types_engine::{ForkchoiceState, PayloadAttributes};
use anyhow::{bail, Context};
use async_trait::async_trait;
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[async_trait]
pub trait ConsensusApplication {
    async fn propose(
        &mut self,
        height: u64,
        timestamp: u64,
        max_bytes: i64,
    ) -> anyhow::Result<Bytes>;
    async fn validate(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[u8],
    ) -> anyhow::Result<ExecutionEnvelope>;
    async fn decide(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[u8],
    ) -> anyhow::Result<Bytes>;
    fn commit(&mut self) -> anyhow::Result<()>;
}

pub struct Metrics {
    registry: Registry,
    pub current_height: IntGauge,
    pub payloads_committed: IntCounter,
    pub payload_transactions: IntCounter,
    pub rpc_errors: IntCounter,
    pub proposals_rejected: IntCounter,
    pub proposal_duration: Histogram,
}

impl Metrics {
    fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();
        let current_height = IntGauge::new(
            "ethbft_current_height",
            "Current committed consensus height",
        )?;
        let payloads_committed = IntCounter::new(
            "ethbft_payloads_committed_total",
            "Execution payloads committed by BFT consensus",
        )?;
        let payload_transactions = IntCounter::new(
            "ethbft_payload_transactions_total",
            "Transactions contained in committed execution payloads",
        )?;
        let rpc_errors = IntCounter::new(
            "ethbft_engine_rpc_errors_total",
            "Execution Engine API failures",
        )?;
        let proposals_rejected = IntCounter::new(
            "ethbft_proposals_rejected_total",
            "Execution proposals rejected before voting",
        )?;
        let proposal_duration = Histogram::with_opts(HistogramOpts::new(
            "ethbft_proposal_duration_seconds",
            "Proposal build and validation duration",
        ))?;
        for collector in [
            Box::new(current_height.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(payloads_committed.clone()),
            Box::new(payload_transactions.clone()),
            Box::new(rpc_errors.clone()),
            Box::new(proposals_rejected.clone()),
            Box::new(proposal_duration.clone()),
        ] {
            registry.register(collector)?;
        }
        Ok(Self {
            registry,
            current_height,
            payloads_committed,
            payload_transactions,
            rpc_errors,
            proposals_rejected,
            proposal_duration,
        })
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut out)?;
        Ok(out)
    }
}

pub struct Node {
    pub config: Config,
    pub engine: EngineClient,
    pub state: PersistedState,
    store: StateStore,
    pub metrics: Metrics,
    pub chain_id: U256,
    pub el_genesis: B256,
    pub protocol_fingerprint: B256,
    fee_recipient: Address,
    last_progress: Instant,
}

impl Node {
    pub async fn connect(config: Config) -> anyhow::Result<Self> {
        let timeout = Duration::from_secs(config.node.timeout);
        let engine = EngineClient::new(
            config.execution.endpoint.clone(),
            &config.execution.jwt_secret,
            timeout,
        )?;
        let capabilities = engine
            .exchange_capabilities()
            .await
            .context("exchange Engine API capabilities")?;
        for version in config.protocol.configured_versions() {
            capabilities.require(version)?;
        }
        let chain_id = engine.chain_id().await.context("read EL chain ID")?;
        let genesis = engine
            .block_by_number("0x0")
            .await
            .context("read EL genesis")?;
        let el_genesis = genesis.hash;
        let fee_recipient = config.protocol.fee_recipient()?;
        let protocol_fingerprint = protocol_fingerprint(&config, chain_id, el_genesis)?;
        let store = StateStore::new(&config.node.state_file);
        let state = store.load(chain_id, el_genesis, protocol_fingerprint)?;
        let mut node = Self {
            config,
            engine,
            state,
            store,
            metrics: Metrics::new()?,
            chain_id,
            el_genesis,
            protocol_fingerprint,
            fee_recipient,
            last_progress: Instant::now(),
        };
        node.reconcile().await?;
        node.metrics
            .current_height
            .set(node.state.last_committed_height as i64);
        let client_version = node.engine.client_version().await.ok().flatten();
        let capability_list = capabilities.methods().collect::<Vec<_>>().join(",");
        info!(
            chain_id = %chain_id,
            genesis = %el_genesis,
            protocol_fingerprint = %protocol_fingerprint,
            height = node.state.last_committed_height,
            capabilities = %capability_list,
            client_version = ?client_version,
            "connected to Engine API"
        );
        if !matches!(node.engine.syncing().await?, Value::Bool(false)) {
            warn!("execution client reports active sync; validator must not vote until ready");
        }
        Ok(node)
    }

    fn app_hash(&self) -> &[u8] {
        &self.state.last_app_hash
    }

    fn committed_parent(&self) -> B256 {
        self.state.last_execution_hash
    }

    async fn reconcile(&mut self) -> anyhow::Result<()> {
        if let Some(intent) = self.state.commit_intent.clone() {
            let envelope = decode_envelope(&intent.encoded_envelope)
                .context("decode pending commit intent")?;
            if envelope.block_hash() != intent.block_hash
                || envelope.engine_api.number() != intent.engine_api_version
            {
                bail!("pending commit intent does not match encoded execution envelope");
            }
            let update = self
                .engine
                .update_forkchoice(envelope.engine_api, envelope.block_hash())
                .await
                .context("recover pending execution forkchoice")?;
            if !update.is_valid() {
                bail!("EL rejected recovered commit intent forkchoice");
            }
            if let Some(current) = self.state.commit_intent.as_mut() {
                current.forkchoice_applied = true;
            }
            self.store.save(&self.state)?;
            return Ok(());
        }
        if self.state.last_committed_height == 0 {
            return Ok(());
        }
        let hash = self.state.last_execution_hash;
        let block = self
            .engine
            .block_by_hash(hash)
            .await?
            .context("persisted execution block is missing")?;
        let number = parse_hex_u64(&block.number)?;
        let canonical = self
            .engine
            .block_by_number(&format!("0x{number:x}"))
            .await?;
        if canonical.hash != hash {
            bail!("persisted execution block {hash} is not canonical at EL height {number}");
        }
        let version = self
            .config
            .protocol
            .engine_version(parse_hex_u64(&block.timestamp)?)?;
        let update = self.engine.update_forkchoice(version, hash).await?;
        if !update.is_valid() {
            bail!("EL rejected persisted forkchoice");
        }
        Ok(())
    }

    fn validate_consensus_fields(
        &self,
        envelope: &ExecutionEnvelope,
        height: u64,
        timestamp: u64,
    ) -> anyhow::Result<()> {
        if envelope.consensus_height != height {
            bail!("envelope height does not match consensus height");
        }
        if envelope.chain_id != self.chain_id {
            bail!("envelope chain ID does not match local EL");
        }
        if envelope.previous_app_hash.as_ref() != self.app_hash() {
            bail!("envelope previous app hash does not match committed state");
        }
        if envelope.parent_hash() != self.committed_parent() {
            bail!("execution parent does not match committed parent");
        }
        if envelope.timestamp() != timestamp {
            bail!("execution timestamp does not match consensus timestamp");
        }
        let expected_version = self.config.protocol.engine_version(timestamp)?;
        if envelope.engine_api != expected_version {
            bail!("Engine API version does not match the configured fork schedule");
        }
        let payload = envelope.payload.as_v1();
        if payload.prev_randao != proposal_randao(self.chain_id, height, self.app_hash()) {
            bail!("invalid deterministic prevRandao");
        }
        if payload.fee_recipient != self.fee_recipient {
            bail!("invalid fee recipient");
        }
        let expected_beacon_root = match expected_version {
            EngineApiVersion::V2 => None,
            EngineApiVersion::V3 | EngineApiVersion::V4 => {
                Some(proposal_beacon_root(height, self.app_hash()))
            }
        };
        if envelope.parent_beacon_block_root != expected_beacon_root {
            bail!("invalid deterministic parent beacon block root");
        }
        envelope.validate()?;
        Ok(())
    }

    fn execution_app_hash(&self, height: u64, encoded_envelope: &[u8]) -> Bytes {
        let mut hasher = Sha256::new();
        hasher.update(b"ETHBFT_APP_HASH_V2");
        hasher.update(self.app_hash());
        hasher.update(self.protocol_fingerprint);
        hasher.update(height.to_be_bytes());
        hasher.update(Sha256::digest(encoded_envelope));
        hasher.finalize().to_vec().into()
    }

    pub fn metrics(&self) -> anyhow::Result<Vec<u8>> {
        self.metrics.encode()
    }

    pub fn last_progress_seconds(&self) -> u64 {
        self.last_progress.elapsed().as_secs()
    }
}

#[async_trait]
impl ConsensusApplication for Node {
    async fn propose(
        &mut self,
        height: u64,
        timestamp: u64,
        max_bytes: i64,
    ) -> anyhow::Result<Bytes> {
        let started = Instant::now();
        let result = async {
            if height == 0 || timestamp == 0 {
                bail!("proposal height and timestamp must be positive");
            }
            let parent = self.committed_parent();
            let parent_block = self
                .engine
                .block_by_hash(parent)
                .await?
                .context("execution parent is missing")?;
            if timestamp <= parse_hex_u64(&parent_block.timestamp)? {
                bail!("proposal timestamp is not greater than parent timestamp");
            }
            let version = self.config.protocol.engine_version(timestamp)?;
            let parent_update = self.engine.update_forkchoice(version, parent).await?;
            if !parent_update.is_valid() {
                bail!("EL rejected committed parent forkchoice");
            }
            let parent_beacon_block_root = match version {
                EngineApiVersion::V2 => None,
                EngineApiVersion::V3 | EngineApiVersion::V4 => {
                    Some(proposal_beacon_root(height, self.app_hash()))
                }
            };
            let attrs = PayloadAttributes {
                timestamp,
                prev_randao: proposal_randao(self.chain_id, height, self.app_hash()),
                suggested_fee_recipient: self.fee_recipient,
                withdrawals: Some(vec![]),
                parent_beacon_block_root,
            };
            let build = self
                .engine
                .start_payload(version, ForkchoiceState::same_hash(parent), attrs.clone())
                .await?;
            if !build.is_valid() {
                bail!("payload build forkchoice was not VALID");
            }
            let payload_id = build
                .payload_id
                .context("payload build returned no payload ID")?;
            let built = self
                .engine
                .get_payload(version, payload_id, parent_beacon_block_root)
                .await?;
            let envelope = ExecutionEnvelope {
                engine_api: version,
                chain_id: self.chain_id,
                consensus_height: height,
                previous_app_hash: Bytes::copy_from_slice(self.app_hash()),
                payload: built.payload,
                parent_beacon_block_root: built.parent_beacon_block_root,
                versioned_hashes: built.versioned_hashes,
                execution_requests: built.execution_requests,
            };
            self.validate_consensus_fields(&envelope, height, timestamp)?;
            let encoded = encode_envelope(&envelope)?;
            let limit = if max_bytes > 0 {
                usize::try_from(max_bytes).unwrap_or(usize::MAX)
            } else {
                self.config.protocol.max_payload_bytes
            }
            .min(self.config.protocol.max_payload_bytes);
            if encoded.len() > limit {
                bail!(
                    "execution envelope uses {} bytes, maximum is {limit}",
                    encoded.len()
                );
            }
            Ok(encoded)
        }
        .await;
        self.metrics
            .proposal_duration
            .observe(started.elapsed().as_secs_f64());
        if result.is_err() {
            self.metrics.rpc_errors.inc();
        }
        result
    }

    async fn validate(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[u8],
    ) -> anyhow::Result<ExecutionEnvelope> {
        let started = Instant::now();
        let result = async {
            if proposal.len() > self.config.protocol.max_payload_bytes {
                bail!("execution envelope exceeds configured maximum");
            }
            let envelope = decode_envelope(proposal)?;
            self.validate_consensus_fields(&envelope, height, timestamp)?;
            let status = self.engine.new_payload(&envelope).await?;
            if !status.is_valid() {
                bail!("execution payload status was not VALID: {status}");
            }
            if let Some(latest) = status.latest_valid_hash {
                if latest != envelope.block_hash() {
                    bail!("latest valid hash does not match payload block hash");
                }
            }
            Ok(envelope)
        }
        .await;
        self.metrics
            .proposal_duration
            .observe(started.elapsed().as_secs_f64());
        if result.is_err() {
            self.metrics.proposals_rejected.inc();
        }
        result
    }

    async fn decide(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[u8],
    ) -> anyhow::Result<Bytes> {
        if let Some(intent) = self.state.commit_intent.clone() {
            if intent.height != height || intent.encoded_envelope.as_ref() != proposal {
                bail!("replayed decision does not match persisted commit intent");
            }
            let envelope = self.validate(height, timestamp, proposal).await?;
            let app_hash = self.execution_app_hash(height, proposal);
            if envelope.block_hash() != intent.block_hash || app_hash != intent.app_hash {
                bail!("replayed decision commitment does not match persisted intent");
            }
            if !intent.forkchoice_applied {
                let update = self
                    .engine
                    .update_forkchoice(envelope.engine_api, envelope.block_hash())
                    .await?;
                if !update.is_valid() {
                    bail!("EL rejected replayed execution forkchoice");
                }
                self.state
                    .commit_intent
                    .as_mut()
                    .expect("intent exists")
                    .forkchoice_applied = true;
                self.store.save(&self.state)?;
            }
            return Ok(app_hash);
        }

        let envelope = self.validate(height, timestamp, proposal).await?;
        let app_hash = self.execution_app_hash(height, proposal);
        self.state.commit_intent = Some(CommitIntent {
            height,
            encoded_envelope: Bytes::copy_from_slice(proposal),
            app_hash: app_hash.clone(),
            block_hash: envelope.block_hash(),
            engine_api_version: envelope.engine_api.number(),
            forkchoice_applied: false,
        });
        self.store
            .save(&self.state)
            .context("persist commit intent")?;
        let update = self
            .engine
            .update_forkchoice(envelope.engine_api, envelope.block_hash())
            .await?;
        if !update.is_valid() {
            bail!("EL rejected decided execution forkchoice");
        }
        self.state
            .commit_intent
            .as_mut()
            .expect("intent exists")
            .forkchoice_applied = true;
        self.store.save(&self.state)?;
        Ok(app_hash)
    }

    fn commit(&mut self) -> anyhow::Result<()> {
        let intent = self
            .state
            .commit_intent
            .clone()
            .context("no finalized execution payload to commit")?;
        if !intent.forkchoice_applied {
            bail!("decided execution forkchoice has not been applied");
        }
        let envelope = decode_envelope(&intent.encoded_envelope)?;
        let previous = self.state.clone();
        self.state.last_committed_height = intent.height;
        self.state.last_execution_hash = intent.block_hash;
        self.state.last_app_hash = intent.app_hash;
        self.state.commit_intent = None;
        if let Err(error) = self.store.save(&self.state) {
            self.state = previous;
            return Err(error);
        }
        self.metrics.current_height.set(intent.height as i64);
        self.metrics.payloads_committed.inc();
        self.metrics
            .payload_transactions
            .inc_by(envelope.transactions().len() as u64);
        self.last_progress = Instant::now();
        Ok(())
    }
}

fn protocol_fingerprint(config: &Config, chain_id: U256, genesis: B256) -> anyhow::Result<B256> {
    let mut hasher = Sha256::new();
    hasher.update(b"ETHBFT_PROTOCOL_FINGERPRINT_V2");
    hasher.update(chain_id.to_be_bytes::<32>());
    hasher.update(genesis);
    hasher.update(serde_json::to_vec(&config.protocol)?);
    Ok(B256::new(hasher.finalize().into()))
}

fn parse_hex_u64(value: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .with_context(|| format!("decode hexadecimal quantity {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_fingerprint_changes_with_consensus_parameters() {
        let first = Config::default();
        let mut second = Config::default();
        second.protocol.max_payload_bytes += 1;
        assert_ne!(
            protocol_fingerprint(&first, U256::from(1), B256::ZERO).unwrap(),
            protocol_fingerprint(&second, U256::from(1), B256::ZERO).unwrap()
        );
    }
}
