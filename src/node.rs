use crate::{
    config::Config,
    engine::EngineClient,
    protocol::{
        decode_envelope, decode_transaction, encode_envelope, is_envelope, proposal_randao,
        transaction_hash, validate_payload_hash, ExecutionMetadataV1,
    },
    state::{CommitIntent, DeliveryStatus, PersistedState, StateStore},
};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types_engine::{ExecutionPayloadV2, ForkchoiceState, PayloadAttributes};
use anyhow::{bail, Context};
use async_trait::async_trait;
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use tracing::{debug, info};

#[async_trait]
pub trait ConsensusExecution {
    async fn build_proposal(
        &mut self,
        height: u64,
        timestamp: u64,
        candidates: Vec<Bytes>,
        max_bytes: i64,
    ) -> anyhow::Result<Vec<Bytes>>;
    async fn validate_proposal(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[Bytes],
    ) -> anyhow::Result<ExecutionPayloadV2>;
    async fn stage_decision(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[Bytes],
    ) -> anyhow::Result<Bytes>;
    fn commit(&mut self) -> anyhow::Result<()>;
}

pub struct Metrics {
    registry: Registry,
    pub current_height: IntGauge,
    pub txs_bridged: IntCounter,
    pub rpc_errors: IntCounter,
    pub txs_rejected: IntCounter,
    pub proposal_duration: Histogram,
}

impl Metrics {
    fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();
        let current_height = IntGauge::new(
            "ethbft_current_height",
            "Current committed consensus height",
        )?;
        let txs_bridged = IntCounter::new(
            "ethbft_txs_bridged_total",
            "Transactions committed in validated execution payloads",
        )?;
        let rpc_errors = IntCounter::new(
            "ethbft_rpc_errors_total",
            "Execution or consensus RPC failures",
        )?;
        let txs_rejected = IntCounter::new(
            "ethbft_txs_rejected_total",
            "Transactions rejected by CheckTx",
        )?;
        let proposal_duration = Histogram::with_opts(HistogramOpts::new(
            "ethbft_proposal_duration_seconds",
            "Proposal build and validation duration",
        ))?;
        for collector in [
            Box::new(current_height.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(txs_bridged.clone()),
            Box::new(rpc_errors.clone()),
            Box::new(txs_rejected.clone()),
            Box::new(proposal_duration.clone()),
        ] {
            registry.register(collector)?;
        }
        Ok(Self {
            registry,
            current_height,
            txs_bridged,
            rpc_errors,
            txs_rejected,
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
    fee_recipient: Address,
    last_progress: Instant,
}

impl Node {
    pub async fn connect(config: Config) -> anyhow::Result<Self> {
        let timeout = Duration::from_secs(config.bridge.timeout);
        let engine = EngineClient::new(
            config.ethereum.endpoint.clone(),
            config.ethereum.engine_api.clone(),
            &config.ethereum.jwt_secret,
            timeout,
        )?;
        let chain_id = engine.chain_id().await.context("read EL chain ID")?;
        let genesis = engine
            .block_by_number("0x0")
            .await
            .context("read EL genesis")?;
        let el_genesis = genesis.hash;
        let fee_recipient = if config.bridge.fee_recipient.trim().is_empty() {
            Address::ZERO
        } else {
            config
                .bridge
                .fee_recipient
                .parse()
                .context("parse fee recipient")?
        };
        let store = StateStore::new(&config.bridge.state_file);
        let state = store.load(chain_id, el_genesis)?;
        let mut node = Self {
            config,
            engine,
            state,
            store,
            metrics: Metrics::new()?,
            chain_id,
            el_genesis,
            fee_recipient,
            last_progress: Instant::now(),
        };
        node.reconcile().await?;
        node.metrics
            .current_height
            .set(node.state.abci_last_block_height as i64);
        info!(chain_id = %chain_id, genesis = %el_genesis, height = node.state.abci_last_block_height, "connected to execution layer");
        Ok(node)
    }

    fn app_hash(&self) -> &[u8] {
        &self.state.abci_last_app_hash
    }

    fn committed_parent(&self, height: u64) -> anyhow::Result<B256> {
        if height <= 1 {
            return Ok(self.el_genesis);
        }
        self.state
            .height_to_hash
            .get(&(height - 1))
            .copied()
            .with_context(|| format!("no committed execution parent for height {height}"))
    }

    async fn reconcile(&mut self) -> anyhow::Result<()> {
        if let Some(intent) = self.state.commit_intent.clone() {
            let update = self
                .engine
                .update_forkchoice(intent.payload.payload_inner.block_hash)
                .await
                .context("recover pending execution forkchoice")?;
            if !update.is_valid() {
                bail!("EL rejected recovered commit intent forkchoice");
            }
            if let Some(current) = self.state.commit_intent.as_mut() {
                current.forkchoice_applied = true;
            }
            self.store.save(&self.state)?;
            // CometBFT will replay FinalizeBlock/Commit for this decision. Keep
            // the EL on the decided payload instead of restoring the previous
            // committed forkchoice below.
            return Ok(());
        }
        if self.state.last_produced_height == 0 {
            return Ok(());
        }
        let hash = *self
            .state
            .height_to_hash
            .get(&self.state.last_produced_height)
            .context("persisted height has no execution hash")?;
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
        let update = self
            .engine
            .update_forkchoice(hash)
            .await
            .context("restore committed forkchoice")?;
        if !update.is_valid() {
            bail!("EL rejected persisted forkchoice");
        }
        Ok(())
    }

    pub fn check_transaction(&self, raw: &[u8]) -> anyhow::Result<B256> {
        let tx = decode_transaction(raw, self.chain_id)?;
        Ok(*tx.tx_hash())
    }

    async fn inject_candidates(&self, candidates: &[Bytes]) {
        for raw in candidates {
            if decode_transaction(raw, self.chain_id).is_err() {
                continue;
            }
            if let Err(error) = self.engine.submit_raw_transaction(raw).await {
                let message = error.to_string().to_ascii_lowercase();
                if !message.contains("already known") {
                    debug!(%error, "candidate was not accepted by EL txpool");
                }
            }
        }
    }

    fn validate_consensus_fields(
        &self,
        metadata: &ExecutionMetadataV1,
        height: u64,
        timestamp: u64,
    ) -> anyhow::Result<()> {
        if metadata.consensus_height != height {
            bail!("metadata height does not match proposal height");
        }
        if metadata.chain_id != self.chain_id {
            bail!("metadata chain ID does not match local EL");
        }
        if metadata.previous_app_hash.as_ref() != self.app_hash() {
            bail!("metadata previous app hash does not match committed state");
        }
        if metadata.parent_hash != self.committed_parent(height)? {
            bail!("execution parent does not match committed parent");
        }
        if metadata.timestamp != timestamp {
            bail!("execution timestamp does not match consensus timestamp");
        }
        if metadata.prev_randao != proposal_randao(self.chain_id, height, self.app_hash()) {
            bail!("invalid deterministic prevRandao");
        }
        if metadata.fee_recipient != self.fee_recipient {
            bail!("invalid fee recipient");
        }
        if !metadata.withdrawals.is_empty() {
            bail!("protocol v1 requires empty withdrawals");
        }
        Ok(())
    }

    fn execution_app_hash(
        &self,
        height: u64,
        payload: &ExecutionPayloadV2,
    ) -> anyhow::Result<Bytes> {
        let tx_root = validate_payload_hash(payload)?;
        let p = &payload.payload_inner;
        let mut hasher = Sha256::new();
        hasher.update(b"ETHBFT_APP_HASH_V1");
        hasher.update(self.app_hash());
        hasher.update(self.chain_id.to_be_bytes::<32>());
        hasher.update(height.to_be_bytes());
        hasher.update(p.parent_hash);
        hasher.update(p.block_hash);
        hasher.update(p.state_root);
        hasher.update(p.receipts_root);
        hasher.update(tx_root);
        Ok(hasher.finalize().to_vec().into())
    }

    pub fn delivery(&self, hash: B256) -> Option<&DeliveryStatus> {
        self.state.deliveries.get(&hash)
    }

    pub fn metrics(&self) -> anyhow::Result<Vec<u8>> {
        self.metrics.encode()
    }

    pub fn last_progress_seconds(&self) -> u64 {
        self.last_progress.elapsed().as_secs()
    }

    pub async fn comet_height(&self) -> anyhow::Result<i64> {
        let url = format!(
            "{}/status",
            self.config.cometbft.endpoint.trim_end_matches('/')
        );
        let value: Value = reqwest::get(url).await?.error_for_status()?.json().await?;
        value
            .pointer("/result/sync_info/latest_block_height")
            .and_then(Value::as_str)
            .context("CometBFT status has no latest height")?
            .parse()
            .context("decode CometBFT height")
    }
}

#[async_trait]
impl ConsensusExecution for Node {
    async fn build_proposal(
        &mut self,
        height: u64,
        timestamp: u64,
        candidates: Vec<Bytes>,
        max_bytes: i64,
    ) -> anyhow::Result<Vec<Bytes>> {
        let started = Instant::now();
        let result = async {
            if height == 0 || timestamp == 0 {
                bail!("proposal height and timestamp must be positive");
            }
            let parent = self.committed_parent(height)?;
            let parent_block = self
                .engine
                .block_by_hash(parent)
                .await?
                .context("execution parent is missing")?;
            if timestamp <= parse_hex_u64(&parent_block.timestamp)? {
                bail!("proposal timestamp is not greater than parent timestamp");
            }
            self.inject_candidates(&candidates).await;
            let parent_update = self.engine.update_forkchoice(parent).await?;
            if !parent_update.is_valid() {
                bail!("EL rejected committed parent forkchoice");
            }
            let attrs = PayloadAttributes {
                timestamp,
                prev_randao: proposal_randao(self.chain_id, height, self.app_hash()),
                suggested_fee_recipient: self.fee_recipient,
                withdrawals: Some(vec![]),
                parent_beacon_block_root: None,
            };
            let build = self
                .engine
                .start_payload(ForkchoiceState::same_hash(parent), attrs.clone())
                .await?;
            if !build.is_valid() {
                bail!("payload build forkchoice was not VALID");
            }
            let payload_id = build
                .payload_id
                .context("payload build returned no payload ID")?;
            let payload = self
                .engine
                .get_payload_v2(payload_id)
                .await?
                .execution_payload;
            let p = &payload.payload_inner;
            if p.parent_hash != parent
                || p.timestamp != timestamp
                || p.prev_randao != attrs.prev_randao
                || p.fee_recipient != self.fee_recipient
            {
                bail!("builder returned payload with non-deterministic attributes");
            }
            if !payload.withdrawals.is_empty() {
                bail!("protocol v1 requires empty withdrawals");
            }
            validate_payload_hash(&payload)?;
            let metadata = ExecutionMetadataV1::from_payload(
                self.chain_id,
                height,
                self.app_hash(),
                &payload,
            )?;
            let envelope = encode_envelope(&metadata)?;
            let mut proposal = Vec::with_capacity(payload.payload_inner.transactions.len() + 1);
            proposal.push(envelope);
            proposal.extend(payload.payload_inner.transactions.iter().cloned());
            let total: usize = proposal.iter().map(|item| item.len()).sum();
            if max_bytes > 0 && total > max_bytes as usize {
                bail!("execution proposal uses {total} bytes, maximum is {max_bytes}");
            }
            Ok(proposal)
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

    async fn validate_proposal(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[Bytes],
    ) -> anyhow::Result<ExecutionPayloadV2> {
        let started = Instant::now();
        let result = async {
            let envelope = proposal
                .first()
                .context("proposal has no execution envelope")?;
            let metadata = decode_envelope(envelope)?;
            self.validate_consensus_fields(&metadata, height, timestamp)?;
            let mut seen = BTreeSet::new();
            for raw in proposal.iter().skip(1) {
                if is_envelope(raw) {
                    bail!("multiple execution envelopes in proposal");
                }
                let tx = decode_transaction(raw, self.chain_id)?;
                if !seen.insert(*tx.tx_hash()) {
                    bail!("duplicate execution transaction {}", tx.tx_hash());
                }
            }
            let transactions = proposal.iter().skip(1).cloned().collect::<Vec<_>>();
            let payload = metadata.payload(&transactions)?;
            validate_payload_hash(&payload)?;
            let status = self.engine.new_payload_v2(&payload).await?;
            if !status.is_valid() {
                bail!("execution payload status was not VALID: {status}");
            }
            if let Some(latest) = status.latest_valid_hash {
                if latest != payload.payload_inner.block_hash {
                    bail!("latest valid hash does not match payload block hash");
                }
            }
            Ok(payload)
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

    async fn stage_decision(
        &mut self,
        height: u64,
        timestamp: u64,
        proposal: &[Bytes],
    ) -> anyhow::Result<Bytes> {
        if let Some(intent) = self.state.commit_intent.clone() {
            if intent.height != height {
                bail!(
                    "uncommitted execution decision remains at height {}",
                    intent.height
                );
            }
            let payload = self.validate_proposal(height, timestamp, proposal).await?;
            let transactions = proposal.iter().skip(1).cloned().collect::<Vec<_>>();
            let app_hash = self.execution_app_hash(height, &payload)?;
            if payload.payload_inner.block_hash != intent.payload.payload_inner.block_hash
                || transactions != intent.transactions
                || app_hash != intent.app_hash
            {
                bail!("replayed decision does not match persisted commit intent");
            }
            if !intent.forkchoice_applied {
                let update = self
                    .engine
                    .update_forkchoice(payload.payload_inner.block_hash)
                    .await?;
                if !update.is_valid() {
                    bail!("EL rejected replayed execution forkchoice");
                }
                self.state
                    .commit_intent
                    .as_mut()
                    .expect("intent exists")
                    .forkchoice_applied = true;
                self.store
                    .save(&self.state)
                    .context("persist replayed forkchoice intent")?;
            }
            return Ok(app_hash);
        }
        let payload = self.validate_proposal(height, timestamp, proposal).await?;
        let app_hash = self.execution_app_hash(height, &payload)?;
        let transactions = proposal.iter().skip(1).cloned().collect::<Vec<_>>();
        self.state.commit_intent = Some(CommitIntent {
            height,
            payload: payload.clone(),
            app_hash: app_hash.clone(),
            transactions,
            forkchoice_applied: false,
        });
        self.store
            .save(&self.state)
            .context("persist commit intent")?;
        let update = self
            .engine
            .update_forkchoice(payload.payload_inner.block_hash)
            .await?;
        if !update.is_valid() {
            bail!("EL rejected decided execution forkchoice");
        }
        self.state
            .commit_intent
            .as_mut()
            .expect("intent exists")
            .forkchoice_applied = true;
        self.store
            .save(&self.state)
            .context("persist applied forkchoice intent")?;
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
        let previous = self.state.clone();
        let block_hash = intent.payload.payload_inner.block_hash;
        for raw in &intent.transactions {
            let hash = transaction_hash(raw)?;
            self.state.deliveries.insert(
                hash,
                DeliveryStatus {
                    tx_hash: hash,
                    height: intent.height,
                    status: "included".into(),
                    last_error: String::new(),
                    el_block_hash: block_hash,
                    attempts: 0,
                },
            );
        }
        self.state.height_to_hash.insert(intent.height, block_hash);
        while self.state.height_to_hash.len() > 4096 {
            if let Some(oldest) = self.state.height_to_hash.keys().next().copied() {
                self.state.height_to_hash.remove(&oldest);
            }
        }
        self.state.last_produced_height = intent.height;
        self.state.abci_last_block_height = intent.height;
        self.state.abci_last_app_hash = intent.app_hash;
        self.state.commit_intent = None;
        let prune_before = intent.height.saturating_sub(4096);
        self.state
            .deliveries
            .retain(|_, delivery| delivery.height >= prune_before);
        if let Err(error) = self.store.save(&self.state) {
            self.state = previous;
            return Err(error);
        }
        self.metrics.current_height.set(intent.height as i64);
        self.metrics
            .txs_bridged
            .inc_by(intent.transactions.len() as u64);
        self.last_progress = Instant::now();
        Ok(())
    }
}

fn parse_hex_u64(value: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .with_context(|| format!("decode hexadecimal quantity {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_quantity_parses() {
        assert_eq!(parse_hex_u64("0x2a").unwrap(), 42);
    }
}
