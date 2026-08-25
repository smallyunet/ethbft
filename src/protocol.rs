use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::{eip4895::Withdrawal, eip7685::Requests, Decodable2718};
use alloy_primitives::{keccak256, Address, Bloom, Bytes, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use alloy_rpc_types_engine::{
    CancunPayloadFields, ExecutionData, ExecutionPayload, ExecutionPayloadSidecar,
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, PraguePayloadFields,
};
use anyhow::{bail, Context};

pub const PROTOCOL_VERSION: u64 = 2;
pub const ENGINE_API_V2: u64 = 2;
pub const ENGINE_API_V3: u64 = 3;
pub const ENGINE_API_V4: u64 = 4;
pub const MAX_ENVELOPE_LEN: usize = 32 * 1024 * 1024;
pub const ENVELOPE_PREFIX: &[u8; 8] = b"ETHBFT\0\x02";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineApiVersion {
    V2,
    V3,
    V4,
}

impl EngineApiVersion {
    pub const fn number(self) -> u64 {
        match self {
            Self::V2 => ENGINE_API_V2,
            Self::V3 => ENGINE_API_V3,
            Self::V4 => ENGINE_API_V4,
        }
    }

    pub fn from_number(value: u64) -> anyhow::Result<Self> {
        match value {
            ENGINE_API_V2 => Ok(Self::V2),
            ENGINE_API_V3 => Ok(Self::V3),
            ENGINE_API_V4 => Ok(Self::V4),
            _ => bail!("unsupported Engine API version {value}"),
        }
    }

    pub const fn required_capabilities(self) -> [&'static str; 3] {
        match self {
            Self::V2 => [
                "engine_forkchoiceUpdatedV2",
                "engine_getPayloadV2",
                "engine_newPayloadV2",
            ],
            Self::V3 => [
                "engine_forkchoiceUpdatedV3",
                "engine_getPayloadV3",
                "engine_newPayloadV3",
            ],
            Self::V4 => [
                "engine_forkchoiceUpdatedV3",
                "engine_getPayloadV4",
                "engine_newPayloadV4",
            ],
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionEnvelope {
    pub engine_api: EngineApiVersion,
    pub chain_id: U256,
    pub consensus_height: u64,
    pub previous_app_hash: Bytes,
    pub payload: ExecutionPayload,
    pub parent_beacon_block_root: Option<B256>,
    pub versioned_hashes: Vec<B256>,
    pub execution_requests: Vec<Bytes>,
}

impl ExecutionEnvelope {
    pub fn block_hash(&self) -> B256 {
        self.payload.block_hash()
    }

    pub fn parent_hash(&self) -> B256 {
        self.payload.parent_hash()
    }

    pub fn timestamp(&self) -> u64 {
        self.payload.timestamp()
    }

    pub fn transactions(&self) -> &[Bytes] {
        self.payload.transactions()
    }

    pub fn execution_data(&self) -> anyhow::Result<ExecutionData> {
        let sidecar = match self.engine_api {
            EngineApiVersion::V2 => ExecutionPayloadSidecar::none(),
            EngineApiVersion::V3 => ExecutionPayloadSidecar::v3(CancunPayloadFields::new(
                self.parent_beacon_block_root
                    .context("Engine API V3 requires parent beacon block root")?,
                self.versioned_hashes.clone(),
            )),
            EngineApiVersion::V4 => ExecutionPayloadSidecar::v4(
                CancunPayloadFields::new(
                    self.parent_beacon_block_root
                        .context("Engine API V4 requires parent beacon block root")?,
                    self.versioned_hashes.clone(),
                ),
                PraguePayloadFields::new(Requests::new(self.execution_requests.clone())),
            ),
        };
        Ok(ExecutionData::new(self.payload.clone(), sidecar))
    }

    pub fn validate(&self) -> anyhow::Result<B256> {
        if self.chain_id.is_zero() || self.consensus_height == 0 {
            bail!("chain ID and consensus height must be positive");
        }
        if !self.previous_app_hash.is_empty() && self.previous_app_hash.len() != 32 {
            bail!("previous app hash must be empty or 32 bytes");
        }
        if self.payload.as_v1().extra_data.len() > 32 {
            bail!("extra data exceeds 32 bytes");
        }
        if self.block_hash().is_zero() {
            bail!("execution block hash must not be zero");
        }
        match (self.engine_api, &self.payload) {
            (EngineApiVersion::V2, ExecutionPayload::V2(_)) => {
                if self.parent_beacon_block_root.is_some()
                    || !self.versioned_hashes.is_empty()
                    || !self.execution_requests.is_empty()
                {
                    bail!("Engine API V2 envelope contains post-Shanghai fields");
                }
            }
            (EngineApiVersion::V3, ExecutionPayload::V3(_)) => {
                if self.parent_beacon_block_root.is_none() {
                    bail!("Engine API V3 requires parent beacon block root");
                }
                if !self.execution_requests.is_empty() {
                    bail!("Engine API V3 envelope contains Prague execution requests");
                }
            }
            (EngineApiVersion::V4, ExecutionPayload::V3(_)) => {
                if self.parent_beacon_block_root.is_none() {
                    bail!("Engine API V4 requires parent beacon block root");
                }
                validate_requests(&self.execution_requests)?;
            }
            _ => bail!("payload shape does not match Engine API version"),
        }

        let decoded_hashes = payload_versioned_hashes(self.payload.transactions())?;
        if decoded_hashes != self.versioned_hashes {
            bail!("blob versioned hashes do not match payload transactions");
        }

        let expected = self.block_hash();
        let block = self
            .execution_data()?
            .try_into_block::<TxEnvelope>()
            .context("reconstruct execution block")?;
        let actual = alloy_consensus::Sealable::hash_slow(&block.header);
        if actual != expected {
            bail!("execution block hash mismatch: computed {actual}, proposed {expected}");
        }
        Ok(block.header.transactions_root)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct WithdrawalRlp {
    index: u64,
    validator_index: u64,
    address: Address,
    amount: u64,
}

impl From<&Withdrawal> for WithdrawalRlp {
    fn from(value: &Withdrawal) -> Self {
        Self {
            index: value.index,
            validator_index: value.validator_index,
            address: value.address,
            amount: value.amount,
        }
    }
}

impl From<WithdrawalRlp> for Withdrawal {
    fn from(value: WithdrawalRlp) -> Self {
        Self {
            index: value.index,
            validator_index: value.validator_index,
            address: value.address,
            amount: value.amount,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct EnvelopeRlp {
    protocol_version: u64,
    engine_api_version: u64,
    chain_id: U256,
    consensus_height: u64,
    previous_app_hash: Bytes,
    parent_hash: B256,
    fee_recipient: Address,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bytes,
    prev_randao: B256,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: Bytes,
    base_fee: U256,
    block_hash: B256,
    transactions: Vec<Bytes>,
    withdrawals: Vec<WithdrawalRlp>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    parent_beacon_block_root: Bytes,
    versioned_hashes: Vec<B256>,
    execution_requests: Vec<Bytes>,
}

pub fn encode_envelope(envelope: &ExecutionEnvelope) -> anyhow::Result<Bytes> {
    envelope.validate()?;
    let payload = envelope.payload.as_v1();
    let withdrawals = envelope
        .payload
        .withdrawals()
        .context("protocol v2 requires withdrawals field")?;
    let body = alloy_rlp::encode(EnvelopeRlp {
        protocol_version: PROTOCOL_VERSION,
        engine_api_version: envelope.engine_api.number(),
        chain_id: envelope.chain_id,
        consensus_height: envelope.consensus_height,
        previous_app_hash: envelope.previous_app_hash.clone(),
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: Bytes::copy_from_slice(payload.logs_bloom.as_slice()),
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions: payload.transactions.clone(),
        withdrawals: withdrawals.iter().map(WithdrawalRlp::from).collect(),
        blob_gas_used: envelope.payload.blob_gas_used().unwrap_or_default(),
        excess_blob_gas: envelope.payload.excess_blob_gas().unwrap_or_default(),
        parent_beacon_block_root: envelope
            .parent_beacon_block_root
            .map(|hash| Bytes::copy_from_slice(hash.as_slice()))
            .unwrap_or_default(),
        versioned_hashes: envelope.versioned_hashes.clone(),
        execution_requests: envelope.execution_requests.clone(),
    });
    if body.len() + ENVELOPE_PREFIX.len() > MAX_ENVELOPE_LEN {
        bail!("execution envelope exceeds {MAX_ENVELOPE_LEN} bytes");
    }
    let mut out = Vec::with_capacity(ENVELOPE_PREFIX.len() + body.len());
    out.extend_from_slice(ENVELOPE_PREFIX);
    out.extend_from_slice(&body);
    Ok(out.into())
}

pub fn decode_envelope(raw: &[u8]) -> anyhow::Result<ExecutionEnvelope> {
    if !raw.starts_with(ENVELOPE_PREFIX) {
        bail!("missing EthBFT protocol-v2 envelope prefix");
    }
    if raw.len() > MAX_ENVELOPE_LEN {
        bail!("execution envelope exceeds {MAX_ENVELOPE_LEN} bytes");
    }
    let body = &raw[ENVELOPE_PREFIX.len()..];
    let mut cursor = body;
    let value = EnvelopeRlp::decode(&mut cursor).context("decode execution envelope")?;
    if !cursor.is_empty() || alloy_rlp::encode(&value).as_slice() != body {
        bail!("non-canonical execution envelope encoding");
    }
    if value.protocol_version != PROTOCOL_VERSION {
        bail!("unsupported protocol version {}", value.protocol_version);
    }
    if value.logs_bloom.len() != 256 {
        bail!("logs bloom must be 256 bytes");
    }
    let engine_api = EngineApiVersion::from_number(value.engine_api_version)?;
    let parent_beacon_block_root = match value.parent_beacon_block_root.len() {
        0 => None,
        32 => Some(B256::from_slice(&value.parent_beacon_block_root)),
        _ => bail!("parent beacon block root must be empty or 32 bytes"),
    };
    let withdrawals = value
        .withdrawals
        .into_iter()
        .map(Withdrawal::from)
        .collect();
    let payload_v1 = ExecutionPayloadV1 {
        parent_hash: value.parent_hash,
        fee_recipient: value.fee_recipient,
        state_root: value.state_root,
        receipts_root: value.receipts_root,
        logs_bloom: Bloom::from_slice(&value.logs_bloom),
        prev_randao: value.prev_randao,
        block_number: value.block_number,
        gas_limit: value.gas_limit,
        gas_used: value.gas_used,
        timestamp: value.timestamp,
        extra_data: value.extra_data,
        base_fee_per_gas: value.base_fee,
        block_hash: value.block_hash,
        transactions: value.transactions,
    };
    let payload_v2 = ExecutionPayloadV2 {
        payload_inner: payload_v1,
        withdrawals,
    };
    let payload = match engine_api {
        EngineApiVersion::V2 => ExecutionPayload::V2(payload_v2),
        EngineApiVersion::V3 | EngineApiVersion::V4 => ExecutionPayload::V3(ExecutionPayloadV3 {
            payload_inner: payload_v2,
            blob_gas_used: value.blob_gas_used,
            excess_blob_gas: value.excess_blob_gas,
        }),
    };
    let envelope = ExecutionEnvelope {
        engine_api,
        chain_id: value.chain_id,
        consensus_height: value.consensus_height,
        previous_app_hash: value.previous_app_hash,
        payload,
        parent_beacon_block_root,
        versioned_hashes: value.versioned_hashes,
        execution_requests: value.execution_requests,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn payload_versioned_hashes(transactions: &[Bytes]) -> anyhow::Result<Vec<B256>> {
    let mut hashes = Vec::new();
    for raw in transactions {
        let tx = TxEnvelope::decode_2718_exact(raw).context("invalid transaction encoding")?;
        if let Some(tx_hashes) = tx.blob_versioned_hashes() {
            hashes.extend_from_slice(tx_hashes);
        }
    }
    Ok(hashes)
}

fn validate_requests(requests: &[Bytes]) -> anyhow::Result<()> {
    let mut previous = None;
    for request in requests {
        if request.len() <= 1 {
            bail!("execution request must contain a type and non-empty data");
        }
        let request_type = request[0];
        if previous.is_some_and(|value| request_type <= value) {
            bail!("execution request types must be unique and strictly ordered");
        }
        previous = Some(request_type);
    }
    Ok(())
}

pub fn proposal_randao(chain_id: U256, height: u64, previous_app_hash: &[u8]) -> B256 {
    let mut bytes = Vec::with_capacity(27 + 32 + 8 + previous_app_hash.len());
    bytes.extend_from_slice(b"ETHBFT_PREVRANDAO_V2");
    bytes.extend_from_slice(&chain_id.to_be_bytes::<32>());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(previous_app_hash);
    keccak256(bytes)
}

pub fn proposal_beacon_root(height: u64, previous_app_hash: &[u8]) -> B256 {
    let mut bytes = Vec::with_capacity(25 + 8 + previous_app_hash.len());
    bytes.extend_from_slice(b"ETHBFT_BEACON_ROOT_V2");
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(previous_app_hash);
    keccak256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> ExecutionEnvelope {
        let mut envelope = ExecutionEnvelope {
            engine_api: EngineApiVersion::V2,
            chain_id: U256::from(1337),
            consensus_height: 1,
            previous_app_hash: Bytes::new(),
            payload: ExecutionPayload::V2(ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    parent_hash: B256::repeat_byte(1),
                    fee_recipient: Address::ZERO,
                    state_root: B256::repeat_byte(2),
                    receipts_root: B256::repeat_byte(3),
                    logs_bloom: Bloom::ZERO,
                    prev_randao: B256::repeat_byte(4),
                    block_number: 1,
                    gas_limit: 30_000_000,
                    gas_used: 0,
                    timestamp: 1,
                    extra_data: Bytes::new(),
                    base_fee_per_gas: U256::from(7),
                    block_hash: B256::ZERO,
                    transactions: vec![],
                },
                withdrawals: vec![],
            }),
            parent_beacon_block_root: None,
            versioned_hashes: vec![],
            execution_requests: vec![],
        };
        let block = envelope
            .execution_data()
            .unwrap()
            .try_into_block::<TxEnvelope>()
            .unwrap();
        envelope.payload.as_v1_mut().block_hash =
            alloy_consensus::Sealable::hash_slow(&block.header);
        envelope
    }

    fn post_shanghai_envelope(version: EngineApiVersion) -> ExecutionEnvelope {
        let mut envelope = envelope();
        let ExecutionPayload::V2(payload) = envelope.payload else {
            unreachable!()
        };
        envelope.engine_api = version;
        envelope.payload = ExecutionPayload::V3(ExecutionPayloadV3 {
            payload_inner: payload,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        });
        envelope.parent_beacon_block_root = Some(B256::repeat_byte(5));
        if version == EngineApiVersion::V4 {
            envelope.execution_requests = vec![Bytes::from_static(&[0, 1])];
        }
        let block = envelope
            .execution_data()
            .unwrap()
            .try_into_block::<TxEnvelope>()
            .unwrap();
        envelope.payload.as_v1_mut().block_hash =
            alloy_consensus::Sealable::hash_slow(&block.header);
        envelope
    }

    #[test]
    fn envelope_round_trip_is_canonical() {
        let expected = envelope();
        let encoded = encode_envelope(&expected).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.engine_api, expected.engine_api);
        assert_eq!(decoded.block_hash(), expected.block_hash());
        assert_eq!(encode_envelope(&decoded).unwrap(), encoded);
    }

    #[test]
    fn cancun_and_prague_envelopes_round_trip() {
        for version in [EngineApiVersion::V3, EngineApiVersion::V4] {
            let expected = post_shanghai_envelope(version);
            let encoded = encode_envelope(&expected).unwrap();
            let decoded = decode_envelope(&encoded).unwrap();
            assert_eq!(decoded.engine_api, version);
            assert_eq!(decoded.block_hash(), expected.block_hash());
            assert_eq!(decoded.execution_requests, expected.execution_requests);
            assert_eq!(encode_envelope(&decoded).unwrap(), encoded);
        }
    }

    #[test]
    fn envelope_rejects_trailing_bytes() {
        let mut encoded = encode_envelope(&envelope()).unwrap().to_vec();
        encoded.push(0);
        assert!(decode_envelope(&encoded).is_err());
    }

    #[test]
    fn request_types_must_be_strictly_ordered() {
        assert!(
            validate_requests(&[Bytes::from_static(&[1, 2]), Bytes::from_static(&[1, 3]),])
                .is_err()
        );
    }

    #[test]
    fn deterministic_header_inputs_are_stable() {
        assert_eq!(
            proposal_randao(U256::from(1), 2, &[3; 32]),
            proposal_randao(U256::from(1), 2, &[3; 32])
        );
        assert_eq!(
            proposal_beacon_root(2, &[3; 32]),
            proposal_beacon_root(2, &[3; 32])
        );
    }
}
