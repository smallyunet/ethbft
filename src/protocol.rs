use alloy_consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope};
use alloy_eips::{eip4895::Withdrawal, Decodable2718, Typed2718};
use alloy_primitives::{keccak256, Address, Bloom, Bytes, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2};
use anyhow::{bail, Context};

pub const VERSION_V1: u64 = 1;
pub const ENGINE_API_V2: u64 = 2;
pub const MAX_ENVELOPE_LEN: usize = 128 * 1024;
pub const ENVELOPE_PREFIX: &[u8; 8] = b"ETHBFT\0\x01";

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct WithdrawalRlp {
    pub index: u64,
    pub validator_index: u64,
    pub address: Address,
    pub amount: u64,
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
pub struct ExecutionMetadataV1 {
    pub protocol_version: u64,
    pub engine_api_version: u64,
    pub chain_id: U256,
    pub consensus_height: u64,
    pub previous_app_hash: Bytes,
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bytes,
    pub prev_randao: B256,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub base_fee: U256,
    pub block_hash: B256,
    pub withdrawals: Vec<WithdrawalRlp>,
}

impl ExecutionMetadataV1 {
    pub fn from_payload(
        chain_id: U256,
        height: u64,
        previous_app_hash: &[u8],
        payload: &ExecutionPayloadV2,
    ) -> anyhow::Result<Self> {
        if chain_id.is_zero() || height == 0 {
            bail!("chain ID and consensus height must be positive");
        }
        let p = &payload.payload_inner;
        let metadata = Self {
            protocol_version: VERSION_V1,
            engine_api_version: ENGINE_API_V2,
            chain_id,
            consensus_height: height,
            previous_app_hash: Bytes::copy_from_slice(previous_app_hash),
            parent_hash: p.parent_hash,
            fee_recipient: p.fee_recipient,
            state_root: p.state_root,
            receipts_root: p.receipts_root,
            logs_bloom: Bytes::copy_from_slice(p.logs_bloom.as_slice()),
            prev_randao: p.prev_randao,
            block_number: p.block_number,
            gas_limit: p.gas_limit,
            gas_used: p.gas_used,
            timestamp: p.timestamp,
            extra_data: p.extra_data.clone(),
            base_fee: p.base_fee_per_gas,
            block_hash: p.block_hash,
            withdrawals: payload
                .withdrawals
                .iter()
                .map(WithdrawalRlp::from)
                .collect(),
        };
        metadata.validate_basic()?;
        Ok(metadata)
    }

    pub fn payload(&self, transactions: &[Bytes]) -> anyhow::Result<ExecutionPayloadV2> {
        self.validate_basic()?;
        let logs_bloom = Bloom::from_slice(&self.logs_bloom);
        Ok(ExecutionPayloadV2 {
            payload_inner: ExecutionPayloadV1 {
                parent_hash: self.parent_hash,
                fee_recipient: self.fee_recipient,
                state_root: self.state_root,
                receipts_root: self.receipts_root,
                logs_bloom,
                prev_randao: self.prev_randao,
                block_number: self.block_number,
                gas_limit: self.gas_limit,
                gas_used: self.gas_used,
                timestamp: self.timestamp,
                extra_data: self.extra_data.clone(),
                base_fee_per_gas: self.base_fee,
                block_hash: self.block_hash,
                transactions: transactions.to_vec(),
            },
            withdrawals: self
                .withdrawals
                .clone()
                .into_iter()
                .map(Withdrawal::from)
                .collect(),
        })
    }

    pub fn validate_basic(&self) -> anyhow::Result<()> {
        if self.protocol_version != VERSION_V1 {
            bail!("unsupported protocol version {}", self.protocol_version);
        }
        if self.engine_api_version != ENGINE_API_V2 {
            bail!("unsupported Engine API version {}", self.engine_api_version);
        }
        if self.chain_id.is_zero() || self.consensus_height == 0 {
            bail!("invalid chain ID or consensus height");
        }
        if !self.previous_app_hash.is_empty() && self.previous_app_hash.len() != 32 {
            bail!("previous app hash must be empty or 32 bytes");
        }
        if self.logs_bloom.len() != 256 {
            bail!("logs bloom must be 256 bytes");
        }
        if self.extra_data.len() > 32 {
            bail!("extra data exceeds 32 bytes");
        }
        if self.block_hash.is_zero() {
            bail!("execution block hash must not be zero");
        }
        if !self.withdrawals.is_empty() {
            bail!("protocol v1 requires empty withdrawals");
        }
        Ok(())
    }
}

pub fn encode_envelope(metadata: &ExecutionMetadataV1) -> anyhow::Result<Bytes> {
    metadata.validate_basic()?;
    let body = alloy_rlp::encode(metadata);
    if body.len() + ENVELOPE_PREFIX.len() > MAX_ENVELOPE_LEN {
        bail!("execution envelope exceeds {MAX_ENVELOPE_LEN} bytes");
    }
    let mut out = Vec::with_capacity(ENVELOPE_PREFIX.len() + body.len());
    out.extend_from_slice(ENVELOPE_PREFIX);
    out.extend_from_slice(&body);
    Ok(out.into())
}

pub fn decode_envelope(raw: &[u8]) -> anyhow::Result<ExecutionMetadataV1> {
    if !is_envelope(raw) {
        bail!("missing EthBFT execution envelope prefix");
    }
    if raw.len() > MAX_ENVELOPE_LEN {
        bail!("execution envelope exceeds {MAX_ENVELOPE_LEN} bytes");
    }
    let body = &raw[ENVELOPE_PREFIX.len()..];
    let mut cursor = body;
    let metadata = ExecutionMetadataV1::decode(&mut cursor).context("decode execution metadata")?;
    if !cursor.is_empty() {
        bail!("trailing execution metadata bytes");
    }
    metadata.validate_basic()?;
    if alloy_rlp::encode(&metadata).as_slice() != body {
        bail!("non-canonical execution metadata encoding");
    }
    Ok(metadata)
}

pub fn is_envelope(raw: &[u8]) -> bool {
    raw.starts_with(ENVELOPE_PREFIX)
}

pub fn decode_transaction(raw: &[u8], chain_id: U256) -> anyhow::Result<TxEnvelope> {
    if raw.len() > MAX_ENVELOPE_LEN {
        bail!("transaction exceeds 128 KiB");
    }
    if is_envelope(raw) {
        bail!("reserved EthBFT execution envelope");
    }
    let tx = TxEnvelope::decode_2718_exact(raw).context("invalid transaction encoding")?;
    let tx_chain = tx
        .chain_id()
        .context("unprotected transactions are not supported")?;
    if U256::from(tx_chain) != chain_id {
        bail!("wrong chain ID: got {tx_chain}, want {chain_id}");
    }
    if tx.ty() > 2 {
        bail!(
            "transaction type {} is not supported by Engine API V2",
            tx.ty()
        );
    }
    tx.recover_signer()
        .context("invalid transaction signature")?;
    Ok(tx)
}

pub fn transaction_hash(raw: &[u8]) -> anyhow::Result<B256> {
    let tx = TxEnvelope::decode_2718_exact(raw).context("invalid transaction encoding")?;
    Ok(*tx.tx_hash())
}

pub fn validate_payload_hash(payload: &ExecutionPayloadV2) -> anyhow::Result<B256> {
    let expected = payload.payload_inner.block_hash;
    let block = payload
        .clone()
        .try_into_block::<TxEnvelope>()
        .context("reconstruct execution block")?;
    let actual = alloy_consensus::Sealable::hash_slow(&block.header);
    if actual != expected {
        bail!("execution block hash mismatch: computed {actual}, proposed {expected}");
    }
    Ok(block.header.transactions_root)
}

pub fn proposal_randao(chain_id: U256, height: u64, previous_app_hash: &[u8]) -> B256 {
    let mut bytes = Vec::with_capacity(27 + 32 + 8 + previous_app_hash.len());
    bytes.extend_from_slice(b"ETHBFT_PREVRANDAO_V1");
    bytes.extend_from_slice(&chain_id.to_be_bytes::<32>());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(previous_app_hash);
    keccak256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> ExecutionMetadataV1 {
        ExecutionMetadataV1 {
            protocol_version: 1,
            engine_api_version: 2,
            chain_id: U256::from(1337),
            consensus_height: 1,
            previous_app_hash: Bytes::new(),
            parent_hash: B256::repeat_byte(1),
            fee_recipient: Address::ZERO,
            state_root: B256::repeat_byte(2),
            receipts_root: B256::repeat_byte(3),
            logs_bloom: Bytes::from(vec![0; 256]),
            prev_randao: B256::repeat_byte(4),
            block_number: 1,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1,
            extra_data: Bytes::new(),
            base_fee: U256::from(7),
            block_hash: B256::repeat_byte(5),
            withdrawals: vec![],
        }
    }

    #[test]
    fn envelope_round_trip_is_canonical() {
        let expected = metadata();
        let encoded = encode_envelope(&expected).unwrap();
        assert_eq!(decode_envelope(&encoded).unwrap(), expected);
        assert_eq!(
            hex::encode(encoded),
            "4554484246540001f901cf01028205390180a00101010101010101010101010101010101010101010101010101010101010101940000000000000000000000000000000000000000a00202020202020202020202020202020202020202020202020202020202020202a00303030303030303030303030303030303030303030303030303030303030303b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00404040404040404040404040404040404040404040404040404040404040404018401c9c38080018007a00505050505050505050505050505050505050505050505050505050505050505c0"
        );
    }

    #[test]
    fn envelope_rejects_trailing_bytes() {
        let mut encoded = encode_envelope(&metadata()).unwrap().to_vec();
        encoded.push(0);
        assert!(decode_envelope(&encoded).is_err());
    }

    #[test]
    fn randao_is_deterministic() {
        assert_eq!(
            proposal_randao(U256::from(1), 2, &[3; 32]),
            proposal_randao(U256::from(1), 2, &[3; 32])
        );
    }
}
