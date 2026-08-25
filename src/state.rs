use alloy_primitives::{Bytes, B256, U256};
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const STATE_VERSION: u64 = 5;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitIntent {
    pub height: u64,
    pub encoded_envelope: Bytes,
    pub app_hash: Bytes,
    pub block_hash: B256,
    pub engine_api_version: u64,
    #[serde(default)]
    pub forkchoice_applied: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedState {
    pub version: u64,
    pub protocol_version: u64,
    pub chain_id: U256,
    pub el_genesis: B256,
    pub protocol_fingerprint: B256,
    #[serde(default)]
    pub last_committed_height: u64,
    #[serde(default)]
    pub last_execution_hash: B256,
    #[serde(default)]
    pub last_app_hash: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_intent: Option<CommitIntent>,
}

impl PersistedState {
    pub fn new(chain_id: U256, el_genesis: B256, protocol_fingerprint: B256) -> Self {
        Self {
            version: STATE_VERSION,
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            chain_id,
            el_genesis,
            protocol_fingerprint,
            last_committed_height: 0,
            last_execution_hash: el_genesis,
            last_app_hash: Bytes::new(),
            commit_intent: None,
        }
    }

    pub fn validate(
        &self,
        chain_id: U256,
        el_genesis: B256,
        protocol_fingerprint: B256,
    ) -> anyhow::Result<()> {
        if self.version != STATE_VERSION
            || self.protocol_version != crate::protocol::PROTOCOL_VERSION
        {
            bail!(
                "state version {}/protocol {} is incompatible with protocol v2",
                self.version,
                self.protocol_version
            );
        }
        if self.chain_id != chain_id {
            bail!(
                "state chain ID {} does not match EL chain ID {}",
                self.chain_id,
                chain_id
            );
        }
        if self.el_genesis != el_genesis {
            bail!(
                "state EL genesis {} does not match {}",
                self.el_genesis,
                el_genesis
            );
        }
        if self.protocol_fingerprint != protocol_fingerprint {
            bail!("local protocol configuration does not match persisted network fingerprint");
        }
        if self.last_committed_height == 0 && self.last_execution_hash != el_genesis {
            bail!("fresh state execution head must equal EL genesis");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(
        &self,
        chain_id: U256,
        el_genesis: B256,
        protocol_fingerprint: B256,
    ) -> anyhow::Result<PersistedState> {
        if !self.path.exists() {
            return Ok(PersistedState::new(
                chain_id,
                el_genesis,
                protocol_fingerprint,
            ));
        }
        let bytes =
            fs::read(&self.path).with_context(|| format!("read state {}", self.path.display()))?;
        let state: PersistedState = serde_json::from_slice(&bytes)
            .with_context(|| format!("decode state {}", self.path.display()))?;
        state.validate(chain_id, el_genesis, protocol_fingerprint)?;
        Ok(state)
    }

    pub fn save(&self, state: &PersistedState) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(state).context("encode persisted state")?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .with_context(|| format!("open temporary state {}", temp.display()))?;
        file.write_all(&bytes).context("write temporary state")?;
        file.sync_all().context("fsync temporary state")?;
        drop(file);
        fs::rename(&temp, &self.path).context("atomically replace state")?;
        if let Some(parent) = self.path.parent() {
            if let Ok(directory) = File::open(normalize_parent(parent)) {
                directory.sync_all().context("fsync state directory")?;
            }
        }
        Ok(())
    }
}

fn normalize_parent(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path().join("state.json"));
        let fingerprint = B256::repeat_byte(9);
        let mut state = PersistedState::new(U256::from(1337), B256::repeat_byte(1), fingerprint);
        state.last_committed_height = 3;
        state.last_execution_hash = B256::repeat_byte(2);
        store.save(&state).unwrap();
        assert_eq!(
            store
                .load(state.chain_id, state.el_genesis, fingerprint)
                .unwrap()
                .last_committed_height,
            3
        );
    }

    #[test]
    fn wrong_protocol_fingerprint_fails_closed() {
        let state = PersistedState::new(U256::from(1), B256::repeat_byte(1), B256::repeat_byte(2));
        assert!(state
            .validate(U256::from(1), B256::repeat_byte(1), B256::repeat_byte(3))
            .is_err());
    }
}
