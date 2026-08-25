#!/bin/sh
set -e

# Try to create directories if they don't exist
# In CI, these might already exist or we might not have permissions
mkdir -p /cometbft/config /cometbft/data 2>/dev/null || true

if [ ! -f /cometbft/config/genesis.json ] || \
  [ ! -f /cometbft/config/config.toml ] || \
  [ ! -f /cometbft/config/node_key.json ] || \
  [ ! -f /cometbft/config/priv_validator_key.json ]; then
  echo "Initializing or reinitializing CometBFT environment..."
  cometbft init --home=/cometbft
fi

# Execution transactions live in the EL txpool. CometBFT carries one payload
# envelope per block, produced through PrepareProposal, so its tx mempool and
# tx index are intentionally disabled.
sed -i 's/^type = "flood"$/type = "nop"/' /cometbft/config/config.toml
sed -i 's/^indexer = "kv"$/indexer = "null"/' /cometbft/config/config.toml

exec cometbft start \
  --home=/cometbft \
  --log_level=info \
  --abci=socket \
  --proxy_app=tcp://ethbft:8080 \
  --rpc.laddr=tcp://0.0.0.0:26657 \
  --p2p.laddr=tcp://0.0.0.0:26656
