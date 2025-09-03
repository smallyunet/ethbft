#!/bin/sh
set -e

mkdir -p /cometbft/config /cometbft/data

if [ ! -f /cometbft/config/genesis.json ] || \
  [ ! -f /cometbft/config/config.toml ] || \
  [ ! -f /cometbft/config/node_key.json ] || \
  [ ! -f /cometbft/config/priv_validator_key.json ]; then
  echo "Initializing or reinitializing CometBFT environment..."
  cometbft init --home=/cometbft
fi

exec cometbft start \
  --home=/cometbft \
  --log_level=debug \
  --abci=socket \
  --proxy_app=tcp://ethbft:8080 \
  --rpc.laddr=tcp://0.0.0.0:26657 \
  --p2p.laddr=tcp://0.0.0.0:26656
