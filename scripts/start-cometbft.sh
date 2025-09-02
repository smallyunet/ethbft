#!/bin/sh
set -e

# Check and create necessary directories
mkdir -p /cometbft/config /cometbft/data

# Initialize CometBFT if any required file is missing
if [ ! -f /cometbft/config/genesis.json ] || \
  [ ! -f /cometbft/config/config.toml ] || \
  [ ! -f /cometbft/config/node_key.json ] || \
  [ ! -f /cometbft/config/priv_validator_key.json ]; then
  echo "Initializing or reinitializing CometBFT environment..."
  cometbft init --home=/cometbft
fi

# Update configuration
if [ -f /cometbft/config/config.toml ]; then
  # Define the replacements
  sed -i 's|proxy_app = "tcp://127.0.0.1:26658"|proxy_app = "grpc://ethbft:8080"|g' /cometbft/config/config.toml
  sed -i 's|laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|g' /cometbft/config/config.toml
  sed -i 's|cors_allowed_origins = \[\]|cors_allowed_origins = ["*"]|g' /cometbft/config/config.toml
  sed -i 's|addr_book_strict = true|addr_book_strict = false|g' /cometbft/config/config.toml
  
  echo "CometBFT configuration updated"
else
  echo "Error: config.toml still does not exist after initialization"
  exit 1
fi

echo "All necessary files are ready, starting CometBFT..."

# Start CometBFT
exec cometbft start \
  --home=/cometbft \
  --log_level=debug \
  --abci=socket \
  --proxy_app=tcp://ethbft:8080 \
  --rpc.laddr=tcp://0.0.0.0:26657 \
  --p2p.laddr=tcp://0.0.0.0:26656
