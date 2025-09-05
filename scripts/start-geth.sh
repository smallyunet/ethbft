#!/bin/sh
set -e

# Simple entrypoint that ensures geth is initialized with a genesis file
# before starting with the provided arguments.

DATADIR=${DATADIR:-/root/.ethereum}
GENESIS=${GENESIS:-/genesis.json}

if [ -f "$GENESIS" ]; then
  if [ ! -d "$DATADIR/geth/chaindata" ] || [ -z "$(ls -A "$DATADIR/geth/chaindata" 2>/dev/null || true)" ]; then
    echo "[start-geth] Initializing geth datadir with genesis: $GENESIS"
    geth init --datadir "$DATADIR" "$GENESIS"
  else
    echo "[start-geth] Datadir already initialized; skipping genesis init"
  fi
else
  echo "[start-geth] WARNING: Genesis file not found at $GENESIS; skipping init"
fi

echo "[start-geth] Geth version:" && geth version || true
if [ -f /jwt.hex ]; then
  echo "[start-geth] JWT file size: $(wc -c < /jwt.hex) bytes (expect 64)"
  head -c 64 /jwt.hex >/dev/null 2>&1 || true
else
  echo "[start-geth] WARNING: /jwt.hex not found inside container"
fi

echo "[start-geth] Starting geth with args: $*"
exec geth "$@"

