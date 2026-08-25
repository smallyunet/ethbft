# EthBFT

EthBFT is a lightweight, client-neutral BFT consensus driver for Ethereum
Execution Layer clients. CometBFT orders one complete execution payload per
height; each validator independently validates that payload through the
standard authenticated Engine API.

> **Status: v0.3 alpha / pre-production.** Protocol v2 and the Rust runtime are
> implemented. Geth/Shanghai runs continuously in single-validator and
> four-validator fault-recovery tests, but the production acceptance gates have
> not passed.

## Design

```text
wallet / application
        |
        | eth_sendRawTransaction
        v
validator EL txpool  <---- EL P2P transaction gossip
        |
        | Engine API: build / validate / forkchoice
        v
      EthBFT  <------ ABCI++ ------>  CometBFT
   (thin adapter)                    (BFT ordering)
```

- No EthBFT transaction mempool, transaction gossip, receipt index, explorer,
  database, or embedded EVM.
- The proposer asks its EL to build a payload from the normal EL txpool.
- CometBFT decides one canonical RLP `ExecutionEnvelope`, including all raw
  transactions and fork-specific fields.
- Validators verify the envelope and accept only an Engine API `VALID` result.
- Forkchoice advances only after the BFT decision; an fsynced commit intent
  makes the `FinalizeBlock`/`Commit` boundary recoverable.
- Startup negotiates Engine API capabilities and fails closed when the
  configured Shanghai/Cancun/Prague method set is unavailable.

The core speaks the specification, not client-specific RPC extensions. Geth is
the reference integration today; Reth, Nethermind, Besu, and Erigon become
supported only after their compatibility suites pass continuously.

## Quick start

Requirements: Docker with Compose and OpenSSL. Rust is needed only for local
development.

```bash
git clone https://github.com/smallyunet/ethbft.git
cd ethbft
make deploy
```

Default endpoints:

| Service | Endpoint |
| --- | --- |
| Execution JSON-RPC | `http://localhost:8545` |
| CometBFT RPC | `http://localhost:26657` |
| Liveness | `http://localhost:8081/live` |
| Readiness | `http://localhost:8081/ready` |
| Runtime status | `http://localhost:8081/status` |
| Prometheus metrics | `http://localhost:8081/metrics` |

Optional monitoring is not started by default:

```bash
docker compose --profile observability up -d
```

Submit Ethereum transactions to the EL JSON-RPC endpoint, never to CometBFT:

```bash
curl -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x..."]}' \
  http://localhost:8545
```

## Configuration

EthBFT reads `config.yaml` or `ETHBFT_CONFIG`. All validators must use the same
`protocol` section, EL chain ID, and EL genesis.

```yaml
execution:
  endpoint: "http://localhost:8551"
  jwtSecret: "./jwt.hex"

cometbft:
  endpoint: "http://localhost:26657"

protocol:
  shanghaiTime: 0
  # cancunTime: 0
  # pragueTime: 0
  feeRecipient: "0x0000000000000000000000000000000000000000"
  maxPayloadBytes: 16777216

node:
  listenAddr: "0.0.0.0:8080"
  healthAddr: "0.0.0.0:8081"
  stateFile: "ethbft_state.json"
  timeout: 10
  maxConsensusLag: 5
  stallTimeout: 30
  logLevel: "info"
```

`EXECUTION_HOST` and `COMETBFT_HOST` replace endpoint hosts for containerized
deployments. `ETHEREUM_HOST` remains a deprecated alias for
`EXECUTION_HOST`.

## Version and migration boundary

Protocol v2 is deliberately incompatible with protocol v1 and state format 4.
Do not point v0.3 at an existing v0.2 chain or state file. For the disposable
Compose network, stop it and remove its data before migrating:

```bash
docker compose down -v
# This destroys only the local development network data.
rm -rf geth_data cometbft_home
make deploy
```

Production networks require an explicit genesis/state migration procedure;
none is supplied by this alpha.

## Production acceptance gates

The architecture is intended for production, but this repository must remain
labelled pre-production until all of these are evidenced:

- multi-validator Byzantine, restart, network-partition, and crash-recovery
  tests;
- Hive-style Engine API conformance plus continuous Geth, Reth, Nethermind,
  Besu, and Erigon matrices for every enabled fork;
- snapshot/state-sync or an operational validator replacement procedure;
- validator-set and protocol-upgrade governance;
- sustained load, payload-size, latency, disk, and memory benchmarks;
- threat model, independent security audit, incident runbooks, and reproducible
  signed releases.

See [RFC 0002](docs/rfc/0002-lightweight-client-neutral-protocol.md), the
[compatibility policy](docs/compatibility.md), and the
[production checklist](docs/production-readiness.md).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
ETHBFT_E2E=1 cargo test --locked --test e2e -- --nocapture
ETHBFT_MULTINODE_E2E=1 cargo test --locked --test multinode_e2e -- --nocapture
```

Rust 1.91 is the minimum supported version. Engine API is private,
JWT-authenticated, and must have exactly one forkchoice authority. Each
validator must operate an independent EL and datadir.

## Consensus backend

CometBFT v0.38 remains the production-track backend because it is mature and
ABCI++ matches the adapter lifecycle. The Rust core is isolated behind
`ConsensusApplication`, so a Malachite transport can be added later. Malachite
and Arc integrations are currently experimental/not implemented and are not
part of the compatibility claim.

Licensed under MIT.
