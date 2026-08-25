# EthBFT

EthBFT is a thin BFT consensus adapter for Ethereum Execution Layer clients.
CometBFT reaches consensus on complete Ethereum execution payloads, while each
validator uses an independent Geth Engine API to validate the proposed state
transition.

> **Status: v0.2.0 MVP.** The execution-payload consensus loop is implemented
> and covered by a single-validator Docker E2E test. The bundled Compose stack
> is a development network, not a production multi-validator deployment.

## What v0.2.0 Implements

- **Payload consensus:** the proposer places deterministic execution metadata
  and the exact ordered payload transactions in the CometBFT proposal.
- **Independent validation:** `ProcessProposal` reconstructs the payload,
  verifies its block hash and consensus fields, and requires the local EL to
  return `VALID` from `engine_newPayloadV2`.
- **Commit-after-consensus:** EL forkchoice advances only for a CometBFT-decided
  proposal. ABCI height and app hash become durable at `Commit`.
- **Execution commitment:** the ABCI app hash commits to the previous app hash,
  chain ID, consensus height, EL parent/block hashes, state root, receipts root,
  and transaction root.
- **Exact transaction order:** CometBFT proposal order is the order in the
  Ethereum execution payload.
- **Crash recovery:** a durable commit-intent journal bridges `FinalizeBlock`,
  EL forkchoice, and ABCI `Commit`; startup safely resumes interrupted commits
  and rejects incompatible legacy state.
- **Deterministic envelope:** protocol-v1 metadata uses canonical RLP with a
  reserved `ETHBFT\x00\x01` prefix.
- **Operations:** JSON logs, Prometheus metrics, liveness/readiness checks, and
  committed transaction lookup.

## MVP Scope and Limitations

Protocol v1 intentionally stays small:

- Engine API V2 and a Shanghai-only execution chain.
- Empty withdrawals and no blob transactions.
- One fixed fee recipient configured identically on every validator.
- Atomic, fsynced state-file and commit-intent persistence rather than a
  transactional database.
- No ABCI/EL snapshot state sync.
- No dynamic validator or protocol-parameter updates.
- No Ethereum-mainnet bridge, light-client proof, or asset custody protocol.
- The default Docker stack contains one CometBFT validator and one Geth.

The full target protocol and production acceptance criteria are described in
[RFC 0001](docs/rfc/0001-execution-payload-consensus.md).

## Consensus Flow

```text
Ethereum transactions
        |
        v
CometBFT proposer -- PrepareProposal --> dedicated Geth builder
        |                                  |
        |<-- metadata + ordered payload ---|
        |
        v
CometBFT proposal
        |
        +--> every validator reconstructs the payload
        +--> every validator calls engine_newPayloadV2
        +--> only VALID payloads receive consensus votes
        |
        v
CometBFT decision
        |
        +--> forkchoiceUpdatedV2(head = safe = finalized)
        +--> durable height -> EL block mapping
        +--> execution-committing ABCI app hash
```

The proposer may select and order valid transactions. Once included in the
execution payload, that exact membership and order is agreed by CometBFT.

## Quick Start

### Prerequisites

- Rust 1.91+
- Docker with Compose
- OpenSSL

### Start the development chain

```bash
git clone https://github.com/smallyunet/ethbft.git
cd ethbft
make deploy
```

When upgrading from v0.0.x, start a new chain because legacy app hashes did not
commit to Ethereum execution:

```bash
docker-compose down -v
rm -rf geth_data cometbft_home
make deploy
```

The removal command deletes the local development chain data. Do not use it for
a network whose state must be retained.

### Access points

| Endpoint | URL |
| --- | --- |
| Geth JSON-RPC | http://localhost:8545 |
| CometBFT RPC | http://localhost:26657 |
| EthBFT liveness | http://localhost:8081/live |
| EthBFT readiness | http://localhost:8081/health |
| Prometheus metrics | http://localhost:8081/metrics |
| Prometheus UI | http://localhost:19090 |
| Grafana | http://localhost:3000 |
| Explorer | http://localhost:5100 |

The default Grafana credentials are `admin` / `admin` and are suitable only for
local development.

### Observe the chain

```bash
docker-compose logs -f ethbft cometbft geth

curl http://localhost:8081/health

curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://localhost:8545
```

After a transaction is committed, query its consensus delivery record:

```bash
curl http://localhost:8081/tx/0xYOUR_ETHEREUM_TRANSACTION_HASH
```

`included` means the transaction belongs to a CometBFT-decided, EL-validated
execution payload. Mempool admission alone does not create a delivery record.

## Configuration

EthBFT loads `config.yaml` or the path in `ETHBFT_CONFIG`.

```yaml
ethereum:
  endpoint: "http://localhost:8545"
  engineAPI: "http://localhost:8551"
  jwtSecret: "./jwt.hex"

cometbft:
  endpoint: "http://localhost:26657"
  homeDir: "./cometbft_home"

bridge:
  listenAddr: "0.0.0.0:8080"
  healthAddr: "0.0.0.0:8081"
  stateFile: "ethbft_state.json"
  appVersion: "0.2.0"
  timeout: 10
  logLevel: "info"
  enableBridging: true
  feeRecipient: "0x0000000000000000000000000000000000000000"
```

Protocol v1 rejects non-zero local `safeDepth`, `finalizedDepth`, or
`finalityDepth`: CometBFT-decided EL blocks are finalized immediately. All
validators must use the same fee recipient, chain ID, genesis, and fork
schedule.

Environment overrides:

| Variable | Purpose |
| --- | --- |
| `ETHBFT_CONFIG` | Configuration file path. |
| `ETHEREUM_HOST` | Replaces the Ethereum RPC host for containers. |
| `COMETBFT_HOST` | Replaces the CometBFT RPC host for containers. |

## Manual Development

Run a Shanghai-enabled post-merge Geth with HTTP and authenticated Engine API,
then run CometBFT with its ABCI proxy pointing to EthBFT:

```bash
make generate-jwt
make create-genesis
make build

ETHBFT_CONFIG=./config/config.yaml ./ethbft

cometbft start \
  --home ./cometbft_home \
  --abci socket \
  --proxy_app tcp://127.0.0.1:8080
```

The Docker path is recommended because it initializes Geth and CometBFT in the
required order.

## Development and Verification

```bash
make test
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets

# Full Docker execution path
ETHBFT_E2E=1 cargo test --locked --test e2e -- --nocapture
```

CI runs formatting, Clippy, unit and integration tests, a release build, and the
Docker E2E test.

## Project Structure

```text
src/abci.rs          CometBFT ABCI++ v0.38 adapter
src/node.rs          consensus-neutral execution lifecycle
src/engine.rs        authenticated Ethereum Engine API transport
src/protocol.rs      versioned execution proposal encoding
src/state.rs         commit journal, persistence, and reconciliation
src/config.rs        local configuration
tests/e2e.rs         Docker execution-path test
docs/rfc/            consensus protocol specifications
```

## Security Boundary

- Each production validator must use an independent, dedicated EL.
- Engine API must remain private and JWT-authenticated.
- EthBFT must be the only forkchoice authority for its EL.
- Validator EL datadirs must never be shared.
- A validator whose EL returns `SYNCING`, `ACCEPTED`, times out, or diverges
  rejects the proposal and must be treated as not ready.
- v0.2.0 has not received an independent security audit.

## Docker Services

The development stack contains Geth, EthBFT, CometBFT, Prometheus, Grafana, and
the Alethio lite explorer. Host-facing ports bind to loopback by default. The
authenticated Engine API remains internal to the Compose network.

## License

MIT. See [LICENSE](LICENSE).
