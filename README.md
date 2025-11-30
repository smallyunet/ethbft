# EthBFT - Ethereum ↔ CometBFT Minimal Bridge

EthBFT is an experimental, lightweight bridge that drives an Ethereum Execution Layer (EL) client (e.g. Geth) using CometBFT block heights as a timing/advancement signal. It focuses on the **Engine API orchestration loop** (forkchoice + payload production) rather than full state / transaction integration. For every new CometBFT height, EthBFT requests the EL to build (currently empty) blocks and advances forkchoice accordingly.

> Status: Proof‑of‑concept / demo. ABCI logic is minimal, blocks produced by Geth are empty, and no transaction translation is performed yet. Expect breaking changes.

## 🚀 Features (Current Scope)

- **Engine API Loop**: Implements the minimal sequence: forkchoiceUpdated → getPayload → newPayload → forkchoiceUpdated (final) per CometBFT height.
- **Height Tracking**: Maintains mapping of CometBFT height → EL head hash to choose parents.
- **ABCI Skeleton**: Implements required ABCI methods with no transaction execution (returns OK for all txs).
- **Dynamic Parent Selection**: Falls back to EL latest head or genesis if internal map has no parent yet.
- **JWT (HS256) Auth**: Automatically signs Engine API calls when a JWT secret is provided.
- **Health Endpoint**: HTTP `/health` (port 8081) plus ABCI socket (8080).
- **Docker Stack**: One‑command demo bringing up Geth + EthBFT + CometBFT.
- **Config Flag**: `bridge.enableBridging` toggles the block production loop.

### Not (Yet) Implemented
- Transaction ingestion / translation between CometBFT and EL
- Execution payload construction from CometBFT data (legacy helpers retained but unused)
- Safe / finalized head derivation beyond setting all three to the produced head
- State proofs, validator set management, or multi‑node orchestration

## 📁 Project Structure

```
ethbft/
├── cmd/
│   └── ethbft/             # Main application entry point
├── pkg/
│   ├── bridge/             # Bridge between CometBFT height and Engine API block production
│   │   ├── bridge.go       # Engine API orchestration & height loop
│   │   ├── server.go       # ABCI server + health HTTP server
│   │   └── types.go        # Aliases of go-ethereum Engine API types
│   ├── config/            # Configuration management
│   ├── consensus/          # CometBFT client integration
│   └── ethereum/           # Ethereum client integration
├── config/                 # Configuration files
├── scripts/                # Utility scripts
├── docker-compose.yml      # Docker orchestration
├── Dockerfile             # Container definition
├── Makefile               # Build and development commands
├── go.mod                 # Go module definition
└── README.md              # This file
```

## 🛠️ Prerequisites

- Go 1.24+ (tested with 1.24.x)
- Docker & Docker Compose (recommended path)
- OpenSSL (for JWT secret generation) or any tool that can produce 32 random bytes hex

Optional (manual run): a locally running Geth with Engine API (authrpc) enabled, and a CometBFT node.

## ⚡ Quick Start

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/smallyunet/ethbft.git
cd ethbft

# Start the complete stack (Geth + CometBFT + EthBFT + Explorer + Monitoring)
make deploy

# View logs
docker-compose logs -f

# Stop all containers
make docker-down

# Rebuild and restart
make docker-rebuild
```

### Access Points

After running `make deploy`, the following services are available:

- **Block Explorer (Alethio)**: [http://localhost:5100](http://localhost:5100)
- **Monitoring (Grafana)**: [http://localhost:3000](http://localhost:3000) (User: `admin`, Pass: `admin`)
- **Prometheus**: [http://localhost:19090](http://localhost:19090)
- **Geth RPC**: [http://localhost:8545](http://localhost:8545)
- **CometBFT RPC**: [http://localhost:26657](http://localhost:26657)

### Manual Setup (Without Docker)

You need three processes: Geth (execution), EthBFT (bridge), CometBFT (consensus). Example outline (simplified, adjust for your environment):

```bash
# 1. Start Geth with Engine API enabled (example minimal flags)
geth \
  --networkid=1337 --nodiscover --http --http.addr=0.0.0.0 --http.api=eth,net,web3,txpool \
  --authrpc.addr=0.0.0.0 --authrpc.port=8551 --authrpc.jwtsecret=./jwt.hex --authrpc.vhosts=* \
  --gcmode=archive --syncmode=full --datadir=./geth_data

# 2. Start (or initialize) a CometBFT node (ensure it listens on 26657 HTTP)
#    Using existing home dir in ./cometbft_home (already included for demo)
cometbft start --home ./cometbft_home

# 3. Run EthBFT
ETHBFT_CONFIG=./config.yaml ./ethbft
```

Full dev bootstrap with repository helpers:

```bash
# Clone and setup
git clone https://github.com/smallyunet/ethbft.git
cd ethbft

# Install dependencies
make deps

# Generate JWT secret
make generate-jwt

# Create genesis file
make create-genesis

# Build the application
make build

# Run the bridge
make run
```

## 🔧 Configuration

EthBFT loads `config.yaml` (or the path in `ETHBFT_CONFIG`). Environment variables may rewrite hostnames for container contexts.

### Example Configuration (`config.yaml`)

```yaml
ethereum:
  endpoint: "http://localhost:8545"     # JSON-RPC endpoint used for non-engine calls
  engineAPI: "http://localhost:8551"     # Auth RPC (Engine API) endpoint
  jwtSecret: "./jwt.hex"                 # Hex file (>= 32 bytes) used for HS256 JWT

cometbft:
  endpoint: "http://localhost:26657"     # HTTP endpoint exposed by CometBFT RPC
  homeDir: "./cometbft_home"

bridge:
  listenAddr: "0.0.0.0:8080"            # ABCI socket address
  logLevel: "info"
  enableBridging: true                   # If false: ABCI server only, no EL block production
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `ETHBFT_CONFIG` | Path to config file (defaults to `./config.yaml`). |
| `ETHEREUM_HOST` | Replaces `localhost` part of `ethereum.endpoint` & `ethereum.engineAPI` (used in Docker). |
| `COMETBFT_HOST` | Replaces `localhost` in `cometbft.endpoint`. |

Example:
```bash
ETHEREUM_HOST=geth COMETBFT_HOST=cometbft ETHBFT_CONFIG=./config/docker-config.yaml ./ethbft
```

## 🏗️ Architecture & Flow

High‑level data/control flow (current minimal mode):

```
CometBFT (height increment) ---> EthBFT loop ---> Engine API (Geth) builds empty block
         ^                         |                       |
         |                         | 1) forkchoiceUpdated  |
         |                         | 2) getPayload         |
         |                         | 3) newPayload         v
         +-------------------------+ 4) forkchoiceUpdated (final head)
```

Key behaviors:
1. Poll CometBFT `status` every 2s; detect new `latest_block_height`.
2. For each new height H: pick parent hash (cached prior EL head or fallback) and run Engine API sequence.
3. Set head/safe/finalized all to the newly produced block hash (demo simplification).
4. Cache (H → headHash) for next iteration.

Legacy helpers exist for building synthetic payloads from CometBFT block data but are not used in the current flow.

## 🐳 Docker Services

Compose brings up three services:

| Service | Purpose | Notes |
|---------|---------|-------|
| `ethbft-geth` | Geth execution client | Exposes HTTP (8545), WS (8546), Auth (8551) locally. |
| `ethbft-app`  | EthBFT bridge | Uses mounted `jwt.hex` and `docker-config.yaml`. |
| `ethbft-cometbft` | CometBFT node | ABCI connects to EthBFT on 8080. |

### Ports

| Port | Service | Description |
|------|---------|-------------|
| 8545 | geth | HTTP JSON-RPC |
| 8546 | geth | WebSocket RPC |
| 8551 | geth | Engine API (authrpc) |
| 8080 | ethbft | ABCI socket |
| 8081 | ethbft | Health check `/health` |
| 26656 | cometbft | P2P |
| 26657 | cometbft | RPC |

## 📊 Monitoring & Ops

### Health Check

```bash
# Check bridge health
curl http://localhost:8081/health

# Check CometBFT status
curl http://localhost:26657/status

# Check Geth status
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://localhost:8545
```

### Logs

```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f ethbft-app
docker-compose logs -f ethbft-cometbft
docker-compose logs -f ethbft-geth
```

## 🛠️ Development

### Available Make Targets

```bash
# Build the application
make build

# Run tests
make test

# Clean build artifacts
make clean

# Generate JWT secret
make generate-jwt

# Create genesis file
make create-genesis

# Setup development environment
make dev-setup

# Docker operations
make docker-up
make docker-down
make docker-rebuild
```

### Building from Source

```bash
# Build for current platform
go build -o ethbft ./cmd/ethbft

# Build for Linux (Docker)
CGO_ENABLED=0 GOOS=linux go build -o ethbft ./cmd/ethbft
```

## 🔍 Troubleshooting

### Common Issues

1. **JWT Authentication Failed**
   ```bash
   # Regenerate JWT secret
   make generate-jwt
   make docker-rebuild
   ```

2. **CometBFT Connection Issues**
   ```bash
   # Check CometBFT logs
   docker-compose logs cometbft
   
   # Restart services
   make docker-rebuild
   ```

3. **Port Conflicts**
  ```bash
  lsof -nP -iTCP:8080 -sTCP:LISTEN
  # Edit docker-compose.yml or config.yaml to adjust.
  ```

4. **No Blocks Produced**
  - Ensure `enableBridging: true`.
  - Verify Engine API reachable: curl localhost:8551 (expect method not allowed / JSON error, not connection refused).
  - Check JWT secret matches the one Geth was launched with.

5. **Forkchoice Errors in Logs**
  - Usually due to invalid parent hash (EL not ready). Wait until Geth has at least one head block, then EthBFT will retry at next poll.

6. **CometBFT Endpoint Scheme**
  - EthBFT expects an HTTP-accessible RPC endpoint (e.g., `http://localhost:26657`). Update `config.yaml` if CometBFT is bound elsewhere.

## 🔐 Security Notes

- Do NOT expose the Engine API (authrpc / 8551) to untrusted networks.
- Current demo runs all components on a single host; multi‑validator / multi‑EL safety not considered.
- JWT tokens are short‑lived (60s) and regenerated per Engine API call.

## 📝 License

MIT (see `LICENSE` if present or to be added).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📚 References

- CometBFT Docs: https://docs.cometbft.com/
- Ethereum Execution / Engine API: https://github.com/ethereum/execution-apis
- ABCI Spec (v0.38): https://docs.cometbft.com/v0.38/spec/abci/
- go-ethereum Engine Types: https://github.com/ethereum/go-ethereum/tree/master/beacon/engine

---

### Future Work (Roadmap Ideas)
- Map CometBFT transactions into valid Ethereum transactions (RLP encoded) & submit via payload attributes.
- Derive safe/finalized heads using height windows instead of equating all to head.
- Multi‑node coordination / validator set syncing.
- Metrics endpoint (Prometheus) and structured logging.
- Pluggable transaction pool abstraction.

Feedback & PRs welcome.
