# Getting Started

## 🛠️ Prerequisites

- **Rust 1.91+**
- **Docker & Docker Compose** (recommended path)
- **OpenSSL** (for JWT secret generation)

## ⚡ Quick Start

### Using Docker (Recommended)

The easiest way to get started is using the provided Docker Compose stack.

```bash
# Clone the repository
git clone https://github.com/smallyunet/ethbft.git
cd ethbft

# Start the complete stack
make deploy

# View logs
docker-compose logs -f
```

If the machine previously ran v0.0.x, delete the disposable development-chain
state before starting v0.2.0:

```bash
docker-compose down -v
rm -rf geth_data cometbft_home
```

This deliberately destroys the local development chain because v0.0.x app
hashes did not commit to Ethereum execution.

### Access Points

After running `make deploy`, the following services are available:

- **Block Explorer (Alethio)**: [http://localhost:5100](http://localhost:5100)
- **Monitoring (Grafana)**: [http://localhost:3000](http://localhost:3000) (User: `admin`, Pass: `admin`)
- **Prometheus**: [http://localhost:19090](http://localhost:19090)
- **Geth RPC**: [http://localhost:8545](http://localhost:8545)
- **CometBFT RPC**: [http://localhost:26657](http://localhost:26657)

## Manual Setup (Without Docker)

You need three processes: Geth (execution), EthBFT (ABCI/Engine adapter), and
CometBFT (consensus).

```bash
# 1. Start Geth with Engine API enabled
geth \
  --networkid=1337 --nodiscover --http --http.addr=0.0.0.0 --http.api=eth,net,web3,txpool \
  --authrpc.addr=0.0.0.0 --authrpc.port=8551 --authrpc.jwtsecret=./jwt.hex --authrpc.vhosts=* \
  --gcmode=archive --syncmode=full --datadir=./geth_data

# 2. Start CometBFT node
cometbft start --home ./cometbft_home

# 3. Run EthBFT
ETHBFT_CONFIG=./config/config.yaml ./ethbft
```

The bundled configuration supports Engine API V2 on a Shanghai-only chain.
Blob transactions and later Engine API versions are rejected in protocol v1.
