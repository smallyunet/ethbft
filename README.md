# EthBFT - Ethereum to CometBFT Bridge

EthBFT is a lightweight bridge that connects Ethereum execution clients (like Geth) with CometBFT consensus. This project enables you to run a blockchain system using Ethereum's execution capabilities with CometBFT's fast and secure consensus mechanism.

## 🚀 Features

- **ABCI Application**: Full CometBFT ABCI interface implementation
- **Engine API Client**: Connects to Ethereum Engine API as a client
- **Health Monitoring**: Built-in connection monitoring and health checks
- **Docker Support**: Complete containerized deployment
- **JWT Authentication**: Secure Engine API communication
- **Lightweight**: Minimal dependencies, focused on core functionality

## 📁 Project Structure

```
ethbft/
├── cmd/
│   └── ethbft/             # Main application entry point
├── pkg/
│   ├── bridge/             # Bridge between Ethereum and CometBFT
│   │   ├── bridge.go      # Main bridge logic
│   │   └── server.go       # ABCI server implementation
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

- **Go 1.24+** (recommended: Go 1.24.6)
- **Docker & Docker Compose** (for containerized deployment)
- **OpenSSL** (for JWT secret generation)

## ⚡ Quick Start

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/smallyunet/ethbft.git
cd ethbft

# Start the complete stack (Geth + CometBFT + EthBFT)
make docker-up

# View logs
docker-compose logs -f

# Stop all containers
make docker-down

# Rebuild and restart
make docker-rebuild
```

### Manual Setup

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

EthBFT uses YAML configuration files. Key configuration options:

### Main Configuration (`config.yaml`)

```yaml
ethereum:
  endpoint: "http://localhost:8545"
  engineAPI: "http://localhost:8551"
  jwtSecret: "./jwt.hex"

cometbft:
  endpoint: "http://localhost:26657"

bridge:
  listenAddr: "0.0.0.0:8080"
  retryInterval: 30
```

### Environment Variables

```bash
# Set custom config path
ETHBFT_CONFIG=/path/to/config.yaml ./ethbft
```

## 🏗️ Architecture

EthBFT acts as a bridge layer between Ethereum execution clients and CometBFT consensus:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    Geth     │◄──►│   EthBFT    │◄──►│  CometBFT   │
│ (Execution)  │    │  (Bridge)   │    │ (Consensus) │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Components

1. **ABCI Application**: Implements CometBFT's ABCI interface
2. **Engine API Client**: Connects to Geth's Engine API as a client
3. **Bridge Logic**: Manages connections and data flow
4. **Health Monitoring**: Monitors service connectivity

## 🐳 Docker Services

The Docker setup includes:

- **ethbft-geth**: Ethereum execution client (Geth)
- **ethbft-app**: EthBFT bridge application
- **ethbft-cometbft**: CometBFT consensus node

### Ports

- `8545`: Geth HTTP RPC
- `8546`: Geth WebSocket RPC
- `8551`: Geth Engine API
- `8080`: ABCI socket server
- `8081`: Health check endpoint
- `26656`: CometBFT P2P
- `26657`: CometBFT RPC

## 📊 Monitoring

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

### Available Commands

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
   # Check port usage
   netstat -tulpn | grep :8080
   
   # Modify ports in docker-compose.yml
   ```

## 📝 License

[MIT License](LICENSE)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📚 References

- [CometBFT Documentation](https://docs.cometbft.com/)
- [Ethereum Engine API](https://github.com/ethereum/execution-apis)
- [ABCI Specification](https://docs.cometbft.com/v0.38/spec/abci/)