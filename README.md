# EthBFT - Ethereum to CometBFT Bridge

EthBFT is a lightweight bridge layer that connects Ethereum execution clients (like Geth) with CometBFT consensus. This project enables you to run a blockchain system using Ethereum's execution capabilities with CometBFT's fast and secure consensus mechanism.

## Project Structure

```
ethbft/
├── cmd/                    # Application entry points
│   └── ethbft/             # Main EthBFT application
├── config/                 # Configuration files
├── docs/                   # Documentation
├── internal/               # Private application code
├── pkg/                    # Public libraries
│   ├── bridge/             # Bridge between Ethereum and CometBFT
│   ├── config/             # Configuration handling
│   ├── consensus/          # CometBFT client and integration
│   ├── ethereum/           # Ethereum client and integration
│   └── types/              # Shared types and data structures
├── Makefile                # Build and development commands
├── go.mod                  # Go module definition
├── go.sum                  # Go module checksums
└── README.md               # Project documentation
```

## Quick Start

### Prerequisites

- Go 1.20 or later
- Ethereum execution client (e.g., Geth)
- CometBFT

### Building

```bash
# Clone the repository
git clone https://github.com/smallyunet/ethbft.git
cd ethbft

# Install dependencies and set up development environment
make dev-setup

# Build the project
make build
```

### Running

Using Docker:

```bash
# Start the complete stack (Geth + CometBFT + EthBFT)
make docker-up

# Stop all containers
make docker-down

# Rebuild and restart all containers
make docker-rebuild
```

Or run the application directly:

```bash
# Start the bridge
make run

# Or run directly
./ethbft
```

## Configuration

EthBFT can be configured using a JSON configuration file. A sample configuration file is provided in `config/config.json`.

You can also set the configuration file path using the `ETHBFT_CONFIG` environment variable:

```bash
ETHBFT_CONFIG=/path/to/config.json ./ethbft
```

Key configuration options:

- `ethereum.endpoint`: URL of your Ethereum execution client's JSON-RPC API
- `cometbft.endpoint`: URL of your CometBFT node's RPC API
- `bridge.retryInterval`: Seconds between connection retry attempts

## Architecture

EthBFT works as a bridge layer between Ethereum execution clients and CometBFT consensus by:

1. Connecting to an Ethereum execution client to retrieve block data
2. Processing this data into a format compatible with CometBFT
3. Proposing blocks to CometBFT for consensus
4. Relaying finalized blocks back to the Ethereum execution layer

The design focuses on simplicity and reliability, avoiding complex state management whenever possible.

## Development

### Testing

```bash
# Run all tests
make test
```

### Utility Commands

```bash
# Generate JWT Secret for Ethereum Engine API
make generate-jwt

# Create genesis.json file
make create-genesis

# Set up development environment
make dev-setup

# Clean all data (JWT, chain data, etc.)
make clean
```

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.