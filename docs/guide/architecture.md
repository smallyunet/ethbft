# Architecture

EthBFT acts as the glue between CometBFT and the Ethereum Execution Layer.

## 📁 Project Structure

```text
ethbft/
├── cmd/
│   └── ethbft/             # Main application entry point
├── pkg/
│   ├── bridge/             # Bridge between CometBFT height and Engine API
│   │   ├── bridge.go       # Engine API orchestration & height loop
│   │   ├── server.go       # ABCI server + health HTTP server
│   │   └── types.go        # Aliases of go-ethereum Engine API types
│   ├── config/             # Configuration management
│   ├── consensus/          # CometBFT client integration
│   └── ethereum/           # Ethereum client integration
├── config/                 # Configuration files
├── scripts/                # Utility scripts
├── docker-compose.yml      # Docker orchestration
├── Dockerfile              # Container definition
├── Makefile                # Build and development commands
├── go.mod                  # Go module definition
└── README.md               # Overview
```

## Engine API Orchestration

EthBFT implements the minimal sequence required by the Engine API to produce and advance blocks:

1. **`engine_forkchoiceUpdatedV2`**: Notifies the EL of the latest head and provides payload attributes for building the next block.
2. **`engine_getPayloadV2`**: Retrieves the built execution payload from the EL.
3. **`engine_newPayloadV2`**: Submits the payload back to the EL for validation.
4. **`engine_forkchoiceUpdatedV2`**: Finalizes the block as the new head.

## Height Mapping

EthBFT maintains a mapping of `CometBFT Height -> Ethereum Block Hash`. This ensures that the blockchain continues linearly and that EthBFT knows exactly which parent to use for a given CometBFT height. This state is persisted to `ethbft_state.json`.
